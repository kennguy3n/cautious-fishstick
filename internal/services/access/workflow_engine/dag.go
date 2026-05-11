package workflow_engine

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// hasDAG returns true when at least one step declares `next` or `join`.
// The linear executor (Execute) handles the false case; the DAG executor
// (ExecuteDAG) handles the true case.
func hasDAG(steps []models.WorkflowStepDefinition) bool {
	for _, s := range steps {
		if len(s.Next) > 0 || len(s.Join) > 0 {
			return true
		}
	}
	return false
}

// dagBuild parses a WorkflowStepDefinition slice into the adjacency
// representation the DAG runtime needs. It also validates that every
// referenced index is in range, that there are no self-loops, and that
// the graph is acyclic (Kahn's algorithm).
//
// The returned `successors` slice is N entries long; entry i is the
// list of step indices that should run after step i. The returned
// `predecessors` slice mirrors successors with edges reversed —
// the executor reads it to know how many incoming edges a step has
// (and therefore how many predecessor completions it must wait for).
//
// `roots` is the set of step indices with no incoming edges; the
// executor launches these first.
func dagBuild(steps []models.WorkflowStepDefinition) (successors, predecessors [][]int, roots []int, err error) {
	n := len(steps)
	if n == 0 {
		return nil, nil, nil, fmt.Errorf("dag: empty steps")
	}

	successors = make([][]int, n)
	predecessors = make([][]int, n)

	// First pass: copy explicit `Next` / `Join`. We treat absence
	// of `Next` on step i as "implicit successor is i+1" only when
	// no step in the workflow declares any DAG metadata. Once any
	// step opts in, every other step is treated as explicit-only;
	// otherwise we'd silently fan out into orphan branches.
	for i, s := range steps {
		for _, j := range s.Next {
			if j == i {
				return nil, nil, nil, fmt.Errorf("dag: step %d has self-loop in next", i)
			}
			if j < 0 || j >= n {
				return nil, nil, nil, fmt.Errorf("dag: step %d next references out-of-range index %d", i, j)
			}
			successors[i] = append(successors[i], j)
			predecessors[j] = append(predecessors[j], i)
		}
		for _, j := range s.Join {
			if j == i {
				return nil, nil, nil, fmt.Errorf("dag: step %d has self-loop in join", i)
			}
			if j < 0 || j >= n {
				return nil, nil, nil, fmt.Errorf("dag: step %d join references out-of-range index %d", i, j)
			}
			// `Join` is the inverse view: step i has predecessor j.
			// We add the edge j → i if it isn't already there.
			if !containsInt(successors[j], i) {
				successors[j] = append(successors[j], i)
				predecessors[i] = append(predecessors[i], j)
			}
		}
	}

	// Sort + dedupe each adjacency list so the executor walks
	// branches in a deterministic order regardless of how the
	// step JSON was serialised.
	for i := range successors {
		successors[i] = uniqueIntSlice(successors[i])
	}
	for i := range predecessors {
		predecessors[i] = uniqueIntSlice(predecessors[i])
	}

	// Roots: any step with zero incoming edges.
	for i := range steps {
		if len(predecessors[i]) == 0 {
			roots = append(roots, i)
		}
	}

	// Cycle detection (Kahn's algorithm). We don't use the
	// resulting topological order directly — the executor uses
	// the in-degree counter at runtime — but we run the full pass
	// to fail loudly on bad workflows.
	indeg := make([]int, n)
	for i := range predecessors {
		indeg[i] = len(predecessors[i])
	}
	queue := append([]int{}, roots...)
	visited := 0
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		visited++
		for _, j := range successors[i] {
			indeg[j]--
			if indeg[j] == 0 {
				queue = append(queue, j)
			}
		}
	}
	if visited != n {
		return nil, nil, nil, fmt.Errorf("dag: workflow contains a cycle (visited %d of %d steps)", visited, n)
	}

	return successors, predecessors, roots, nil
}

// dagBranchOutcome captures the per-step outcome the executor records
// while traversing the DAG. The DAG executor returns the worst
// outcome (deny / pending / escalate) it observed; if all branches
// completed with `approve`, the result is `approve`.
type dagBranchOutcome struct {
	stepIndex int
	stepType  string
	decision  StepDecision
	reason    string
	err       error
}

// executeDAG walks the DAG of `steps` starting from the configured
// roots. Steps that fan out (multiple successors) launch parallel
// goroutines; steps that fan in (multiple predecessors) wait until
// all predecessors complete before running.
//
// Branch failure semantics:
//   - approve → schedule successors, branch keeps walking.
//   - deny / escalate / pending → branch halts, executor records the
//     outcome and returns it as the overall result. Other branches
//     keep running because Phase 8 promises that "failure in one
//     branch does not block the other".
//   - error from runStepWithRetry → branch halts, the error is
//     recorded in step-history (status=failed) so ListFailedSteps
//     surfaces it.
//
// The first non-approve outcome wins for the overall ExecutionResult.
// Ties are broken by step index (lower wins) so the result is
// deterministic.
func (e *WorkflowExecutor) executeDAG(
	ctx context.Context,
	areq *models.AccessRequest,
	wfID, requestID string,
	steps []models.WorkflowStepDefinition,
	successors, predecessors [][]int,
	roots []int,
) (*ExecutionResult, error) {
	n := len(steps)
	// pendingPreds tracks the number of predecessor completions a
	// step still needs before it can run. We decrement it under
	// `mu` when a predecessor finishes successfully.
	pendingPreds := make([]int, n)
	for i := range predecessors {
		pendingPreds[i] = len(predecessors[i])
	}

	// branchIndex[i] is the index of the root from which step i
	// descends. Root r gets branch index `sort.SearchInts(roots, r)`;
	// non-root step i inherits the lowest branch index among its
	// predecessors so fan-in (join) steps land in the leftmost
	// branch. Linear (single-root) workflows produce branchIndex[i] =
	// 0 for every step, which is recorded as 0 to make the DLQ view
	// easy to filter on.
	branchIndex := computeBranchIndex(n, predecessors, roots)

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		outcomes []dagBranchOutcome
	)

	// runOne walks a single step and, on success, schedules its
	// successors. It is goroutine-safe; multiple branches may
	// invoke runOne concurrently.
	var runOne func(i int)
	runOne = func(i int) {
		defer wg.Done()

		historyAvailable := e.stepHistoryAvailable()
		var historyID string
		if historyAvailable {
			var herr error
			bi := branchIndex[i]
			historyID, herr = e.startStepHistoryAt(ctx, requestID, wfID, i, steps[i].Type, &bi)
			if herr != nil {
				mu.Lock()
				outcomes = append(outcomes, dagBranchOutcome{
					stepIndex: i, stepType: steps[i].Type, err: herr,
				})
				mu.Unlock()
				return
			}
		}
		decision, reason, attempts, err := e.runStepWithRetry(ctx, areq, steps[i])
		if err != nil {
			if historyID != "" {
				_ = e.finishStepHistory(ctx, historyID, models.WorkflowStepStatusFailed, err.Error(), attempts)
			}
			mu.Lock()
			outcomes = append(outcomes, dagBranchOutcome{
				stepIndex: i, stepType: steps[i].Type, err: err,
			})
			mu.Unlock()
			return
		}

		// Record the per-step outcome.
		var status string
		switch decision {
		case StepApprove:
			status = models.WorkflowStepStatusCompleted
		case StepDeny:
			status = models.WorkflowStepStatusDenied
		case StepEscalate:
			status = models.WorkflowStepStatusEscalated
		default:
			status = models.WorkflowStepStatusPending
		}
		if historyID != "" {
			_ = e.finishStepHistory(ctx, historyID, status, reason, attempts)
		}

		mu.Lock()
		outcomes = append(outcomes, dagBranchOutcome{
			stepIndex: i, stepType: steps[i].Type, decision: decision, reason: reason,
		})
		mu.Unlock()

		if decision != StepApprove {
			// Branch halted. Do NOT schedule successors.
			return
		}

		// Successors: decrement pendingPreds; schedule any that hit zero.
		mu.Lock()
		ready := []int{}
		for _, j := range successors[i] {
			pendingPreds[j]--
			if pendingPreds[j] == 0 {
				ready = append(ready, j)
			}
		}
		mu.Unlock()

		for _, j := range ready {
			wg.Add(1)
			go runOne(j)
		}
	}

	// Launch the roots.
	for _, r := range roots {
		wg.Add(1)
		go runOne(r)
	}
	wg.Wait()

	// Pick the result. Approve unless any branch produced a
	// non-approve decision OR an error. Errors win over other
	// non-approve outcomes; among non-approve decisions, deny
	// wins, then escalate, then pending. Ties broken by step
	// index ascending.
	var first *dagBranchOutcome
	priority := func(o dagBranchOutcome) int {
		switch {
		case o.err != nil:
			return 0
		case o.decision == StepDeny:
			return 1
		case o.decision == StepEscalate:
			return 2
		case o.decision == StepPending:
			return 3
		default:
			return 99
		}
	}
	sort.SliceStable(outcomes, func(a, b int) bool {
		if priority(outcomes[a]) != priority(outcomes[b]) {
			return priority(outcomes[a]) < priority(outcomes[b])
		}
		return outcomes[a].stepIndex < outcomes[b].stepIndex
	})
	for i := range outcomes {
		o := outcomes[i]
		if o.err != nil {
			return nil, fmt.Errorf("workflow_engine: dag step %d (%s): %w", o.stepIndex, o.stepType, o.err)
		}
		if o.decision != StepApprove {
			first = &o
			break
		}
	}
	if first != nil {
		return &ExecutionResult{
			Decision:  first.decision,
			StepIndex: first.stepIndex,
			StepType:  first.stepType,
			Reason:    first.reason,
		}, nil
	}

	// All branches approved. Use the highest-index step as the
	// terminal one (consistent with the linear executor).
	last := 0
	for i := range steps {
		if i > last {
			last = i
		}
	}
	return &ExecutionResult{
		Decision:  StepApprove,
		StepIndex: last,
		StepType:  steps[last].Type,
	}, nil
}

// computeBranchIndex returns a slice mapping every step index to the
// (0-based) index of the root branch it descends from. Roots receive
// their own position in the `roots` slice; non-root steps inherit the
// minimum branch index across their predecessors. This guarantees:
//
//   - A linear workflow (single root) records branch 0 for every step.
//   - In a fan-out, each branch's body keeps the branch number of its
//     root.
//   - In a fan-in (join), the join step lands in the leftmost branch
//     so operators looking at "branch 0" see the join — matching the
//     visual order users expect in the DAG-builder UI.
//
// The algorithm processes steps in DAG order (topological) via Kahn's
// algorithm so every step's predecessors are resolved before it.
func computeBranchIndex(n int, predecessors [][]int, roots []int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = -1
	}
	for idx, r := range roots {
		out[r] = idx
	}

	// Topological sort to resolve predecessor labels first.
	indeg := make([]int, n)
	successors := make([][]int, n)
	for i, preds := range predecessors {
		indeg[i] = len(preds)
		for _, p := range preds {
			successors[p] = append(successors[p], i)
		}
	}
	queue := make([]int, 0, n)
	for i := 0; i < n; i++ {
		if indeg[i] == 0 {
			queue = append(queue, i)
		}
	}
	for len(queue) > 0 {
		i := queue[0]
		queue = queue[1:]
		if out[i] < 0 {
			// Non-root: inherit min branch index from predecessors.
			min := -1
			for _, p := range predecessors[i] {
				if out[p] < 0 {
					continue
				}
				if min < 0 || out[p] < min {
					min = out[p]
				}
			}
			if min < 0 {
				min = 0
			}
			out[i] = min
		}
		for _, j := range successors[i] {
			indeg[j]--
			if indeg[j] == 0 {
				queue = append(queue, j)
			}
		}
	}
	// Safety: any step still unlabeled (cycle case — dagBuild
	// would have already errored out) defaults to branch 0.
	for i := range out {
		if out[i] < 0 {
			out[i] = 0
		}
	}
	return out
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func uniqueIntSlice(xs []int) []int {
	if len(xs) <= 1 {
		return xs
	}
	seen := make(map[int]struct{}, len(xs))
	out := make([]int, 0, len(xs))
	for _, x := range xs {
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	sort.Ints(out)
	return out
}
