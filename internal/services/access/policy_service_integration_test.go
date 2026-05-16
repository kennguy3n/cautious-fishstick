package access

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubOpenZitiPolicyWriter is the test double the Phase 3
// integration test wires onto PolicyService to assert "drafts never
// create OpenZiti ServicePolicy until promotion". Each
// WriteServicePolicy call increments Calls and appends the policy
// pointer; setting Err drives the failure-path branch.
//
// The stub is intentionally tiny — a real OpenZiti client lives in
// the ZTNA business layer. This stub exercises the access platform's
// side of the contract: the call site (Promote, after commit) and
// the negative space (CreateDraft / Simulate must NOT call it).
type stubOpenZitiPolicyWriter struct {
	Calls    atomic.Int64
	Policies []*models.Policy
	Err      error
}

func (s *stubOpenZitiPolicyWriter) WriteServicePolicy(_ context.Context, policy *models.Policy) error {
	s.Calls.Add(1)
	s.Policies = append(s.Policies, policy)
	return s.Err
}

// TestPolicyService_DraftNeverCreatesOpenZitiServicePolicy is the
// Phase 3 exit-criterion integration test: drafts do not create
// OpenZiti ServicePolicy until promotion — verified by round-tripping
// a draft → simulate → impact and asserting no Ziti write.
//
// The flow:
//
//  1. CreateDraft persists IsDraft=true. Asserts: 0 Ziti calls.
//  2. Simulate computes ImpactReport and persists draft_impact.
//     Asserts: ImpactReport returned with at least one affected
//     member or resource, 0 Ziti calls (the negative space).
//  3. (Promote is exercised by the sibling positive test.)
//
// The integration test wires a stub OpenZiti writer onto the service
// so the assertion is against the writer's call counter directly,
// not the process-global openZitiCallCount() counter (which other
// tests share).
func TestPolicyService_DraftNeverCreatesOpenZitiServicePolicy(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	writer := &stubOpenZitiPolicyWriter{}
	svc.SetOpenZitiPolicyWriter(writer)

	// Step 1: CreateDraft.
	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if !draft.IsDraft {
		t.Errorf("draft.IsDraft = false; want true")
	}
	if got := writer.Calls.Load(); got != 0 {
		t.Errorf("after CreateDraft: writer.Calls = %d; want 0 (drafts must not write Ziti)", got)
	}

	// Step 2: Simulate. ImpactReport must be returned and persisted.
	report, err := svc.Simulate(context.Background(), ws, draft.ID)
	if err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if report == nil {
		t.Fatal("Simulate returned nil ImpactReport; want populated report")
	}
	if len(report.AffectedMembers) == 0 && len(report.AffectedResources) == 0 {
		t.Errorf("ImpactReport is empty; want at least one affected member or resource (impact resolver must populate even an unscoped match)")
	}
	if got := writer.Calls.Load(); got != 0 {
		t.Errorf("after Simulate: writer.Calls = %d; want 0 (simulate must not write Ziti)", got)
	}

	// Step 3: re-load the draft and assert IsDraft is still true and
	// draft_impact is populated.
	var reloaded models.Policy
	if err := db.Where("id = ?", draft.ID).First(&reloaded).Error; err != nil {
		t.Fatalf("reload draft: %v", err)
	}
	if !reloaded.IsDraft {
		t.Errorf("after Simulate: reloaded.IsDraft = false; want true (Simulate must not flip is_draft)")
	}
	if len(reloaded.DraftImpact) == 0 {
		t.Errorf("after Simulate: reloaded.DraftImpact is empty; want populated")
	}
	if got := writer.Calls.Load(); got != 0 {
		t.Errorf("at end of draft+simulate: writer.Calls = %d; want 0", got)
	}
}

// TestPolicyService_PromoteCallsOpenZitiWriterOnce is the positive
// counterpart to the draft test above. When an OpenZiti writer is
// wired onto the service, Promote calls WriteServicePolicy exactly
// once — and the call lands AFTER the DB transaction has committed,
// so the policy passed to the writer has IsDraft=false.
func TestPolicyService_PromoteCallsOpenZitiWriterOnce(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	writer := &stubOpenZitiPolicyWriter{}
	svc.SetOpenZitiPolicyWriter(writer)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	promoted, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	if got := writer.Calls.Load(); got != 1 {
		t.Fatalf("writer.Calls = %d; want exactly 1", got)
	}
	if len(writer.Policies) != 1 {
		t.Fatalf("writer.Policies len = %d; want 1", len(writer.Policies))
	}
	got := writer.Policies[0]
	if got.IsDraft {
		t.Errorf("writer received policy with IsDraft=true; want false (writer must run AFTER commit)")
	}
	if got.PromotedAt == nil {
		t.Errorf("writer received policy with PromotedAt=nil; want set")
	}
	if got.ID != promoted.ID {
		t.Errorf("writer received policy id %q; want %q", got.ID, promoted.ID)
	}
}

// TestPolicyService_PromoteWriterFailureDoesNotRollback asserts the
// best-effort semantics documented on OpenZitiPolicyWriter: a Ziti
// failure logs a warning but does NOT roll back the DB promotion.
// The DB is the source of truth; the ZTNA business layer reconciles
// the Ziti state eventually.
func TestPolicyService_PromoteWriterFailureDoesNotRollback(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	writer := &stubOpenZitiPolicyWriter{Err: errors.New("ziti controller unreachable")}
	svc.SetOpenZitiPolicyWriter(writer)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	promoted, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if err != nil {
		t.Fatalf("Promote: %v (writer failure must not surface as Promote error)", err)
	}
	if promoted.IsDraft {
		t.Errorf("promoted.IsDraft = true; want false (writer failure must not roll back DB)")
	}

	// Re-load: DB row must be promoted even though writer failed.
	var reloaded models.Policy
	if err := db.Where("id = ?", draft.ID).First(&reloaded).Error; err != nil {
		t.Fatalf("reload promoted: %v", err)
	}
	if reloaded.IsDraft {
		t.Errorf("after Promote with writer failure: reloaded.IsDraft = true; want false (DB is source of truth)")
	}
	if got := writer.Calls.Load(); got != 1 {
		t.Errorf("writer.Calls = %d; want 1 (writer must be invoked exactly once even on failure)", got)
	}
}

// TestPolicyService_PromoteWithoutWriterDoesNotPanic asserts the
// default "no Ziti writer wired" behaviour is preserved: Promote
// flips the DB state and returns the promoted row without any Ziti
// integration in this repo. This is the path cmd/ztna-api takes by
// default; the ZTNA business layer is responsible for the Ziti
// write.
func TestPolicyService_PromoteWithoutWriterDoesNotPanic(t *testing.T) {
	db := newPhase3DB(t)
	const ws = "01H000000000000000WORKSPACE"
	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	// Intentionally do NOT call SetOpenZitiPolicyWriter.

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	promoted, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if promoted.IsDraft {
		t.Errorf("promoted.IsDraft = true; want false")
	}
}
