// Package pam — command policy evaluation (Milestone 9 Task 24).
//
// PAMCommandPolicyService evaluates an operator-typed command against
// the workspace's pam_command_policies rows and returns the first
// matching action (allow / deny / step_up) per docs/pam/architecture.md
// §6 and §10.4. Patterns are compiled once and cached per workspace
// with TTL invalidation so the gateway's hot path stays in-process.
//
// Default behaviour: when no rule matches, the command is allowed.
// A workspace with zero policies (or a workspace where every policy
// targets a different (asset, account) tuple) defaults to allow.
package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ErrPAMCommandPolicyMissingDB is returned by the constructor when
// the caller passes nil for the gorm.DB handle. The service cannot
// load policies without it — every fallback path would silently
// allow every command, which is not a safe default for a service
// whose purpose is to block dangerous commands.
var ErrPAMCommandPolicyMissingDB = errors.New("pam: command policy service requires a non-nil *gorm.DB")

// defaultPolicyCacheTTL is how long a workspace's compiled rule set
// stays cached before EvaluateCommand re-fetches from the DB. Short
// enough that a policy edit lands within the gateway in under a
// minute, long enough that a busy session does not re-query for
// every line the operator types.
const defaultPolicyCacheTTL = 30 * time.Second

// CommandPolicyContext is the per-evaluation tuple the gateway hands
// to EvaluateCommand. It carries the asset + account identifiers and
// any tags / criticality the selectors might filter on.
//
// AssetMetadata / AccountMetadata are intentionally flat
// map[string]string so the JSONB selectors in pam_command_policies
// can be evaluated with a simple equality check per key. Anything
// fancier (numeric ranges, regex selectors) is out of scope for
// Phase 1 — the proposal calls only for "match all critical assets"
// and "match this specific account".
type CommandPolicyContext struct {
	AssetID         string
	AccountID       string
	AssetMetadata   map[string]string
	AccountMetadata map[string]string
}

// CommandDecision is the result of EvaluateCommand.
//
// MatchedPolicy is nil when no rule matched — the gateway should
// treat that as "allow with no audit annotation". When a rule
// matches, Action is one of models.PAMCommandActionAllow /
// PAMCommandActionDeny / PAMCommandActionStepUp, Reason is the
// human-readable rationale the gateway surfaces to the operator
// (and stamps into pam_session_commands.risk_flag annotations), and
// MatchedPolicy carries the rule for downstream audit emission.
type CommandDecision struct {
	Action        string
	Reason        string
	MatchedPolicy *models.PAMCommandPolicy
}

// compiledPolicy is the in-memory representation of a
// pam_command_policies row after regex compilation + selector
// parsing. Stored in the per-workspace policyCacheEntry so
// EvaluateCommand stays allocation-free in the hot loop.
type compiledPolicy struct {
	row             models.PAMCommandPolicy
	pattern         *regexp.Regexp
	assetSelector   map[string]string
	accountSelector map[string]string
}

// policyCacheEntry is one workspace's compiled rule set + its load
// time. EvaluateCommand re-loads when time.Since(loadedAt) >= TTL.
type policyCacheEntry struct {
	loadedAt time.Time
	rules    []compiledPolicy
}

// PAMCommandPolicyService loads, compiles, caches, and evaluates
// PAM command policies for the gateway.
//
// Concurrency: safe for concurrent use. The cache is guarded by a
// RWMutex; the hot path takes only a read lock when the cache is
// fresh, so multiple gateway sessions can evaluate commands
// in parallel without contention.
type PAMCommandPolicyService struct {
	db       *gorm.DB
	now      func() time.Time
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]*policyCacheEntry
}

// NewPAMCommandPolicyService constructs a PAMCommandPolicyService
// bound to db. now defaults to time.Now; cacheTTL defaults to
// defaultPolicyCacheTTL when zero.
func NewPAMCommandPolicyService(db *gorm.DB) (*PAMCommandPolicyService, error) {
	if db == nil {
		return nil, ErrPAMCommandPolicyMissingDB
	}
	return &PAMCommandPolicyService{
		db:       db,
		now:      time.Now,
		cacheTTL: defaultPolicyCacheTTL,
		cache:    make(map[string]*policyCacheEntry),
	}, nil
}

// SetNow overrides the time source. Tests pin time so cache TTL
// expiry can be asserted without sleeping.
func (s *PAMCommandPolicyService) SetNow(now func() time.Time) {
	if s == nil || now == nil {
		return
	}
	s.now = now
}

// SetCacheTTL overrides the cache TTL. A non-positive value resets
// to the default. Tests pass a small value to verify cache reload.
func (s *PAMCommandPolicyService) SetCacheTTL(ttl time.Duration) {
	if s == nil {
		return
	}
	if ttl <= 0 {
		s.cacheTTL = defaultPolicyCacheTTL
		return
	}
	s.cacheTTL = ttl
}

// Invalidate drops the cached compiled rule set for workspaceID, so
// the next EvaluateCommand call re-fetches from the database.
// Callers that mutate a workspace's policies via an admin API
// should call this to make the change visible to in-flight
// sessions immediately rather than waiting up to cacheTTL.
//
// Passing an empty workspaceID drops every cached workspace.
func (s *PAMCommandPolicyService) Invalidate(workspaceID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if workspaceID == "" {
		s.cache = make(map[string]*policyCacheEntry)
		return
	}
	delete(s.cache, workspaceID)
}

// EvaluateCommand returns the first matching command policy
// decision for input under workspaceID + cmdCtx.
//
// Evaluation order (per docs/pam/architecture.md §10.4):
//
//  1. Filter to rules whose AssetSelector matches cmdCtx.AssetID +
//     cmdCtx.AssetMetadata and whose AccountSelector matches
//     cmdCtx.AccountID + cmdCtx.AccountMetadata. An empty selector
//     matches everything.
//  2. Sort by Priority ascending (lower wins) with CreatedAt
//     ascending as the tiebreaker, matching the model doc.
//  3. Return the first rule whose Pattern regex matches input.
//
// If no rule matches the command is allowed with an empty Reason
// and a nil MatchedPolicy. Returning a decision is best-effort: a
// transient DB error during cache reload surfaces as an error so
// the caller can fail-closed (deny the command) per the §6 fail-
// safe default for the policy engine itself.
func (s *PAMCommandPolicyService) EvaluateCommand(
	ctx context.Context,
	workspaceID string,
	cmdCtx CommandPolicyContext,
	input string,
) (CommandDecision, error) {
	if s == nil {
		return CommandDecision{Action: models.PAMCommandActionAllow}, nil
	}
	workspaceID = strings.TrimSpace(workspaceID)
	if workspaceID == "" {
		return CommandDecision{}, errors.New("pam: command policy: workspace_id is required")
	}
	// We allow empty commands through unconditionally — the gateway
	// already discards empty lines before audit, but a defensive
	// short-circuit here keeps the cache miss path off the critical
	// path for prompt redraws.
	if strings.TrimSpace(input) == "" {
		return CommandDecision{Action: models.PAMCommandActionAllow}, nil
	}

	rules, err := s.getOrLoad(ctx, workspaceID)
	if err != nil {
		return CommandDecision{}, fmt.Errorf("pam: command policy: load rules: %w", err)
	}
	if len(rules) == 0 {
		return CommandDecision{Action: models.PAMCommandActionAllow}, nil
	}

	for i := range rules {
		rule := &rules[i]
		if !selectorMatches(rule.assetSelector, cmdCtx.AssetID, cmdCtx.AssetMetadata) {
			continue
		}
		if !selectorMatches(rule.accountSelector, cmdCtx.AccountID, cmdCtx.AccountMetadata) {
			continue
		}
		if rule.pattern == nil {
			continue
		}
		if !rule.pattern.MatchString(input) {
			continue
		}
		decisionRow := rule.row
		return CommandDecision{
			Action:        rule.row.Action,
			Reason:        decisionReasonFor(&rule.row, input),
			MatchedPolicy: &decisionRow,
		}, nil
	}

	return CommandDecision{Action: models.PAMCommandActionAllow}, nil
}

// getOrLoad returns the compiled rule set for workspaceID, loading
// from the DB if the cache entry is missing or stale.
//
// Cache freshness is checked under a read lock; the load + replace
// path takes the write lock so a thundering herd reduces to a
// single DB round trip per workspace per TTL window.
func (s *PAMCommandPolicyService) getOrLoad(ctx context.Context, workspaceID string) ([]compiledPolicy, error) {
	s.mu.RLock()
	if entry, ok := s.cache[workspaceID]; ok && s.now().Sub(entry.loadedAt) < s.cacheTTL {
		out := entry.rules
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock; another goroutine may have
	// just refreshed the cache.
	if entry, ok := s.cache[workspaceID]; ok && s.now().Sub(entry.loadedAt) < s.cacheTTL {
		return entry.rules, nil
	}

	rules, err := s.loadCompiled(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	s.cache[workspaceID] = &policyCacheEntry{
		loadedAt: s.now(),
		rules:    rules,
	}
	return rules, nil
}

// loadCompiled fetches non-deleted policies for workspaceID, sorts
// them by (priority asc, created_at asc), compiles regexes, and
// decodes asset / account selectors. Rules whose Pattern fails to
// compile are dropped with a warning log line — a broken regex on
// one rule should not blast every other rule for the workspace.
func (s *PAMCommandPolicyService) loadCompiled(ctx context.Context, workspaceID string) ([]compiledPolicy, error) {
	var rows []models.PAMCommandPolicy
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ?", workspaceID).
		Order("priority ASC, created_at ASC").
		Find(&rows).Error; err != nil {
		return nil, err
	}

	// gorm's ORDER BY honours NULL-last semantics differently across
	// dialects; sort in-process as a defensive tiebreaker so tests
	// pin order regardless of backend.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Priority != rows[j].Priority {
			return rows[i].Priority < rows[j].Priority
		}
		return rows[i].CreatedAt.Before(rows[j].CreatedAt)
	})

	compiled := make([]compiledPolicy, 0, len(rows))
	for _, row := range rows {
		if !models.IsValidPAMCommandAction(row.Action) {
			log.Printf("pam: command policy: skipping rule %s with invalid action %q", row.ID, row.Action)
			continue
		}
		re, err := regexp.Compile(row.Pattern)
		if err != nil {
			log.Printf("pam: command policy: skipping rule %s with invalid pattern %q: %v", row.ID, row.Pattern, err)
			continue
		}
		assetSel, err := decodeSelector(row.AssetSelector)
		if err != nil {
			log.Printf("pam: command policy: skipping rule %s with invalid asset_selector: %v", row.ID, err)
			continue
		}
		accountSel, err := decodeSelector(row.AccountSelector)
		if err != nil {
			log.Printf("pam: command policy: skipping rule %s with invalid account_selector: %v", row.ID, err)
			continue
		}
		compiled = append(compiled, compiledPolicy{
			row:             row,
			pattern:         re,
			assetSelector:   assetSel,
			accountSelector: accountSel,
		})
	}
	return compiled, nil
}

// decodeSelector unmarshals a JSONB selector blob into a
// map[string]string. An empty / nil blob decodes to a nil map
// which selectorMatches treats as "match everything".
//
// The selector schema is intentionally narrow:
//
//	{ "id": "asset-abc"            }   → match exact ID
//	{ "criticality": "critical"    }   → match metadata key
//	{ "tag": "prod", "env": "us" }     → match every key (AND)
//
// Non-string values are coerced to strings via fmt.Sprintf to
// stay forgiving of operator-typed JSON; an empty object returns
// a nil map.
func decodeSelector(raw []byte) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return nil, nil
	}
	var generic map[string]interface{}
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	if len(generic) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(generic))
	for k, v := range generic {
		if v == nil {
			continue
		}
		switch t := v.(type) {
		case string:
			out[k] = t
		case bool:
			if t {
				out[k] = "true"
			} else {
				out[k] = "false"
			}
		case float64:
			// JSON numbers come back as float64; preserve integer
			// rendering so {"priority": 100} matches "100".
			if t == float64(int64(t)) {
				out[k] = fmt.Sprintf("%d", int64(t))
			} else {
				out[k] = fmt.Sprintf("%g", t)
			}
		default:
			out[k] = fmt.Sprintf("%v", t)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// selectorMatches reports whether (id, metadata) satisfies sel.
//
//   - A nil / empty selector matches everything.
//   - The special key "id" matches when sel["id"] == id.
//   - Every other key matches when metadata[key] == sel[key].
//
// All keys must match (AND semantics). Phase 1 keeps the operator
// model simple: a deny rule for /critical postgres/ is a single
// AND-selector on {kind:"db", criticality:"critical"}.
func selectorMatches(sel map[string]string, id string, metadata map[string]string) bool {
	if len(sel) == 0 {
		return true
	}
	for k, want := range sel {
		if k == "id" {
			if id != want {
				return false
			}
			continue
		}
		got, ok := metadata[k]
		if !ok || got != want {
			return false
		}
	}
	return true
}

// decisionReasonFor renders the operator-visible rationale for a
// matched policy. We keep this terse — the operator sees it inline
// at the gateway terminal — and stamp the policy ID so the audit
// stream can correlate back to the rule.
//
// Reasons are stable strings the gateway can match in tests; the
// gateway adds wire-protocol-specific framing (e.g. an SSH banner
// vs a PG error response) on top.
func decisionReasonFor(row *models.PAMCommandPolicy, input string) string {
	if row == nil {
		return ""
	}
	// We deliberately echo a truncated form of the command back so
	// the operator can tell which line the gateway intercepted —
	// useful when a paste batch contains several denied lines.
	excerpt := strings.TrimSpace(input)
	const maxExcerpt = 80
	if len(excerpt) > maxExcerpt {
		excerpt = excerpt[:maxExcerpt] + "..."
	}
	switch row.Action {
	case models.PAMCommandActionDeny:
		return fmt.Sprintf("pam: command denied by policy %s: %s", row.ID, excerpt)
	case models.PAMCommandActionStepUp:
		return fmt.Sprintf("pam: command requires step-up MFA per policy %s: %s", row.ID, excerpt)
	default:
		return fmt.Sprintf("pam: command allowed by policy %s", row.ID)
	}
}
