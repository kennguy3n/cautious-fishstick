package pam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// SessionPolicyAdapter is the bridge that lets the gateway's
// CommandPolicyEvaluator interface — which only carries
// (workspace_id, session_id, input) — call into the rich
// PAMCommandPolicyService API that needs an (asset_id, account_id,
// asset_metadata, account_metadata) context.
//
// The adapter is intended to be wired inside ztna-api: the
// gateway-side HTTP client (APIPolicyEvaluator in
// internal/gateway/api_policy_evaluator.go) calls a thin handler
// (POST /pam/policy/evaluate) which delegates to this adapter.
//
// Concurrency: safe for concurrent use. The per-session context
// cache is guarded by an RWMutex.
type SessionPolicyAdapter struct {
	db       *gorm.DB
	policy   *PAMCommandPolicyService
	now      func() time.Time
	cacheTTL time.Duration

	mu    sync.RWMutex
	cache map[string]sessionContextCacheEntry
}

// sessionContextCacheEntry is one resolved session → context
// mapping. CachedAt drives TTL invalidation: a session's
// asset/account does not change during its lifetime, but cached
// entries are dropped when the cache TTL elapses so a typo on a
// new session_id does not pin a stale context forever.
type sessionContextCacheEntry struct {
	cachedAt time.Time
	ctx      CommandPolicyContext
}

// defaultSessionContextCacheTTL is generous because PAM sessions
// rarely change asset/account once active, and a stale entry only
// matters when the session terminates (in which case the next
// lookup will miss anyway).
const defaultSessionContextCacheTTL = 5 * time.Minute

// NewSessionPolicyAdapter builds an adapter bound to the supplied
// command policy service + DB handle. Either may be nil — a nil
// policy service falls through to allow-everything (caller side
// must check; this matches the listener's "no evaluator
// configured" default).
func NewSessionPolicyAdapter(
	db *gorm.DB,
	policy *PAMCommandPolicyService,
) *SessionPolicyAdapter {
	return &SessionPolicyAdapter{
		db:       db,
		policy:   policy,
		now:      time.Now,
		cacheTTL: defaultSessionContextCacheTTL,
		cache:    make(map[string]sessionContextCacheEntry),
	}
}

// SetNow overrides the time source. Tests pin time so cache TTL
// expiry can be asserted without sleeping.
func (a *SessionPolicyAdapter) SetNow(now func() time.Time) {
	if a == nil || now == nil {
		return
	}
	a.now = now
}

// SetCacheTTL overrides the session-context cache TTL. A
// non-positive value resets to the default.
func (a *SessionPolicyAdapter) SetCacheTTL(ttl time.Duration) {
	if a == nil {
		return
	}
	if ttl <= 0 {
		a.cacheTTL = defaultSessionContextCacheTTL
		return
	}
	a.cacheTTL = ttl
}

// InvalidateSession drops the cached context for sessionID. The
// session-service's terminate / fail paths should call this so a
// session that ended is not held in the cache past its lifetime.
func (a *SessionPolicyAdapter) InvalidateSession(sessionID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.cache, sessionID)
}

// EvaluateCommand satisfies gateway.CommandPolicyEvaluator by
// resolving session_id → (asset_id, account_id, asset_metadata,
// account_metadata) and forwarding to PAMCommandPolicyService.
//
// Returns (action, reason, error). On any DB / lookup error the
// caller (the gateway) logs and continues (fail-open at the
// gateway level), matching the existing listener behaviour.
//
// Returned action values:
//
//   - models.PAMCommandActionAllow   (string "allow")
//   - models.PAMCommandActionDeny    (string "deny")
//   - models.PAMCommandActionStepUp  (string "step_up")
//
// A nil receiver returns ("allow", "", nil) so the SSH listener's
// pre-existing fallback path (no evaluator configured) keeps
// behaving the same way.
func (a *SessionPolicyAdapter) EvaluateCommand(
	ctx context.Context,
	workspaceID, sessionID, input string,
) (string, string, error) {
	if a == nil || a.policy == nil {
		return models.PAMCommandActionAllow, "", nil
	}
	workspaceID = strings.TrimSpace(workspaceID)
	sessionID = strings.TrimSpace(sessionID)
	if workspaceID == "" {
		return "", "", errors.New("pam: session policy: workspace_id is required")
	}
	if sessionID == "" {
		return "", "", errors.New("pam: session policy: session_id is required")
	}

	cmdCtx, err := a.resolveContext(ctx, workspaceID, sessionID)
	if err != nil {
		return "", "", err
	}
	decision, err := a.policy.EvaluateCommand(ctx, workspaceID, cmdCtx, input)
	if err != nil {
		return "", "", err
	}
	return decision.Action, decision.Reason, nil
}

// resolveContext loads the session row + its asset row to build a
// CommandPolicyContext. The result is cached for a.cacheTTL so a
// stream of commands from one session does not hammer the DB.
//
// On cache miss the lookup is two single-row queries: one
// pam_sessions, one pam_assets. We deliberately do not join: gorm
// joins with WHERE on multiple tables tend to drop the index
// hints, and two First() calls is more predictable.
//
// Asset metadata exposed to the policy engine:
//
//	"protocol":    asset.Protocol  // "ssh"|"k8s"|"postgres"|"mysql"
//	"criticality": asset.Criticality  // "low"|"medium"|"high"|"critical"
//	"host":        asset.Host
//	"name":        asset.Name
//
// Account metadata is not loaded (no pam_accounts table read on the
// hot path). The matched selector schema in Phase 1 only filters on
// account ID, so account_id is enough.
func (a *SessionPolicyAdapter) resolveContext(
	ctx context.Context,
	workspaceID, sessionID string,
) (CommandPolicyContext, error) {
	a.mu.RLock()
	if entry, ok := a.cache[sessionID]; ok && a.now().Sub(entry.cachedAt) < a.cacheTTL {
		out := entry.ctx
		a.mu.RUnlock()
		return out, nil
	}
	a.mu.RUnlock()

	var session models.PAMSession
	if err := a.db.WithContext(ctx).
		Where("id = ? AND workspace_id = ?", sessionID, workspaceID).
		First(&session).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return CommandPolicyContext{}, fmt.Errorf("pam: session policy: session %s not found in workspace %s", sessionID, workspaceID)
		}
		return CommandPolicyContext{}, fmt.Errorf("pam: session policy: load session: %w", err)
	}

	cmdCtx := CommandPolicyContext{
		AssetID:   session.AssetID,
		AccountID: session.AccountID,
	}
	if session.AssetID != "" {
		var asset models.PAMAsset
		if err := a.db.WithContext(ctx).
			Where("id = ? AND workspace_id = ?", session.AssetID, workspaceID).
			First(&asset).Error; err == nil {
			cmdCtx.AssetMetadata = map[string]string{
				"protocol":    asset.Protocol,
				"criticality": asset.Criticality,
				"host":        asset.Host,
				"name":        asset.Name,
			}
		}
		// We tolerate a missing pam_assets row — the selector with
		// no metadata still matches "id" selectors and any rule
		// with an empty selector, which is a safer behaviour than
		// failing the whole evaluation when an asset was deleted
		// mid-session.
	}

	a.mu.Lock()
	a.cache[sessionID] = sessionContextCacheEntry{
		cachedAt: a.now(),
		ctx:      cmdCtx,
	}
	a.mu.Unlock()

	return cmdCtx, nil
}
