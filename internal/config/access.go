// Package config holds the authoritative process-level configuration
// for the ShieldNet 360 Access Platform binaries (cmd/ztna-api,
// cmd/access-connector-worker, cmd/access-workflow-engine). Per
// docs/PROPOSAL.md §10.2 the access platform reads its knobs from
// environment variables; this package centralises the reads so a
// future migration to TOML / YAML / Vault is one file change.
package config

import (
	"os"
	"strconv"
	"time"
)

// Default values for the access-platform knobs. Mirrors the table in
// docs/PROPOSAL.md §10.2.
const (
	// DefaultFullResyncInterval is the cadence at which the
	// access-connector-worker runs a full enumeration of identities,
	// even when a delta link is available. Mirrors SN360's
	// INTEGRATION_FULL_RESYNC_INTERVAL.
	DefaultFullResyncInterval = 7 * 24 * time.Hour

	// DefaultReviewFrequency is the cadence at which scheduled access
	// review campaigns kick off when an admin does not override it
	// per resource category.
	DefaultReviewFrequency = 90 * 24 * time.Hour

	// DefaultDraftPolicyStaleAfter is the age at which a draft policy
	// without a fresh Simulate run is flagged as "stale". Promotion is
	// not blocked, but the admin UI surfaces a warning prompting a
	// re-simulate.
	DefaultDraftPolicyStaleAfter = 14 * 24 * time.Hour
)

// Access is the typed snapshot of the access-platform environment
// configuration. Construct via Load() at process start; mutating the
// struct after that is undefined behaviour (no synchronisation).
type Access struct {
	// AIAgentBaseURL is the root URL of the access-ai-agent A2A
	// server. Empty means "AI is intentionally unconfigured" — the
	// service layer's AssessRiskWithFallback recognises this and
	// short-circuits to the medium-risk fallback per
	// docs/PROPOSAL.md §5.3.
	AIAgentBaseURL string

	// AIAgentAPIKey is the shared secret for X-API-Key header per
	// docs/PROPOSAL.md §10.3. Never logged.
	AIAgentAPIKey string

	// WorkflowEngineBaseURL is the root URL of the
	// access-workflow-engine LangGraph orchestrator. Currently
	// unused by the API binary but populated for future Phase 8
	// hand-off work.
	WorkflowEngineBaseURL string

	// FullResyncInterval is the connector full-sync cadence. Defaults
	// to DefaultFullResyncInterval.
	FullResyncInterval time.Duration

	// ReviewDefaultFrequency is the default scheduled-campaign
	// cadence. Defaults to DefaultReviewFrequency.
	ReviewDefaultFrequency time.Duration

	// DraftPolicyStaleAfter is the "this draft hasn't been simulated
	// recently" threshold. Defaults to DefaultDraftPolicyStaleAfter.
	DraftPolicyStaleAfter time.Duration
}

// Load reads the Access* environment variables and returns a
// populated *Access. Missing / malformed durations fall back to the
// matching Default* constant; missing string variables default to
// "".
//
// Load never panics and never returns an error: an entirely empty
// environment yields a struct with zero-value strings and the
// default durations, which is the right behaviour for tests and
// for the dev binary that runs without AI configured.
func Load() *Access {
	return &Access{
		AIAgentBaseURL:         getEnv("ACCESS_AI_AGENT_BASE_URL"),
		AIAgentAPIKey:          getEnv("ACCESS_AI_AGENT_API_KEY"),
		WorkflowEngineBaseURL:  getEnv("ACCESS_WORKFLOW_ENGINE_BASE_URL"),
		FullResyncInterval:     getDurationEnv("ACCESS_FULL_RESYNC_INTERVAL", DefaultFullResyncInterval),
		ReviewDefaultFrequency: getDurationEnv("ACCESS_REVIEW_DEFAULT_FREQUENCY", DefaultReviewFrequency),
		DraftPolicyStaleAfter:  getDurationEnv("ACCESS_DRAFT_POLICY_STALE_AFTER", DefaultDraftPolicyStaleAfter),
	}
}

// AIConfigured reports whether the AI agent is wired up. Convenience
// helper for log lines and admin-UI feature flags so callers don't
// duplicate the empty-string check.
func (a *Access) AIConfigured() bool {
	return a != nil && a.AIAgentBaseURL != ""
}

// getEnv returns the environment variable named key, or "" if unset.
// Centralised so a future move to a config file is one function
// change.
func getEnv(key string) string {
	return os.Getenv(key)
}

// getDurationEnv parses the environment variable named key as a Go
// time.Duration (e.g. "168h", "7d-equivalent"). Falls back to def
// when the variable is unset, empty, or unparseable. A negative
// duration also falls back — periods can't be negative.
//
// Two formats are accepted:
//
//   - Anything time.ParseDuration accepts (e.g. "5s", "2h").
//   - A bare integer interpreted as seconds (e.g. "604800" → 7 days).
//
// The bare-integer format is convenient for shell-based
// configuration where appending a unit suffix is awkward.
func getDurationEnv(key string, def time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	if d, err := time.ParseDuration(raw); err == nil && d > 0 {
		return d
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return def
}
