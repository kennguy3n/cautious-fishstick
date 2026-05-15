package config

import (
	"testing"
	"time"
)

func TestLoad_DefaultsWhenUnset(t *testing.T) {
	t.Setenv("ACCESS_AI_AGENT_BASE_URL", "")
	t.Setenv("ACCESS_AI_AGENT_API_KEY", "")
	t.Setenv("ACCESS_WORKFLOW_ENGINE_BASE_URL", "")
	t.Setenv("ACCESS_FULL_RESYNC_INTERVAL", "")
	t.Setenv("ACCESS_REVIEW_DEFAULT_FREQUENCY", "")
	t.Setenv("ACCESS_DRAFT_POLICY_STALE_AFTER", "")
	cfg := Load()
	if cfg.AIAgentBaseURL != "" {
		t.Fatalf("AIAgentBaseURL = %q; want empty", cfg.AIAgentBaseURL)
	}
	if cfg.AIConfigured() {
		t.Fatal("AIConfigured = true; want false")
	}
	if cfg.FullResyncInterval != DefaultFullResyncInterval {
		t.Fatalf("FullResyncInterval = %v; want %v", cfg.FullResyncInterval, DefaultFullResyncInterval)
	}
	if cfg.ReviewDefaultFrequency != DefaultReviewFrequency {
		t.Fatalf("ReviewDefaultFrequency = %v", cfg.ReviewDefaultFrequency)
	}
	if cfg.DraftPolicyStaleAfter != DefaultDraftPolicyStaleAfter {
		t.Fatalf("DraftPolicyStaleAfter = %v", cfg.DraftPolicyStaleAfter)
	}
}

func TestLoad_ReadsValues(t *testing.T) {
	t.Setenv("ACCESS_AI_AGENT_BASE_URL", "https://example.com")
	t.Setenv("ACCESS_AI_AGENT_API_KEY", "secret")
	t.Setenv("ACCESS_FULL_RESYNC_INTERVAL", "1h")
	t.Setenv("ACCESS_REVIEW_DEFAULT_FREQUENCY", "3600")     // bare seconds
	t.Setenv("ACCESS_DRAFT_POLICY_STALE_AFTER", "garbage") // falls back

	cfg := Load()
	if cfg.AIAgentBaseURL != "https://example.com" {
		t.Fatalf("AIAgentBaseURL = %q", cfg.AIAgentBaseURL)
	}
	if cfg.AIAgentAPIKey != "secret" {
		t.Fatalf("AIAgentAPIKey = %q; want secret", cfg.AIAgentAPIKey)
	}
	if !cfg.AIConfigured() {
		t.Fatal("AIConfigured = false; want true")
	}
	if cfg.FullResyncInterval != time.Hour {
		t.Fatalf("FullResyncInterval = %v; want 1h", cfg.FullResyncInterval)
	}
	if cfg.ReviewDefaultFrequency != time.Hour {
		t.Fatalf("ReviewDefaultFrequency = %v; want 1h via bare-seconds 3600", cfg.ReviewDefaultFrequency)
	}
	if cfg.DraftPolicyStaleAfter != DefaultDraftPolicyStaleAfter {
		t.Fatalf("DraftPolicyStaleAfter = %v; want default %v", cfg.DraftPolicyStaleAfter, DefaultDraftPolicyStaleAfter)
	}
}

func TestAIConfigured_NilReceiverReturnsFalse(t *testing.T) {
	var a *Access
	if a.AIConfigured() {
		t.Fatal("nil-receiver AIConfigured returned true")
	}
}

// TestLoad_GrantExpiryCheckIntervalDefault covers the Phase 11
// (docs/overview.md §13) default: when ACCESS_GRANT_EXPIRY_CHECK_INTERVAL
// is unset the loaded config exposes DefaultGrantExpiryCheckInterval
// (1 hour) so the worker schedules grant-expiry sweeps without
// requiring operator action.
func TestLoad_GrantExpiryCheckIntervalDefault(t *testing.T) {
	t.Setenv("ACCESS_GRANT_EXPIRY_CHECK_INTERVAL", "")
	cfg := Load()
	if cfg.GrantExpiryCheckInterval != DefaultGrantExpiryCheckInterval {
		t.Fatalf("GrantExpiryCheckInterval = %v; want %v",
			cfg.GrantExpiryCheckInterval, DefaultGrantExpiryCheckInterval)
	}
	if DefaultGrantExpiryCheckInterval != time.Hour {
		t.Fatalf("DefaultGrantExpiryCheckInterval = %v; want 1h (Phase 11 contract)",
			DefaultGrantExpiryCheckInterval)
	}
}

// TestLoad_GrantExpiryCheckIntervalOverride asserts an operator
// override via env var lands on the loaded config so deployments
// can tune the cadence down (e.g. 5m for JIT-heavy workloads) or
// up (e.g. 6h for batch workloads).
func TestLoad_GrantExpiryCheckIntervalOverride(t *testing.T) {
	t.Setenv("ACCESS_GRANT_EXPIRY_CHECK_INTERVAL", "5m")
	cfg := Load()
	if cfg.GrantExpiryCheckInterval != 5*time.Minute {
		t.Fatalf("GrantExpiryCheckInterval = %v; want 5m", cfg.GrantExpiryCheckInterval)
	}
}

// TestLoad_OrphanReconcileDelayPerConnectorDefault asserts the
// Phase 11 batch 6 default per-connector throttle is wired onto
// the loaded config.
func TestLoad_OrphanReconcileDelayPerConnectorDefault(t *testing.T) {
	t.Setenv("ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR", "")
	cfg := Load()
	if cfg.OrphanReconcileDelayPerConnector != DefaultOrphanReconcileDelayPerConnector {
		t.Fatalf("OrphanReconcileDelayPerConnector = %v; want %v",
			cfg.OrphanReconcileDelayPerConnector, DefaultOrphanReconcileDelayPerConnector)
	}
	if DefaultOrphanReconcileDelayPerConnector != time.Second {
		t.Fatalf("DefaultOrphanReconcileDelayPerConnector = %v; want 1s", DefaultOrphanReconcileDelayPerConnector)
	}
}

// TestLoad_OrphanReconcileDelayPerConnectorOverride asserts the
// env-driven override lands on the loaded config.
func TestLoad_OrphanReconcileDelayPerConnectorOverride(t *testing.T) {
	t.Setenv("ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR", "250ms")
	cfg := Load()
	if cfg.OrphanReconcileDelayPerConnector != 250*time.Millisecond {
		t.Fatalf("OrphanReconcileDelayPerConnector = %v; want 250ms",
			cfg.OrphanReconcileDelayPerConnector)
	}
}

// TestLoad_GrantExpiryWarningHoursDefault asserts the Phase 11
// batch 6 default look-ahead window is wired onto the loaded
// config.
func TestLoad_GrantExpiryWarningHoursDefault(t *testing.T) {
	t.Setenv("ACCESS_GRANT_EXPIRY_WARNING_HOURS", "")
	cfg := Load()
	if cfg.GrantExpiryWarningHours != DefaultGrantExpiryWarningHours {
		t.Fatalf("GrantExpiryWarningHours = %d; want %d",
			cfg.GrantExpiryWarningHours, DefaultGrantExpiryWarningHours)
	}
	if DefaultGrantExpiryWarningHours != 24 {
		t.Fatalf("DefaultGrantExpiryWarningHours = %d; want 24",
			DefaultGrantExpiryWarningHours)
	}
}

// TestLoad_GrantExpiryWarningHoursOverride asserts the env-driven
// override lands on the loaded config.
func TestLoad_GrantExpiryWarningHoursOverride(t *testing.T) {
	t.Setenv("ACCESS_GRANT_EXPIRY_WARNING_HOURS", "12")
	cfg := Load()
	if cfg.GrantExpiryWarningHours != 12 {
		t.Fatalf("GrantExpiryWarningHours = %d; want 12",
			cfg.GrantExpiryWarningHours)
	}
}
