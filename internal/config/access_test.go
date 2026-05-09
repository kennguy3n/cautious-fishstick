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
