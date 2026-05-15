package config

import (
	"testing"
	"time"
)

// TestLoad_MalformedDurationFallsBackToDefault asserts the
// documented contract for getDurationEnv: an unparseable value
// quietly falls back to the supplied default. Callers (cron loops,
// scheduler tickers) rely on this so a typo in a Helm values file
// can't accidentally set "0s" or "" and break startup.
func TestLoad_MalformedDurationFallsBackToDefault(t *testing.T) {
	cases := []struct {
		envKey   string
		envValue string
		field    func(a *Access) time.Duration
		want     time.Duration
		name     string
	}{
		{"ACCESS_FULL_RESYNC_INTERVAL", "not-a-duration", func(a *Access) time.Duration { return a.FullResyncInterval }, DefaultFullResyncInterval, "FullResyncInterval"},
		{"ACCESS_FULL_RESYNC_INTERVAL", "-5h", func(a *Access) time.Duration { return a.FullResyncInterval }, DefaultFullResyncInterval, "FullResyncInterval/negative"},
		{"ACCESS_REVIEW_DEFAULT_FREQUENCY", "1d", func(a *Access) time.Duration { return a.ReviewDefaultFrequency }, DefaultReviewFrequency, "ReviewDefaultFrequency/no-d-suffix"},
		{"ACCESS_ANOMALY_SCAN_INTERVAL", "xyz", func(a *Access) time.Duration { return a.AnomalyScanInterval }, DefaultAnomalyScanInterval, "AnomalyScanInterval"},
		{"ACCESS_GRANT_EXPIRY_CHECK_INTERVAL", "", func(a *Access) time.Duration { return a.GrantExpiryCheckInterval }, DefaultGrantExpiryCheckInterval, "GrantExpiryCheckInterval/empty"},
		{"ACCESS_ORPHAN_RECONCILE_INTERVAL", "", func(a *Access) time.Duration { return a.OrphanReconcileInterval }, DefaultOrphanReconcileInterval, "OrphanReconcileInterval/empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.envKey, tc.envValue)
			got := tc.field(Load())
			if got != tc.want {
				t.Errorf("%s = %v; want %v (fallback to default on malformed value)", tc.name, got, tc.want)
			}
		})
	}
}

// TestLoad_DurationAcceptsBareSeconds asserts the bare-integer
// duration parser path (documented on getDurationEnv) — a shell
// operator setting "604800" should be interpreted as 7 days, not
// silently dropped to the default.
func TestLoad_DurationAcceptsBareSeconds(t *testing.T) {
	t.Setenv("ACCESS_FULL_RESYNC_INTERVAL", "604800")
	got := Load().FullResyncInterval
	want := 7 * 24 * time.Hour
	if got != want {
		t.Errorf("FullResyncInterval = %v; want %v (bare-int seconds parse)", got, want)
	}
}

// TestLoad_MalformedIntFallsBackToDefault asserts getIntEnv quietly
// returns the supplied default when the env var is unparseable —
// the same contract callers like CredentialExpiryWarningDays
// rely on so a typo can't crash the credential checker boot.
func TestLoad_MalformedIntFallsBackToDefault(t *testing.T) {
	t.Setenv("ACCESS_CREDENTIAL_EXPIRY_WARNING_DAYS", "not-a-number")
	got := Load().CredentialExpiryWarningDays
	if got != DefaultCredentialExpiryWarningDays {
		t.Errorf("CredentialExpiryWarningDays = %d; want %d", got, DefaultCredentialExpiryWarningDays)
	}
}

// TestLoad_AllDefaultsWhenEnvEmpty is the boot-without-config
// smoke test: a fresh process with no ACCESS_* env vars set must
// boot cleanly with every duration / int at its documented default.
// Regressing any of these defaults breaks the dev-binary smoke
// path documented in docs/getting-started.md.
func TestLoad_AllDefaultsWhenEnvEmpty(t *testing.T) {
	// Explicitly clear the env vars Load reads so a developer's
	// shell can't leak values into the assertion.
	for _, k := range []string{
		"ACCESS_AI_AGENT_BASE_URL",
		"ACCESS_AI_AGENT_API_KEY",
		"ACCESS_WORKFLOW_ENGINE_BASE_URL",
		"ACCESS_FULL_RESYNC_INTERVAL",
		"ACCESS_REVIEW_DEFAULT_FREQUENCY",
		"ACCESS_DRAFT_POLICY_STALE_AFTER",
		"ACCESS_ANOMALY_SCAN_INTERVAL",
		"ACCESS_CREDENTIAL_EXPIRY_WARNING_DAYS",
		"ACCESS_CREDENTIAL_CHECKER_INTERVAL",
		"ACCESS_GRANT_EXPIRY_CHECK_INTERVAL",
		"ACCESS_GRANT_EXPIRY_WARNING_HOURS",
		"ACCESS_ORPHAN_RECONCILE_INTERVAL",
		"ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR",
		"NOTIFICATION_SMTP_HOST",
		"NOTIFICATION_SMTP_PORT",
		"NOTIFICATION_SMTP_FROM",
		"NOTIFICATION_SMTP_USERNAME",
		"NOTIFICATION_SMTP_PASSWORD",
		"NOTIFICATION_SLACK_WEBHOOK_URL",
		"ACCESS_HEALTH_WEBHOOK_URL",
		"ACCESS_KAFKA_BROKERS",
		"ACCESS_AUDIT_LOG_TOPIC",
	} {
		t.Setenv(k, "")
	}
	a := Load()

	checks := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"FullResyncInterval", a.FullResyncInterval, DefaultFullResyncInterval},
		{"ReviewDefaultFrequency", a.ReviewDefaultFrequency, DefaultReviewFrequency},
		{"DraftPolicyStaleAfter", a.DraftPolicyStaleAfter, DefaultDraftPolicyStaleAfter},
		{"AnomalyScanInterval", a.AnomalyScanInterval, DefaultAnomalyScanInterval},
		{"CredentialCheckerInterval", a.CredentialCheckerInterval, DefaultCredentialCheckerInterval},
		{"GrantExpiryCheckInterval", a.GrantExpiryCheckInterval, DefaultGrantExpiryCheckInterval},
		{"OrphanReconcileInterval", a.OrphanReconcileInterval, DefaultOrphanReconcileInterval},
		{"OrphanReconcileDelayPerConnector", a.OrphanReconcileDelayPerConnector, DefaultOrphanReconcileDelayPerConnector},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v; want %v", c.name, c.got, c.want)
		}
	}
	if a.CredentialExpiryWarningDays != DefaultCredentialExpiryWarningDays {
		t.Errorf("CredentialExpiryWarningDays = %d; want %d", a.CredentialExpiryWarningDays, DefaultCredentialExpiryWarningDays)
	}
	if a.GrantExpiryWarningHours != DefaultGrantExpiryWarningHours {
		t.Errorf("GrantExpiryWarningHours = %d; want %d", a.GrantExpiryWarningHours, DefaultGrantExpiryWarningHours)
	}
	if a.NotificationSMTPPort != 587 {
		t.Errorf("NotificationSMTPPort = %d; want 587 (default SMTP submission port)", a.NotificationSMTPPort)
	}
	if a.AuditLogTopic != DefaultAuditLogTopic {
		t.Errorf("AuditLogTopic = %q; want %q", a.AuditLogTopic, DefaultAuditLogTopic)
	}
	if a.AIConfigured() {
		t.Error("AIConfigured() = true with empty AIAgentBaseURL; want false")
	}
}

// TestLoad_AllValuesParsed exercises the "every env var honoured"
// path with realistic operator-supplied values. It catches a
// regression where a new field is added to Access but Load forgets
// to wire it.
func TestLoad_AllValuesParsed(t *testing.T) {
	envs := map[string]string{
		"ACCESS_AI_AGENT_BASE_URL":                    "http://ai-agent:8090",
		"ACCESS_AI_AGENT_API_KEY":                     "sk-test",
		"ACCESS_WORKFLOW_ENGINE_BASE_URL":             "http://workflow:8082",
		"ACCESS_FULL_RESYNC_INTERVAL":                 "12h",
		"ACCESS_REVIEW_DEFAULT_FREQUENCY":             "720h",
		"ACCESS_DRAFT_POLICY_STALE_AFTER":             "48h",
		"ACCESS_ANOMALY_SCAN_INTERVAL":                "6h",
		"ACCESS_CREDENTIAL_EXPIRY_WARNING_DAYS":       "30",
		"ACCESS_CREDENTIAL_CHECKER_INTERVAL":          "12h",
		"ACCESS_GRANT_EXPIRY_CHECK_INTERVAL":          "30m",
		"ACCESS_GRANT_EXPIRY_WARNING_HOURS":           "48",
		"ACCESS_ORPHAN_RECONCILE_INTERVAL":            "6h",
		"ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR": "500ms",
		"NOTIFICATION_SMTP_HOST":                      "smtp.example.com",
		"NOTIFICATION_SMTP_PORT":                      "2525",
		"NOTIFICATION_SMTP_FROM":                      "alerts@example.com",
		"NOTIFICATION_SMTP_USERNAME":                  "alerts",
		"NOTIFICATION_SMTP_PASSWORD":                  "pw",
		"NOTIFICATION_SLACK_WEBHOOK_URL":              "https://hooks.slack.com/services/T/B/X",
		"ACCESS_HEALTH_WEBHOOK_URL":                   "https://example.com/hooks/health",
		"ACCESS_KAFKA_BROKERS":                        "kafka:9092",
		"ACCESS_AUDIT_LOG_TOPIC":                      "custom_audit_logs",
	}
	for k, v := range envs {
		t.Setenv(k, v)
	}
	a := Load()

	if a.AIAgentBaseURL != "http://ai-agent:8090" {
		t.Errorf("AIAgentBaseURL = %q", a.AIAgentBaseURL)
	}
	if !a.AIConfigured() {
		t.Error("AIConfigured() = false; want true after AIAgentBaseURL set")
	}
	if a.FullResyncInterval != 12*time.Hour {
		t.Errorf("FullResyncInterval = %v; want 12h", a.FullResyncInterval)
	}
	if a.GrantExpiryCheckInterval != 30*time.Minute {
		t.Errorf("GrantExpiryCheckInterval = %v; want 30m", a.GrantExpiryCheckInterval)
	}
	if a.OrphanReconcileDelayPerConnector != 500*time.Millisecond {
		t.Errorf("OrphanReconcileDelayPerConnector = %v; want 500ms", a.OrphanReconcileDelayPerConnector)
	}
	if a.CredentialExpiryWarningDays != 30 {
		t.Errorf("CredentialExpiryWarningDays = %d; want 30", a.CredentialExpiryWarningDays)
	}
	if a.GrantExpiryWarningHours != 48 {
		t.Errorf("GrantExpiryWarningHours = %d; want 48", a.GrantExpiryWarningHours)
	}
	if a.NotificationSMTPPort != 2525 {
		t.Errorf("NotificationSMTPPort = %d; want 2525", a.NotificationSMTPPort)
	}
	if a.AuditLogTopic != "custom_audit_logs" {
		t.Errorf("AuditLogTopic = %q; want %q", a.AuditLogTopic, "custom_audit_logs")
	}
}

// TestAIConfigured_TableDriven covers the AIConfigured helper's
// three documented branches: nil receiver, empty URL, populated URL.
func TestAIConfigured_TableDriven(t *testing.T) {
	cases := []struct {
		name string
		a    *Access
		want bool
	}{
		{"nil receiver", nil, false},
		{"empty URL", &Access{}, false},
		{"populated URL", &Access{AIAgentBaseURL: "http://x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.AIConfigured(); got != tc.want {
				t.Errorf("AIConfigured() = %v; want %v", got, tc.want)
			}
		})
	}
}
