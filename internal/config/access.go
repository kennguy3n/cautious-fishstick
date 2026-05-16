// Package config holds the authoritative process-level configuration
// for the ShieldNet 360 Access Platform binaries (cmd/ztna-api,
// cmd/access-connector-worker, cmd/access-workflow-engine). Per
// docs/architecture.md §12 the access platform reads its knobs from
// environment variables; this package centralises the reads so a
// future migration to TOML / YAML / Vault is one file change.
package config

import (
	"os"
	"strconv"
	"time"
)

// Default values for the access-platform knobs. Mirrors the table in
// docs/architecture.md §12.
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

	// DefaultAnomalyScanInterval is the cadence at which the
	// access-connector-worker walks every workspace and asks the AI
	// agent for anomaly observations. Mirrors the access-review
	// scheduler — 24h is the right default for a Phase 6 stub
	// (cheap to run, surfaces stale grants quickly enough).
	DefaultAnomalyScanInterval = 24 * time.Hour

	// DefaultCredentialExpiryWarningDays is the number of days
	// ahead of credential expiry at which CredentialChecker emits a
	// notification. 14 days mirrors common SaaS rotation reminders
	// and gives operators two cycles of weekly review to act on
	// the warning before access breaks.
	DefaultCredentialExpiryWarningDays = 14

	// DefaultCredentialCheckerInterval is the cadence at which the
	// access-connector-worker scans access_connectors for soon-to-
	// expire credentials. Once daily is plenty for a 14-day warning
	// horizon.
	DefaultCredentialCheckerInterval = 24 * time.Hour

	// DefaultGrantExpiryCheckInterval is the cadence at which the
	// access-connector-worker scans access_grants for rows whose
	// expires_at has passed and pushes a revoke to the upstream
	// connector. Phase 11 (docs/architecture.md §13) introduces grant-
	// expiry enforcement as the automated counterpart to the
	// reviewer-driven Phase 5 revoke flow; one hour is the right
	// default for a JIT "15-minute grant" workload — the worst-case
	// time-to-revoke after expiry is bounded by the tick interval.
	DefaultGrantExpiryCheckInterval = 1 * time.Hour

	// DefaultOrphanReconcileInterval is the cadence at which the
	// access-connector-worker walks every workspace through the
	// orphan-account reconciler. 24h is the right default for a
	// Phase 11 surface that surfaces "unused app accounts" to
	// operators — it matches the daily anomaly-scan cadence and
	// keeps the reconciler cheap to run.
	DefaultOrphanReconcileInterval = 24 * time.Hour

	// DefaultOrphanReconcileDelayPerConnector is the throttle the
	// reconciler waits between connector iterations inside a single
	// workspace pass. 1s keeps every connector's SyncIdentities one
	// after the other so upstream APIs are not hammered when a
	// workspace has many connectors.
	DefaultOrphanReconcileDelayPerConnector = 1 * time.Second

	// DefaultGrantExpiryWarningHours is the look-ahead window for
	// the grant-expiry warning sweep. Grants whose expires_at falls
	// within this window are flagged in a "your access expires
	// soon" notification so users can request renewal before the
	// auto-revoke pass. Phase 11 batch 6 hook.
	DefaultGrantExpiryWarningHours = 24

	// DefaultAuditLogTopic is the Kafka topic the access-audit
	// producer publishes ShieldnetLogEvent v1 envelopes to.
	DefaultAuditLogTopic = "access_audit_logs"
)

// Access is the typed snapshot of the access-platform environment
// configuration. Construct via Load() at process start; mutating the
// struct after that is undefined behaviour (no synchronisation).
type Access struct {
	// AIAgentBaseURL is the root URL of the access-ai-agent A2A
	// server. Empty means "AI is intentionally unconfigured" — the
	// service layer's AssessRiskWithFallback recognises this and
	// short-circuits to the medium-risk fallback per
	// docs/architecture.md §8.
	AIAgentBaseURL string

	// AIAgentAPIKey is the shared secret for X-API-Key header per
	// docs/architecture.md §12. Never logged.
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

	// AnomalyScanInterval is the cadence at which the
	// access-connector-worker walks every workspace through
	// AnomalyDetectionService.ScanWorkspace. Defaults to
	// DefaultAnomalyScanInterval.
	AnomalyScanInterval time.Duration

	// CredentialExpiryWarningDays is the number of days before a
	// connector credential expires that the credential-checker cron
	// emits a notification. Defaults to
	// DefaultCredentialExpiryWarningDays.
	CredentialExpiryWarningDays int

	// CredentialCheckerInterval is the cadence at which the
	// access-connector-worker scans access_connectors for credential
	// expiry. Defaults to DefaultCredentialCheckerInterval.
	CredentialCheckerInterval time.Duration

	// OrphanReconcileInterval is the cadence at which the
	// access-connector-worker walks every workspace through
	// OrphanReconciler.ReconcileWorkspace. Defaults to
	// DefaultOrphanReconcileInterval.
	OrphanReconcileInterval time.Duration

	// OrphanReconcileDelayPerConnector is the throttle the
	// reconciler waits between connector iterations inside a
	// single workspace pass. Defaults to
	// DefaultOrphanReconcileDelayPerConnector.
	OrphanReconcileDelayPerConnector time.Duration

	// GrantExpiryWarningHours is the look-ahead window (in hours)
	// for the grant-expiry warning sweep. Defaults to
	// DefaultGrantExpiryWarningHours.
	GrantExpiryWarningHours int

	// GrantExpiryCheckInterval is the cadence at which the
	// access-connector-worker walks access_grants for expired rows
	// and revokes each one through the upstream connector. Phase 11
	// (docs/architecture.md §13) automation. Defaults to
	// DefaultGrantExpiryCheckInterval.
	GrantExpiryCheckInterval time.Duration

	// Notification SMTP knobs power the email Notifier. All five
	// must be set for the notifier to dispatch real emails; if SMTPHost
	// is empty the notifier is in "log-only" mode (it formats the
	// message and writes it to the log without dialling SMTP).
	NotificationSMTPHost     string
	NotificationSMTPPort     int
	NotificationSMTPFrom     string
	NotificationSMTPUsername string
	// NotificationSMTPPassword is the SMTP AUTH password. Never logged.
	NotificationSMTPPassword string

	// NotificationSlackWebhookURL is the Slack incoming-webhook URL
	// the slack Notifier posts to. Empty means "Slack channel is
	// intentionally unconfigured" — the notifier short-circuits to a
	// log line so dev binaries stay healthy without a webhook.
	NotificationSlackWebhookURL string

	// HealthWebhookURL is the operator-supplied URL the platform
	// POSTs ConnectorHealthEvent envelopes to whenever a connector
	// enters the "needs attention" state (stale audit cursor /
	// expired credential). Empty turns the dispatcher into a no-op
	// (see internal/services/access/connector_health_webhook.go).
	HealthWebhookURL string

	// KafkaBrokers is the comma-separated list of Kafka bootstrap
	// brokers used by the access-audit producer (docs/architecture.md).
	// Empty means "Kafka is intentionally unconfigured" — the
	// AuditProducer factory falls back to NoOpAuditProducer so dev
	// binaries can run without a broker.
	KafkaBrokers string

	// AuditLogTopic is the Kafka topic the access-audit producer
	// writes ShieldnetLogEvent v1 envelopes to. Defaults to
	// "access_audit_logs" per docs/architecture.md.
	AuditLogTopic string
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
		AIAgentBaseURL:              getEnv("ACCESS_AI_AGENT_BASE_URL"),
		AIAgentAPIKey:               getEnv("ACCESS_AI_AGENT_API_KEY"),
		WorkflowEngineBaseURL:       getEnv("ACCESS_WORKFLOW_ENGINE_BASE_URL"),
		FullResyncInterval:          getDurationEnv("ACCESS_FULL_RESYNC_INTERVAL", DefaultFullResyncInterval),
		ReviewDefaultFrequency:      getDurationEnv("ACCESS_REVIEW_DEFAULT_FREQUENCY", DefaultReviewFrequency),
		DraftPolicyStaleAfter:       getDurationEnv("ACCESS_DRAFT_POLICY_STALE_AFTER", DefaultDraftPolicyStaleAfter),
		AnomalyScanInterval:         getDurationEnv("ACCESS_ANOMALY_SCAN_INTERVAL", DefaultAnomalyScanInterval),
		CredentialExpiryWarningDays: getIntEnv("ACCESS_CREDENTIAL_EXPIRY_WARNING_DAYS", DefaultCredentialExpiryWarningDays),
		CredentialCheckerInterval:   getDurationEnv("ACCESS_CREDENTIAL_CHECKER_INTERVAL", DefaultCredentialCheckerInterval),
		GrantExpiryCheckInterval:    getDurationEnv("ACCESS_GRANT_EXPIRY_CHECK_INTERVAL", DefaultGrantExpiryCheckInterval),
		GrantExpiryWarningHours:     getIntEnv("ACCESS_GRANT_EXPIRY_WARNING_HOURS", DefaultGrantExpiryWarningHours),
		OrphanReconcileInterval:     getDurationEnv("ACCESS_ORPHAN_RECONCILE_INTERVAL", DefaultOrphanReconcileInterval),
		OrphanReconcileDelayPerConnector: getDurationEnv("ACCESS_ORPHAN_RECONCILE_DELAY_PER_CONNECTOR", DefaultOrphanReconcileDelayPerConnector),
		NotificationSMTPHost:        getEnv("NOTIFICATION_SMTP_HOST"),
		NotificationSMTPPort:        getIntEnv("NOTIFICATION_SMTP_PORT", 587),
		NotificationSMTPFrom:        getEnv("NOTIFICATION_SMTP_FROM"),
		NotificationSMTPUsername:    getEnv("NOTIFICATION_SMTP_USERNAME"),
		NotificationSMTPPassword:    getEnv("NOTIFICATION_SMTP_PASSWORD"),
		NotificationSlackWebhookURL: getEnv("NOTIFICATION_SLACK_WEBHOOK_URL"),
		HealthWebhookURL:            getEnv("ACCESS_HEALTH_WEBHOOK_URL"),
		KafkaBrokers:                getEnv("ACCESS_KAFKA_BROKERS"),
		AuditLogTopic:               getEnvDefault("ACCESS_AUDIT_LOG_TOPIC", DefaultAuditLogTopic),
	}
}

// getEnvDefault returns the environment variable named key, or def if
// the variable is unset or empty.
func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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

// getIntEnv parses the environment variable named key as a base-10
// integer. Falls back to def when the variable is unset, empty, or
// unparseable. Negative values are accepted (callers that want
// non-negative semantics validate after Load).
func getIntEnv(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}
