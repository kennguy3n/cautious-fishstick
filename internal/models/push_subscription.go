package models

import "time"

// PushSubscription mirrors the push_subscriptions table. Operators
// register a row per browser session via the access-platform UI; the
// notification service's WebPushNotifier reads them by UserID and
// fans the rendered envelope out to every active row.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - WorkspaceID is the multi-tenant scoping dimension.
//   - UserID is the internal user ID the subscription belongs to.
//   - Endpoint is the absolute push-service URL the browser
//     supplied. It is opaque to us and may carry a sensitive token in
//     the path; never log it raw — use redactEndpoint helper.
//   - P256DH / Auth are the per-subscription public keys returned by
//     the browser-side PushManager.subscribe() call.
//   - DisabledAt being non-nil soft-disables the row without
//     deleting it (e.g. after the browser reports the subscription
//     expired).
//
// No FOREIGN KEY constraints (per docs/internal/PHASES.md cross-cutting
// criteria).
type PushSubscription struct {
	ID          string     `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID string     `gorm:"type:varchar(26);not null;index:idx_push_subscriptions_workspace_user,priority:1" json:"workspace_id"`
	UserID      string     `gorm:"type:varchar(64);not null;index:idx_push_subscriptions_workspace_user,priority:2" json:"user_id"`
	Endpoint    string     `gorm:"type:text;not null" json:"endpoint"`
	P256DH      string     `gorm:"type:varchar(255)" json:"p256dh,omitempty"`
	Auth        string     `gorm:"type:varchar(255)" json:"auth,omitempty"`
	UserAgent   string     `gorm:"type:text" json:"user_agent,omitempty"`
	DisabledAt  *time.Time `json:"disabled_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// TableName overrides the default plural so the table name is
// exactly push_subscriptions (matching the migration).
func (PushSubscription) TableName() string {
	return "push_subscriptions"
}
