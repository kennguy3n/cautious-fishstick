package models

import "time"

// AccessRequestStateHistory mirrors the access_request_state_history table
// per docs/architecture.md §10. One row per state transition on an
// AccessRequest. Inserted from inside the same DB transaction that flips
// AccessRequest.State, so the audit trail can never disagree with the live
// state column.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - RequestID is *not* a FOREIGN KEY (per SN360 database-index rule); it
//     is a plain indexed string column. Joins are application-side.
//   - FromState may be the empty string for the initial "" → "requested"
//     entry created by CreateRequest. Every subsequent row has a non-empty
//     FromState matching a value in request_state_machine.go.
//   - ActorUserID is the user who triggered the transition. May be empty
//     for system-driven transitions (auto-expiry, provisioning worker, ...).
//   - There is no UpdatedAt and no DeletedAt: history rows are append-only.
type AccessRequestStateHistory struct {
	ID          string    `gorm:"primaryKey;type:varchar(26)" json:"id"`
	RequestID   string    `gorm:"type:varchar(26);not null;index" json:"request_id"`
	FromState   string    `gorm:"type:varchar(50);not null" json:"from_state"`
	ToState     string    `gorm:"type:varchar(50);not null" json:"to_state"`
	ActorUserID string    `gorm:"type:varchar(26)" json:"actor_user_id,omitempty"`
	Reason      string    `gorm:"type:text" json:"reason,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// TableName overrides the default plural so the table name is exactly
// access_request_state_history.
func (AccessRequestStateHistory) TableName() string {
	return "access_request_state_history"
}
