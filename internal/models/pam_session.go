package models

import (
	"time"

	"gorm.io/gorm"
)

// PAMSession mirrors the pam_sessions table per docs/pam/architecture.md.
// One row per live or historical privileged session brokered through
// pam-gateway. The State column is the source of truth for where the
// session is in the FSM (requested → active → completed/terminated/failed).
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints; WorkspaceID / UserID /
//     AssetID / AccountID are indexed strings; application code
//     enforces referential integrity.
//   - ReplayStorageKey is the S3 object key the gateway streams I/O
//     to; empty until the gateway accepts the session. Per
//     docs/pam/architecture.md it lands under
//     s3://shieldnet-pam-replay/{workspace}/{session}.bin.
//   - RiskScore is a coarse numeric bucket (0-100) populated by the
//     AI agent after the row is written. Nullable; never set by the
//     user.
//   - CommandCount is a denormalised counter kept in sync by the
//     gateway as commands are appended to pam_session_commands; the
//     authoritative count is the COUNT(*) over that child table.
type PAMSession struct {
	ID               string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID      string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	UserID           string         `gorm:"type:varchar(26);not null;index" json:"user_id"`
	AssetID          string         `gorm:"type:varchar(26);not null;index" json:"asset_id"`
	AccountID        string         `gorm:"type:varchar(26);not null" json:"account_id"`
	Protocol         string         `gorm:"type:varchar(32);not null" json:"protocol"`
	State            string         `gorm:"type:varchar(32);not null;default:'requested';index" json:"state"`
	StartedAt        *time.Time     `json:"started_at,omitempty"`
	EndedAt          *time.Time     `json:"ended_at,omitempty"`
	ReplayStorageKey string         `gorm:"type:varchar(512)" json:"replay_storage_key,omitempty"`
	CommandCount     int            `gorm:"not null;default:0" json:"command_count"`
	RiskScore        *int           `json:"risk_score,omitempty"`
	DeletedAt        gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_sessions.
func (PAMSession) TableName() string {
	return "pam_sessions"
}

// PAM session state enums. Strings are operator-visible in the admin
// UI and stable across versions.
const (
	PAMSessionStateRequested  = "requested"
	PAMSessionStateActive     = "active"
	PAMSessionStateCompleted  = "completed"
	PAMSessionStateTerminated = "terminated"
	PAMSessionStateFailed     = "failed"
)

// IsValidPAMSessionState reports whether state is one of the five
// supported FSM states.
func IsValidPAMSessionState(state string) bool {
	switch state {
	case PAMSessionStateRequested, PAMSessionStateActive,
		PAMSessionStateCompleted, PAMSessionStateTerminated,
		PAMSessionStateFailed:
		return true
	}
	return false
}
