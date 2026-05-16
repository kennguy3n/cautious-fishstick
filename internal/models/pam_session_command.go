package models

import (
	"time"

	"gorm.io/gorm"
)

// PAMSessionCommand mirrors the pam_session_commands table per
// docs/pam/architecture.md. One row per command (SSH shell verb,
// kubectl call, SQL statement) observed during a brokered session.
// The row stores the operator-typed Input verbatim and an OutputHash
// (SHA-256) of the response stream — full output lives in the S3
// replay blob, never on disk in this row.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints; SessionID is an indexed
//     string and application code enforces referential integrity.
//   - Sequence is monotonically increasing within a session — the
//     gateway stamps it as it appends.
//   - Timestamp is the wall-clock time the command was observed (NOT
//     CreatedAt — CreatedAt is the DB insert time, which can lag).
//   - RiskFlag is nullable; populated by the command-policy engine
//     when the input matched a deny / step_up rule.
type PAMSessionCommand struct {
	ID         string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	SessionID  string         `gorm:"type:varchar(26);not null;index" json:"session_id"`
	Sequence   int            `gorm:"not null" json:"sequence"`
	Input      string         `gorm:"type:text;not null" json:"input"`
	OutputHash string         `gorm:"type:varchar(128)" json:"output_hash,omitempty"`
	Timestamp  time.Time      `gorm:"not null" json:"timestamp"`
	RiskFlag   *string        `gorm:"type:varchar(64)" json:"risk_flag,omitempty"`
	DeletedAt  gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_session_commands.
func (PAMSessionCommand) TableName() string {
	return "pam_session_commands"
}
