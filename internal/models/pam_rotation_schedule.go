package models

import (
	"time"

	"gorm.io/gorm"
)

// PAMRotationSchedule mirrors the pam_rotation_schedules table per
// docs/pam/architecture.md. One row per PAMSecret that should be
// rotated on a recurring cadence. The rotation cron scans this table
// for IsActive rows with NextRunAt <= now and dispatches a rotation
// through SecretBrokerService.RotateSecret.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rules); SecretID is an indexed string and application code
//     enforces referential integrity.
//   - FrequencyDays drives the NextRunAt update after a successful
//     rotation (next_run_at = now + frequency_days).
//   - LastResult is a short status code ("success", "failed:
//     {reason}") rather than a full audit log — full history lives
//     in the audit producer.
//   - IsActive defaults to true. Operators can pause a schedule
//     without deleting it by flipping this flag.
type PAMRotationSchedule struct {
	ID            string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	SecretID      string         `gorm:"type:varchar(26);not null;index" json:"secret_id"`
	FrequencyDays int            `gorm:"not null" json:"frequency_days"`
	NextRunAt     time.Time      `gorm:"not null;index" json:"next_run_at"`
	LastResult    string         `gorm:"type:varchar(255)" json:"last_result,omitempty"`
	IsActive      bool           `gorm:"not null;default:true" json:"is_active"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_rotation_schedules.
func (PAMRotationSchedule) TableName() string {
	return "pam_rotation_schedules"
}
