package models

import (
	"time"

	"gorm.io/gorm"
)

// PAMAccount mirrors the pam_accounts table per docs/pam/architecture.md.
// One row per (asset, username) tuple — a named credential surface
// on the target asset (e.g. root@db-prod-01, deploy@web-prod-01).
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rules); AssetID + SecretID are indexed strings; application
//     code enforces referential integrity.
//   - SecretID is nullable — an account row can exist without a vaulted
//     secret (e.g. a shared SSH key managed out-of-band).
//   - AccountType is one of (shared, personal, service); validated
//     by IsValidPAMAccountType before insert.
//   - IsDefault flags the account that pam-gateway will pick when
//     a session request does not specify an account explicitly.
type PAMAccount struct {
	ID          string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	AssetID     string         `gorm:"type:varchar(26);not null;index" json:"asset_id"`
	Username    string         `gorm:"type:varchar(255);not null" json:"username"`
	AccountType string         `gorm:"type:varchar(32);not null;default:'shared'" json:"account_type"`
	SecretID    *string        `gorm:"type:varchar(26);index" json:"secret_id,omitempty"`
	IsDefault   bool           `gorm:"not null;default:false" json:"is_default"`
	Status      string         `gorm:"type:varchar(32);not null;default:'active'" json:"status"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_accounts.
func (PAMAccount) TableName() string {
	return "pam_accounts"
}

// PAM account type enums. Drives the session-broker UX:
//   - shared: same secret across multiple users (e.g. root)
//   - personal: per-user secret (e.g. alice@host)
//   - service: machine identity (long-lived service principal)
const (
	PAMAccountTypeShared   = "shared"
	PAMAccountTypePersonal = "personal"
	PAMAccountTypeService  = "service"
)

// PAM account status enums.
const (
	PAMAccountStatusActive   = "active"
	PAMAccountStatusInactive = "inactive"
	PAMAccountStatusArchived = "archived"
)

// IsValidPAMAccountType reports whether accountType is one of the
// three supported values.
func IsValidPAMAccountType(accountType string) bool {
	switch accountType {
	case PAMAccountTypeShared, PAMAccountTypePersonal, PAMAccountTypeService:
		return true
	}
	return false
}
