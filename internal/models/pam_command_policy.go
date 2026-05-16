package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// PAMCommandPolicy mirrors the pam_command_policies table per
// docs/pam/architecture.md. One row per per-workspace command rule
// evaluated by pam-gateway during a live session — matched policies
// drive allow / deny / step_up actions on the offending command.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string).
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rules); WorkspaceID is an indexed string.
//   - AssetSelector / AccountSelector are operator-visible JSON
//     blobs that scope which (asset, account) tuples the rule
//     applies to (e.g. {"criticality": "critical"} → all critical
//     assets). Empty selector means "any".
//   - Pattern is a Go regexp matched against the operator-typed
//     command line. The pam-gateway compiles it once at policy
//     load time and caches the result.
//   - Action is one of (allow, deny, step_up). step_up forces a
//     re-MFA challenge before the command is forwarded.
//   - Priority orders the rule set; lower numbers win. Ties are
//     broken by CreatedAt ascending.
type PAMCommandPolicy struct {
	ID              string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID     string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	AssetSelector   datatypes.JSON `gorm:"type:jsonb" json:"asset_selector,omitempty"`
	AccountSelector datatypes.JSON `gorm:"type:jsonb" json:"account_selector,omitempty"`
	Pattern         string         `gorm:"type:text;not null" json:"pattern"`
	Action          string         `gorm:"type:varchar(32);not null" json:"action"`
	Priority        int            `gorm:"not null;default:100" json:"priority"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_command_policies.
func (PAMCommandPolicy) TableName() string {
	return "pam_command_policies"
}

// PAM command policy action enums.
const (
	PAMCommandActionAllow  = "allow"
	PAMCommandActionDeny   = "deny"
	PAMCommandActionStepUp = "step_up"
)

// IsValidPAMCommandAction reports whether action is one of the three
// supported values.
func IsValidPAMCommandAction(action string) bool {
	switch action {
	case PAMCommandActionAllow, PAMCommandActionDeny, PAMCommandActionStepUp:
		return true
	}
	return false
}
