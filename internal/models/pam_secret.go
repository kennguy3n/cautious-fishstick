package models

import (
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// PAMSecret mirrors the pam_secrets table per docs/pam/architecture.md.
// One row per vaulted credential (password, SSH key, certificate,
// API token) referenced by a PAMAccount. Plaintext NEVER lands on
// disk — Ciphertext is AES-GCM under the org DEK with the secret's
// ULID bound as Additional Authenticated Data.
//
// Notable invariants:
//
//   - ID is a 26-char ULID (string). The ID doubles as the AAD when
//     encrypting Ciphertext; changing the ID after a row is written
//     makes the ciphertext undecryptable on purpose.
//   - There are no FOREIGN KEY constraints (per SN360 database-index
//     rules).
//   - Ciphertext is the base64-encoded, nonce-prefixed AES-GCM
//     payload. KeyVersion pins which org DEK version was used so a
//     future rotation can read older ciphertext.
//   - RotationPolicy is operator-visible JSON (frequency_days,
//     auto_rotate, ...) consumed by the rotation cron.
//   - SecretType is one of (password, ssh_key, certificate, token);
//     validated by IsValidPAMSecretType.
type PAMSecret struct {
	ID             string         `gorm:"primaryKey;type:varchar(26)" json:"id"`
	WorkspaceID    string         `gorm:"type:varchar(26);not null;index" json:"workspace_id"`
	SecretType     string         `gorm:"type:varchar(32);not null" json:"secret_type"`
	Ciphertext     string         `gorm:"type:text;not null" json:"-"`
	KeyVersion     int            `gorm:"not null;default:1" json:"key_version"`
	RotationPolicy datatypes.JSON `gorm:"type:jsonb" json:"rotation_policy,omitempty"`
	LastRotatedAt  *time.Time     `json:"last_rotated_at,omitempty"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// TableName overrides the default plural form so the table is exactly
// pam_secrets.
func (PAMSecret) TableName() string {
	return "pam_secrets"
}

// PAM secret type enums. Drives the rotation generator and the
// session-injection path:
//   - password: opaque text credential
//   - ssh_key: PEM-encoded SSH private key (RSA / Ed25519)
//   - certificate: x509 / SSH certificate bundle
//   - token: short-lived bearer (API key, OAuth refresh)
const (
	PAMSecretTypePassword    = "password"
	PAMSecretTypeSSHKey      = "ssh_key"
	PAMSecretTypeCertificate = "certificate"
	PAMSecretTypeToken       = "token"
)

// IsValidPAMSecretType reports whether secretType is one of the four
// supported values.
func IsValidPAMSecretType(secretType string) bool {
	switch secretType {
	case PAMSecretTypePassword, PAMSecretTypeSSHKey, PAMSecretTypeCertificate, PAMSecretTypeToken:
		return true
	}
	return false
}
