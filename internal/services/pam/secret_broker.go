package pam

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// Sentinel errors for the secret broker. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on the message
// format. Mapped to HTTP status codes by the handler layer.
var (
	// ErrSecretNotFound is returned when the supplied secret ID does
	// not match a row scoped by workspace.
	ErrSecretNotFound = errors.New("pam: secret not found")

	// ErrEncryptorRequired is returned when SecretBrokerService is
	// constructed without a CredentialEncryptor — production
	// configurations must wire one, dev binaries may pass
	// access.PassthroughEncryptor{}.
	ErrEncryptorRequired = errors.New("pam: credential encryptor is required")
)

// SecretType-scoped MFA gate identifier used as the second arg to
// MFAVerifier.VerifyStepUp. Stable so the production verifier can
// scope the MFA session to "reveal a vault secret" specifically and
// reject tokens minted for other surfaces.
const MFAScopeSecretReveal = "pam.secret.reveal"

// SecretBrokerService backs the /pam/secrets/* HTTP surface and
// owns the vault lifecycle: vault → reveal → rotate. The service
// holds an access.CredentialEncryptor so the same AES-GCM primitive
// (and the same ACCESS_CREDENTIAL_DEK env var) that protects
// connector secrets also protects PAM secrets — no duplicate crypto
// stack.
//
// Plaintext NEVER leaves this service. The Vault* / Rotate*
// methods accept plaintext over their input parameters, encrypt it,
// and persist only the ciphertext. The Reveal* method is the single
// authorised exit point — every caller must pass through it (and
// pass the MFAVerifier gate in the handler layer first).
type SecretBrokerService struct {
	db        *gorm.DB
	encryptor access.CredentialEncryptor
	now       func() time.Time
	newID     func() string
}

// NewSecretBrokerService returns a service backed by db with the
// supplied encryptor. encryptor must not be nil and must operate
// on raw bytes (the PAM secret plaintext is a password / PEM key /
// raw token, NOT a JSON-encoded map). Production binaries wire
// pam.RawBytesAESGCMEncryptor (see raw_bytes_encryptor.go); dev /
// test code passes access.PassthroughEncryptor{}.
//
// IMPORTANT: do NOT pass access.AESGCMEncryptor here — that
// encryptor JSON-unmarshals its plaintext input and will reject
// every PAM Vault / Rotate call with an unmarshal error.
func NewSecretBrokerService(db *gorm.DB, encryptor access.CredentialEncryptor) (*SecretBrokerService, error) {
	if encryptor == nil {
		return nil, ErrEncryptorRequired
	}
	return &SecretBrokerService{
		db:        db,
		encryptor: encryptor,
		now:       time.Now,
		newID:     NewULID,
	}, nil
}

// VaultSecretInput is the input contract for VaultSecret. Plaintext
// is the raw credential bytes (password, PEM-encoded SSH key, raw
// token). It is NEVER persisted — the service immediately encrypts
// it under the broker's encryptor and discards the buffer.
type VaultSecretInput struct {
	SecretType     string
	Plaintext      []byte
	RotationPolicy datatypes.JSON
	ExpiresAt      *time.Time
}

// validateVaultSecret enforces required fields + enum membership.
func validateVaultSecret(in VaultSecretInput) error {
	if in.SecretType == "" {
		return fmt.Errorf("%w: secret_type is required", ErrValidation)
	}
	if !models.IsValidPAMSecretType(in.SecretType) {
		return fmt.Errorf("%w: secret_type %q is not one of password/ssh_key/certificate/token", ErrValidation, in.SecretType)
	}
	if len(in.Plaintext) == 0 {
		return fmt.Errorf("%w: plaintext is required", ErrValidation)
	}
	return nil
}

// VaultSecret encrypts plaintext under the broker's encryptor and
// persists the resulting ciphertext as a new pam_secrets row.
// workspaceID is bound as part of the AAD (alongside the row ID)
// so a ciphertext copy-pasted between workspaces fails to decrypt
// on purpose.
func (s *SecretBrokerService) VaultSecret(ctx context.Context, workspaceID string, in VaultSecretInput) (*models.PAMSecret, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if err := validateVaultSecret(in); err != nil {
		return nil, err
	}
	id := s.newID()
	aad := secretAAD(workspaceID, id)
	ciphertext, kv, err := s.encryptor.Encrypt(in.Plaintext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("pam: encrypt secret: %w", err)
	}
	kvInt := parseKeyVersion(kv)
	now := s.now().UTC()
	secret := &models.PAMSecret{
		ID:             id,
		WorkspaceID:    workspaceID,
		SecretType:     in.SecretType,
		Ciphertext:     string(ciphertext),
		KeyVersion:     kvInt,
		RotationPolicy: in.RotationPolicy,
		ExpiresAt:      in.ExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("pam: insert pam_secret: %w", err)
	}
	return secret, nil
}

// GetSecretMetadata returns a single pam_secrets row scoped to
// workspaceID. The Ciphertext field is NEVER exposed to the caller
// — the model's JSON tag is `-` so an accidental serialisation does
// not leak the sealed payload either.
func (s *SecretBrokerService) GetSecretMetadata(ctx context.Context, workspaceID, secretID string) (*models.PAMSecret, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if secretID == "" {
		return nil, fmt.Errorf("%w: secret_id is required", ErrValidation)
	}
	var secret models.PAMSecret
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, secretID)
		}
		return nil, fmt.Errorf("pam: get pam_secret: %w", err)
	}
	// Belt-and-braces: blank the ciphertext on the returned struct
	// so a caller that ignores the JSON tag still cannot read it.
	secret.Ciphertext = ""
	return &secret, nil
}

// RevealSecret decrypts the stored ciphertext under the broker's
// encryptor and returns the raw plaintext. The handler layer MUST
// gate this call on MFAVerifier.VerifyStepUp first; this method
// trusts that the gate has already passed (it only enforces the
// non-empty mfaAssertion present-check as a defence-in-depth
// against handler bugs).
//
// The returned plaintext is the operator's responsibility — the
// service does not log it, but it now lives outside the encryptor
// and any further copying or logging is on the caller.
func (s *SecretBrokerService) RevealSecret(ctx context.Context, workspaceID, secretID string, mfaAssertion []byte) ([]byte, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if secretID == "" {
		return nil, fmt.Errorf("%w: secret_id is required", ErrValidation)
	}
	if len(mfaAssertion) == 0 {
		return nil, ErrMFARequired
	}
	var secret models.PAMSecret
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, secretID)
		}
		return nil, fmt.Errorf("pam: get pam_secret: %w", err)
	}
	aad := secretAAD(workspaceID, secret.ID)
	plaintext, err := s.encryptor.Decrypt([]byte(secret.Ciphertext), []byte(aad), formatKeyVersion(secret.KeyVersion))
	if err != nil {
		return nil, fmt.Errorf("pam: decrypt secret: %w", err)
	}
	return plaintext, nil
}

// RotateSecret generates a new credential appropriate for the
// existing pam_secrets row's SecretType, encrypts it under the
// broker's encryptor, and updates the row in place. The previous
// ciphertext is overwritten — historic plaintext is unrecoverable
// after this call.
//
// Rotation policy is consulted only for the LastRotatedAt /
// ExpiresAt bookkeeping; the cron scheduler is responsible for
// dispatching this method on a recurring cadence.
func (s *SecretBrokerService) RotateSecret(ctx context.Context, workspaceID, secretID string) (*models.PAMSecret, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if secretID == "" {
		return nil, fmt.Errorf("%w: secret_id is required", ErrValidation)
	}
	var secret models.PAMSecret
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, secretID)
		}
		return nil, fmt.Errorf("pam: get pam_secret: %w", err)
	}
	newPlaintext, err := generateSecretPlaintext(secret.SecretType)
	if err != nil {
		return nil, fmt.Errorf("pam: generate new secret plaintext: %w", err)
	}
	aad := secretAAD(workspaceID, secret.ID)
	ciphertext, kv, err := s.encryptor.Encrypt(newPlaintext, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("pam: encrypt rotated secret: %w", err)
	}
	now := s.now().UTC()
	updates := map[string]interface{}{
		"ciphertext":      string(ciphertext),
		"key_version":     parseKeyVersion(kv),
		"last_rotated_at": now,
		"updated_at":      now,
	}
	if err := s.db.WithContext(ctx).
		Model(&models.PAMSecret{}).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("pam: rotate pam_secret: %w", err)
	}
	// Re-read the row so the returned struct reflects the new
	// LastRotatedAt + KeyVersion fields.
	if err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		First(&secret).Error; err != nil {
		return nil, fmt.Errorf("pam: re-read rotated pam_secret: %w", err)
	}
	secret.Ciphertext = ""
	return &secret, nil
}

// RotationEvent is the audit-trail entry returned by
// GetRotationHistory. The minimal field set is intentional — full
// rotation history lives in the audit producer (Kafka topic);
// this method returns a degraded "last rotation" tuple from the
// pam_secrets row itself so the admin UI can render a "last
// rotated" string without a Kafka consumer.
type RotationEvent struct {
	SecretID  string    `json:"secret_id"`
	RotatedAt time.Time `json:"rotated_at"`
	Result    string    `json:"result"`
}

// GetRotationHistory returns the single most recent rotation event
// for secretID derived from the pam_secrets row. The full audit
// trail will land in a follow-up milestone backed by the audit
// producer; until then callers see only the last successful
// rotation.
//
// Workspace-scoped on purpose: rotation timestamps can leak
// activity patterns about another tenant's secret schedule, so the
// row lookup must match BOTH the supplied workspaceID and
// secretID (mirrors GetSecretMetadata).
func (s *SecretBrokerService) GetRotationHistory(ctx context.Context, workspaceID, secretID string) ([]RotationEvent, error) {
	if workspaceID == "" {
		return nil, fmt.Errorf("%w: workspace_id is required", ErrValidation)
	}
	if secretID == "" {
		return nil, fmt.Errorf("%w: secret_id is required", ErrValidation)
	}
	var secret models.PAMSecret
	err := s.db.WithContext(ctx).
		Where("workspace_id = ? AND id = ?", workspaceID, secretID).
		First(&secret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrSecretNotFound, secretID)
		}
		return nil, fmt.Errorf("pam: get pam_secret: %w", err)
	}
	if secret.LastRotatedAt == nil {
		return []RotationEvent{}, nil
	}
	return []RotationEvent{{
		SecretID:  secret.ID,
		RotatedAt: *secret.LastRotatedAt,
		Result:    "success",
	}}, nil
}

// CheckOutSecret resolves a secret for a session-injection use case.
// leaseID is logged (in a follow-up audit producer) so the reveal is
// tied to a specific JIT lease; the current implementation simply
// validates the lease ID is non-empty and routes through
// RevealSecret with a synthesised MFA assertion (the lease's own
// approval substitutes for step-up MFA at this surface).
func (s *SecretBrokerService) CheckOutSecret(ctx context.Context, workspaceID, secretID, leaseID string) ([]byte, error) {
	if leaseID == "" {
		return nil, fmt.Errorf("%w: lease_id is required", ErrValidation)
	}
	// The lease ID acts as the implicit step-up — the gateway side
	// already validated the lease's approval state before requesting
	// the secret. A follow-up milestone will revisit this once the
	// audit producer can correlate the reveal to the lease.
	return s.RevealSecret(ctx, workspaceID, secretID, []byte(leaseID))
}

// InjectSecret resolves a secret for the pam-gateway "inject the
// credential into the SSH session" use case. sessionID + accountID
// are accepted for audit correlation; the current implementation
// looks up the account's default secret and routes through
// RevealSecret.
func (s *SecretBrokerService) InjectSecret(ctx context.Context, sessionID, accountID string) ([]byte, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: session_id is required", ErrValidation)
	}
	if accountID == "" {
		return nil, fmt.Errorf("%w: account_id is required", ErrValidation)
	}
	var account models.PAMAccount
	if err := s.db.WithContext(ctx).Where("id = ?", accountID).First(&account).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrAccountNotFound, accountID)
		}
		return nil, fmt.Errorf("pam: get pam_account: %w", err)
	}
	if account.SecretID == nil || *account.SecretID == "" {
		return nil, fmt.Errorf("%w: account %s has no vaulted secret", ErrValidation, accountID)
	}
	// Look up the asset so we can scope the reveal to the asset's
	// workspace — preserves the "ciphertext bound to workspace_id"
	// invariant established in VaultSecret.
	var asset models.PAMAsset
	if err := s.db.WithContext(ctx).Where("id = ?", account.AssetID).First(&asset).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrAssetNotFound, account.AssetID)
		}
		return nil, fmt.Errorf("pam: get pam_asset for inject: %w", err)
	}
	// Session ID acts as the implicit step-up — the gateway has
	// already validated the session's lease before reaching this
	// point.
	return s.RevealSecret(ctx, asset.WorkspaceID, *account.SecretID, []byte(sessionID))
}

// secretAAD builds the Additional Authenticated Data binding used
// for AES-GCM. Including the workspace ID + the secret ID means a
// ciphertext copied between secrets or between workspaces fails to
// decrypt.
func secretAAD(workspaceID, secretID string) string {
	return "pam:" + workspaceID + ":" + secretID
}

// parseKeyVersion turns the encryptor's keyVersion string ("1",
// "2", ...) into the int column stored on pam_secrets. Falls back
// to 0 on a non-numeric value so unknown encryptors stay routable
// through Decrypt (which ignores the column in the static-DEK boot
// mode anyway).
func parseKeyVersion(kv string) int {
	var n int
	for _, r := range kv {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	if kv == "" {
		return 0
	}
	return n
}

// formatKeyVersion is the inverse of parseKeyVersion — turns the
// int column back into the string the encryptor expects. n=0 is a
// valid key version stamp (PassthroughEncryptor returns "0", and a
// future KMS-backed encryptor may use 0 as the bootstrap version)
// so it round-trips as "0". Negative values are not produced by
// parseKeyVersion but we clamp them to "0" as a defence against
// callers that pass corrupted column values.
func formatKeyVersion(n int) string {
	if n < 0 {
		return "0"
	}
	if n == 0 {
		return "0"
	}
	// Avoid pulling strconv into the hot path; tiny inline.
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// generateSecretPlaintext produces a fresh credential appropriate
// for secretType. The output is the raw plaintext the encryptor
// expects; callers seal it under the broker's encryptor before
// persisting.
//
// password: 32-byte random base64 — the same entropy floor used by
// the access-platform credential manager.
// ssh_key: PEM-encoded 2048-bit RSA private key (per
// docs/pam/architecture.md). Ed25519 would be the modern choice
// but RSA stays compatible with the broadest set of target hosts;
// the gateway is free to upgrade per-asset later.
// certificate / token: 32-byte random base64 — generic fallback.
// Operators that need a real x509 cert sign one out-of-band and
// VaultSecret it.
func generateSecretPlaintext(secretType string) ([]byte, error) {
	switch secretType {
	case models.PAMSecretTypePassword, models.PAMSecretTypeToken, models.PAMSecretTypeCertificate:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return nil, fmt.Errorf("read entropy: %w", err)
		}
		out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(out, raw)
		return out, nil
	case models.PAMSecretTypeSSHKey:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate rsa key: %w", err)
		}
		der := x509.MarshalPKCS1PrivateKey(key)
		pemBytes := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: der,
		})
		return pemBytes, nil
	default:
		return nil, fmt.Errorf("%w: unsupported secret_type %q", ErrValidation, secretType)
	}
}
