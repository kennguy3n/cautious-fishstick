// Package credentials provides AES-GCM credential encryption for access
// connector secrets. Mirrors shieldnet360-backend/internal/pkg/credentials and
// internal/pkg/encryption: secrets JSON is encrypted under a per-organization
// DEK with the access connector ULID bound as Additional Authenticated Data,
// and the resulting ciphertext is stored in access_connectors.credentials.
//
// Decrypted secrets are scoped to a single job execution; callers must not
// log them or persist them anywhere outside the in-memory map returned by
// GetCredentials.
package credentials

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// dekSize is the required DEK length (AES-256 → 32 bytes).
const dekSize = 32

// Sentinel errors.
var (
	// ErrInvalidDEK is returned when the supplied DEK is not 32 bytes.
	ErrInvalidDEK = errors.New("credentials: DEK must be 32 bytes (AES-256)")
	// ErrEmptyAAD is returned when AAD is empty. AAD binds ciphertext to
	// its connector ULID; allowing empty AAD would let ciphertext be
	// copy-pasted between connectors.
	ErrEmptyAAD = errors.New("credentials: AAD (connector ULID) must not be empty")
	// ErrEmptyCiphertext is returned when GetCredentials is called with
	// empty ciphertext (i.e. row was never seeded).
	ErrEmptyCiphertext = errors.New("credentials: ciphertext is empty")
)

// KeyManager is the contract the CredentialManager uses to fetch organization
// data-encryption keys. The production implementation lives outside this
// package (it wraps a KMS / Vault / dev-only secrets.Manager) — we keep the
// interface here so the CredentialManager can be unit-tested against a stub.
type KeyManager interface {
	// GetLatestOrgDEK returns the current DEK for orgID and the version
	// stamp that should be persisted alongside any new ciphertext written
	// for that organization.
	GetLatestOrgDEK(ctx context.Context, orgID string) (dek []byte, keyVersion int, err error)

	// GetOrgDEK returns the DEK for orgID at the given version. Used at
	// decrypt time so old ciphertext stays readable across DEK rotations.
	GetOrgDEK(ctx context.Context, orgID string, version int) (dek []byte, err error)
}

// CredentialManager encrypts and decrypts the JSON-shaped secrets blob stored
// in access_connectors.credentials.
type CredentialManager struct {
	keyManager KeyManager
}

// NewCredentialManager constructs a CredentialManager backed by the supplied
// KeyManager. keyManager may be nil for tests that only exercise the raw
// Encrypt / Decrypt entry points.
func NewCredentialManager(keyManager KeyManager) *CredentialManager {
	return &CredentialManager{keyManager: keyManager}
}

// Encrypt JSON-marshals secrets and seals them under the supplied DEK using
// AES-GCM with aad bound as Additional Authenticated Data. aad is the access
// connector ULID — passing it through unchanged at decrypt time is what
// prevents ciphertext from being copy-pasted between rows.
//
// The returned string is base64-encoded, contains the GCM nonce as a prefix,
// and is suitable for direct insertion into access_connectors.credentials.
func (cm *CredentialManager) Encrypt(secrets map[string]interface{}, dek []byte, aad string) (string, error) {
	if len(dek) != dekSize {
		return "", ErrInvalidDEK
	}
	if aad == "" {
		return "", ErrEmptyAAD
	}

	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return "", fmt.Errorf("credentials: marshal secrets: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("credentials: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("credentials: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("credentials: read nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(aad))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt: it base64-decodes ciphertext, opens it under the
// supplied DEK with aad as AAD, and JSON-unmarshals the inner plaintext into
// a fresh map.
//
// Decrypt deliberately does not log the plaintext on success or failure.
// Errors include the AES-GCM authentication outcome — they intentionally do
// not embed the ciphertext or DEK so log scrapes never accidentally surface
// secret material.
func (cm *CredentialManager) Decrypt(ciphertextB64 string, dek []byte, aad string) (map[string]interface{}, error) {
	if len(dek) != dekSize {
		return nil, ErrInvalidDEK
	}
	if aad == "" {
		return nil, ErrEmptyAAD
	}

	sealed, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("credentials: base64 decode: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("credentials: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credentials: new gcm: %w", err)
	}

	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("credentials: ciphertext too short")
	}

	nonce, payload := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, payload, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("credentials: gcm open failed (aad mismatch or wrong key): %w", err)
	}

	var out map[string]interface{}
	if err := json.Unmarshal(plaintext, &out); err != nil {
		return nil, fmt.Errorf("credentials: unmarshal plaintext: %w", err)
	}
	return out, nil
}

// EncryptBytes seals plaintext bytes under the supplied DEK using AES-GCM
// with aad bound as Additional Authenticated Data. It is the raw-bytes twin
// of Encrypt: callers that hold credential material which is NOT a
// JSON-marshalled map (raw passwords, PEM-encoded SSH keys, base64 tokens,
// x509 certificates) go through EncryptBytes instead of paying the
// marshal / unmarshal round trip. The output is the same nonce-prefixed,
// base64-encoded payload format DecryptBytes — and the JSON-map Encrypt —
// produce, so the same backing store can hold both shapes.
func (cm *CredentialManager) EncryptBytes(plaintext []byte, dek []byte, aad string) (string, error) {
	if len(dek) != dekSize {
		return "", ErrInvalidDEK
	}
	if aad == "" {
		return "", ErrEmptyAAD
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("credentials: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("credentials: new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("credentials: read nonce: %w", err)
	}

	sealed := gcm.Seal(nonce, nonce, plaintext, []byte(aad))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptBytes is the raw-bytes twin of Decrypt: it base64-decodes
// ciphertext, opens it under the supplied DEK with aad as AAD, and returns
// the inner plaintext verbatim — no JSON unmarshalling. Used by PAM secrets
// (passwords, SSH keys, tokens, certificates) whose plaintext is not a JSON
// map and would fail to unmarshal through Decrypt.
func (cm *CredentialManager) DecryptBytes(ciphertextB64 string, dek []byte, aad string) ([]byte, error) {
	if len(dek) != dekSize {
		return nil, ErrInvalidDEK
	}
	if aad == "" {
		return nil, ErrEmptyAAD
	}

	sealed, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("credentials: base64 decode: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("credentials: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credentials: new gcm: %w", err)
	}

	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("credentials: ciphertext too short")
	}

	nonce, payload := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, payload, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("credentials: gcm open failed (aad mismatch or wrong key): %w", err)
	}
	return plaintext, nil
}

// GetCredentials is the convenience entry point used by worker handlers. It
// fetches the right-versioned DEK from the configured KeyManager, decrypts
// the supplied ciphertext with the connector ULID as AAD, and returns the
// secrets map.
//
// connectorID doubles as the AAD; orgID + keyVersion select the DEK.
func (cm *CredentialManager) GetCredentials(
	ctx context.Context,
	connectorID, orgID string,
	keyVersion int,
	ciphertextB64 string,
) (map[string]interface{}, error) {
	if cm.keyManager == nil {
		return nil, errors.New("credentials: key manager not configured")
	}
	if connectorID == "" {
		return nil, errors.New("credentials: connectorID required")
	}
	ciphertextB64 = strings.TrimSpace(ciphertextB64)
	if ciphertextB64 == "" {
		return nil, ErrEmptyCiphertext
	}

	dek, err := cm.keyManager.GetOrgDEK(ctx, orgID, keyVersion)
	if err != nil {
		return nil, fmt.Errorf("credentials: get DEK (org=%s, version=%d): %w", orgID, keyVersion, err)
	}

	return cm.Decrypt(ciphertextB64, dek, connectorID)
}
