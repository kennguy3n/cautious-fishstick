package pam

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/credentials"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// RawBytesAESGCMEncryptor is the production CredentialEncryptor for
// the PAM module. It seals raw credential bytes (passwords,
// PEM-encoded SSH keys, base64 tokens, x509 certificates, ...) at
// the bytes layer by routing through the audited
// internal/pkg/credentials AES-256-GCM primitive. Like the access
// connector AESGCMEncryptor it binds an AAD (the pam_secrets ULID)
// so ciphertext cannot be copy-pasted between rows; unlike that
// adapter it does NOT JSON-marshal the plaintext on encrypt or
// JSON-unmarshal on decrypt, since PAM secrets are not JSON maps.
//
// Both encryptors load their DEK from the same env var
// (ACCESS_CREDENTIAL_DEK) so a single static key seals every
// connector and PAM secret in this deployment. The KMS-backed
// follow-up will swap this for a per-org KeyManager that returns
// the right DEK for the request context; until then this adapter
// ships a security floor that prevents PAM credentials from being
// readable in plaintext from pam_secrets.ciphertext.
type RawBytesAESGCMEncryptor struct {
	cm  *credentials.CredentialManager
	dek []byte
}

// rawBytesDEKEnvVar is the env var the binary reads the static DEK
// from. Shared with internal/services/access/aesgcm_encryptor.go on
// purpose: operators provision one DEK that seals both the
// connector and PAM secret tables.
const rawBytesDEKEnvVar = "ACCESS_CREDENTIAL_DEK"

// rawBytesDEKSize is the required DEK length in bytes (AES-256).
// Anything shorter or longer is rejected at boot so a typo in the
// env var cannot silently downgrade encryption.
const rawBytesDEKSize = 32

// rawBytesStaticKeyVersion is the key-version stamp written
// alongside every ciphertext in this boot mode. Only one DEK is
// loaded so the version is always "1"; matches the connector
// adapter so callers cannot tell the two encryptors apart at the
// keyVersion layer.
const rawBytesStaticKeyVersion = "1"

// NewRawBytesAESGCMEncryptor constructs an adapter from a 32-byte
// raw DEK. dek must be exactly rawBytesDEKSize bytes; the
// constructor rejects any other length so misconfiguration fails
// loudly at boot.
func NewRawBytesAESGCMEncryptor(dek []byte) (*RawBytesAESGCMEncryptor, error) {
	if len(dek) != rawBytesDEKSize {
		return nil, fmt.Errorf("pam: raw-bytes AES-GCM encryptor DEK must be %d bytes (got %d)", rawBytesDEKSize, len(dek))
	}
	// CredentialManager's bytes-layer EncryptBytes / DecryptBytes
	// entry points do not consult the KeyManager — we pass nil
	// here and feed the DEK in directly on every call. The
	// KeyManager slot is reserved for the KMS-backed follow-up.
	cm := credentials.NewCredentialManager(nil)
	out := make([]byte, len(dek))
	copy(out, dek)
	return &RawBytesAESGCMEncryptor{cm: cm, dek: out}, nil
}

// LoadRawBytesAESGCMEncryptorFromEnv reads a base64-encoded
// 32-byte DEK from ACCESS_CREDENTIAL_DEK and returns a configured
// encryptor. Mirrors access.LoadAESGCMEncryptorFromEnv so the
// binary can wire both encryptors from the same env var.
//
//   - (encryptor, nil) when the env var is set and decodes to a
//     valid 32-byte DEK — the binary should wire the encryptor.
//   - (nil, nil) when the env var is unset — the caller decides
//     between falling back to access.PassthroughEncryptor (with a
//     loud warning) or refusing to boot.
//   - (nil, err) when the env var is set but the value is
//     malformed — the binary must refuse to boot rather than
//     silently fall back to plaintext.
func LoadRawBytesAESGCMEncryptorFromEnv() (*RawBytesAESGCMEncryptor, error) {
	raw := os.Getenv(rawBytesDEKEnvVar)
	if raw == "" {
		return nil, nil
	}
	dek, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("pam: decode %s: %w", rawBytesDEKEnvVar, err)
	}
	return NewRawBytesAESGCMEncryptor(dek)
}

// Encrypt seals plaintext under the adapter's DEK with aad bound
// as Additional Authenticated Data. The returned ciphertext bytes
// are the base64-encoded, nonce-prefixed sealed payload — exactly
// the format Decrypt expects to read back, and the same shape the
// connector adapter writes.
//
// The aad must be non-empty (the pam_secrets ULID); an empty aad
// would let ciphertext be copy-pasted between rows.
func (e *RawBytesAESGCMEncryptor) Encrypt(plaintext []byte, aad []byte) ([]byte, string, error) {
	if e == nil {
		return nil, "", fmt.Errorf("pam: raw-bytes aes-gcm encryptor is nil")
	}
	if len(aad) == 0 {
		return nil, "", fmt.Errorf("pam: raw-bytes aes-gcm: aad required")
	}
	sealed, err := e.cm.EncryptBytes(plaintext, e.dek, string(aad))
	if err != nil {
		return nil, "", fmt.Errorf("pam: raw-bytes aes-gcm: encrypt: %w", err)
	}
	return []byte(sealed), rawBytesStaticKeyVersion, nil
}

// Decrypt opens ciphertext under the adapter's DEK with aad as
// AAD and returns the plaintext bytes verbatim. keyVersion is
// accepted for interface conformance but ignored in this boot
// mode — only one DEK is loaded, so any persisted key-version
// stamp must resolve to it. The KMS follow-up will branch here to
// pick the right DEK from the KeyManager.
func (e *RawBytesAESGCMEncryptor) Decrypt(ciphertext []byte, aad []byte, keyVersion string) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("pam: raw-bytes aes-gcm encryptor is nil")
	}
	if len(aad) == 0 {
		return nil, fmt.Errorf("pam: raw-bytes aes-gcm: aad required")
	}
	plaintext, err := e.cm.DecryptBytes(string(ciphertext), e.dek, string(aad))
	if err != nil {
		return nil, fmt.Errorf("pam: raw-bytes aes-gcm: decrypt: %w", err)
	}
	return plaintext, nil
}

// Compile-time assertion that RawBytesAESGCMEncryptor satisfies the
// access.CredentialEncryptor contract the SecretBrokerService
// consumes. If the access package signature drifts the build
// breaks here instead of at the call site.
var _ access.CredentialEncryptor = (*RawBytesAESGCMEncryptor)(nil)
