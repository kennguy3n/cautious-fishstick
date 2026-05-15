package access

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kennguy3n/cautious-fishstick/internal/pkg/credentials"
)

// AESGCMEncryptor is the production CredentialEncryptor. It seals
// connector secrets at the bytes layer by routing through the
// internal/pkg/credentials CredentialManager — which is AES-256-GCM
// with the access connector ULID bound as Additional Authenticated
// Data. The DEK is loaded once at boot from a base64 env var and
// held in memory for the lifetime of the process.
//
// The CredentialEncryptor interface deals in bytes (the calling
// service encryptSecretsMap helper has already JSON-marshalled the
// secrets map by the time we receive it); CredentialManager.Encrypt
// only knows how to seal a map[string]interface{}. The adapter
// resolves the impedance by unmarshalling the supplied plaintext
// bytes back into a map and then handing it to the manager. The
// double-encode/decode pass is the price of routing through the
// audited primitive instead of re-implementing AES-GCM here.
//
// Adapter scope: a single static DEK loaded from
// ACCESS_CREDENTIAL_DEK. Production deployments will eventually
// swap this for a KMS-backed KeyManager that returns per-org DEKs
// keyed off the request context; that lands in a follow-up. Until
// then this adapter ships a security floor that prevents
// connector credentials from being readable in plaintext from
// access_connectors.credentials.
type AESGCMEncryptor struct {
	cm  *credentials.CredentialManager
	dek []byte
}

// dekEnvVar is the env var the binary reads the static DEK from.
// The value is base64-encoded — 32 bytes of raw entropy expand
// to 44 base64 characters. Operators generate the key via e.g.
// `openssl rand -base64 32`.
const dekEnvVar = "ACCESS_CREDENTIAL_DEK"

// staticDEKKeyVersion is the key-version stamp written alongside
// every ciphertext in this boot mode. Only one DEK is loaded so
// the version is always "1"; the KMS-backed follow-up will
// increment this as keys rotate.
const staticDEKKeyVersion = "1"

// aesGCMDEKSize is the required DEK length in bytes (AES-256).
// Anything shorter or longer is rejected at boot so a typo in the
// env var cannot silently downgrade encryption.
const aesGCMDEKSize = 32

// NewAESGCMEncryptor constructs an adapter from a 32-byte raw DEK.
// dek must be exactly aesGCMDEKSize bytes; the constructor rejects
// any other length so misconfiguration fails loudly.
func NewAESGCMEncryptor(dek []byte) (*AESGCMEncryptor, error) {
	if len(dek) != aesGCMDEKSize {
		return nil, fmt.Errorf("access: AES-GCM encryptor DEK must be %d bytes (got %d)", aesGCMDEKSize, len(dek))
	}
	// CredentialManager's bytes-layer Encrypt / Decrypt entry
	// points do not consult the KeyManager — we pass nil here
	// and feed the DEK in directly on every call. The KeyManager
	// slot is reserved for the KMS-backed follow-up.
	cm := credentials.NewCredentialManager(nil)
	out := make([]byte, len(dek))
	copy(out, dek)
	return &AESGCMEncryptor{cm: cm, dek: out}, nil
}

// LoadAESGCMEncryptorFromEnv reads a base64-encoded 32-byte DEK
// from ACCESS_CREDENTIAL_DEK and returns a configured encryptor.
//
//   - (encryptor, nil) when the env var is set and decodes to a
//     valid 32-byte DEK — the binary should wire the encryptor.
//   - (nil, nil) when the env var is unset — the caller decides
//     between falling back to PassthroughEncryptor (with a loud
//     warning) or refusing to boot.
//   - (nil, err) when the env var is set but the value is
//     malformed — the binary must refuse to boot rather than
//     silently fall back to plaintext.
func LoadAESGCMEncryptorFromEnv() (*AESGCMEncryptor, error) {
	raw := os.Getenv(dekEnvVar)
	if raw == "" {
		return nil, nil
	}
	dek, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("access: decode %s: %w", dekEnvVar, err)
	}
	return NewAESGCMEncryptor(dek)
}

// Encrypt seals plaintext (the JSON-marshalled secrets map
// produced by encryptSecretsMap) under the adapter's DEK with aad
// bound as Additional Authenticated Data. The returned ciphertext
// bytes are the base64-encoded, nonce-prefixed sealed payload —
// exactly the format CredentialManager.Decrypt expects to read
// back.
//
// The aad must be non-empty (the connector ULID); an empty aad
// would let ciphertext be copy-pasted between rows.
func (e *AESGCMEncryptor) Encrypt(plaintext []byte, aad []byte) ([]byte, string, error) {
	if e == nil {
		return nil, "", fmt.Errorf("access: aes-gcm encryptor is nil")
	}
	if len(aad) == 0 {
		return nil, "", fmt.Errorf("access: aes-gcm: aad required")
	}
	var secrets map[string]interface{}
	if err := json.Unmarshal(plaintext, &secrets); err != nil {
		return nil, "", fmt.Errorf("access: aes-gcm: unmarshal plaintext: %w", err)
	}
	sealed, err := e.cm.Encrypt(secrets, e.dek, string(aad))
	if err != nil {
		return nil, "", fmt.Errorf("access: aes-gcm: encrypt: %w", err)
	}
	return []byte(sealed), staticDEKKeyVersion, nil
}

// Decrypt opens ciphertext under the adapter's DEK with aad as
// AAD and returns the JSON-encoded plaintext bytes. keyVersion is
// accepted for interface conformance but ignored in this boot
// mode — only one DEK is loaded, so any persisted key-version
// stamp must resolve to it. The KMS follow-up will branch here
// to pick the right DEK from the KeyManager.
func (e *AESGCMEncryptor) Decrypt(ciphertext []byte, aad []byte, keyVersion string) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("access: aes-gcm encryptor is nil")
	}
	if len(aad) == 0 {
		return nil, fmt.Errorf("access: aes-gcm: aad required")
	}
	secrets, err := e.cm.Decrypt(string(ciphertext), e.dek, string(aad))
	if err != nil {
		return nil, fmt.Errorf("access: aes-gcm: decrypt: %w", err)
	}
	out, err := json.Marshal(secrets)
	if err != nil {
		return nil, fmt.Errorf("access: aes-gcm: marshal plaintext: %w", err)
	}
	return out, nil
}
