package access

import (
	"encoding/json"
	"fmt"
)

// CredentialEncryptor is the narrow contract
// ConnectorManagementService uses to seal connector secrets before
// persisting them in access_connectors.credentials. The production
// implementation wraps internal/pkg/credentials.CredentialManager
// (AES-GCM under a per-org DEK with the connector ULID bound as
// Additional Authenticated Data); tests substitute a
// PassthroughEncryptor that returns plaintext unmodified.
//
// The interface is intentionally small so the service layer never
// imports the credentials package directly — cmd/ztna-api wires
// the production encryptor in at boot, and the service layer stays
// free of crypto primitives.
//
// aad is the access_connectors.ID; binding the ULID prevents
// ciphertext from being copy-pasted between rows. keyVersion is
// returned by Encrypt so the caller can persist it alongside the
// ciphertext for future Decrypt lookups across DEK rotations.
type CredentialEncryptor interface {
	Encrypt(plaintext []byte, aad []byte) (ciphertext []byte, keyVersion string, err error)
	Decrypt(ciphertext []byte, aad []byte, keyVersion string) (plaintext []byte, err error)
}

// PassthroughEncryptor is the test-only CredentialEncryptor that
// returns plaintext verbatim. It is NOT a mock — the type implements
// the real interface contract; its semantics happen to be the
// identity function so seed data can be inserted as plaintext JSON
// and read back through the same DefaultLoadConnector decrypt hook
// production uses.
//
// Production wires an AES-GCM encryptor; tests wire
// PassthroughEncryptor{}. Both go through the same call site, so
// the test exercises the real code path end-to-end.
type PassthroughEncryptor struct{}

// Encrypt returns plaintext unmodified and keyVersion="0".
func (PassthroughEncryptor) Encrypt(plaintext []byte, aad []byte) ([]byte, string, error) {
	if len(aad) == 0 {
		return nil, "", fmt.Errorf("credential_encryptor: aad is required")
	}
	// Defensive copy so callers cannot mutate our returned buffer
	// after the fact.
	out := make([]byte, len(plaintext))
	copy(out, plaintext)
	return out, "0", nil
}

// Decrypt returns ciphertext unmodified. keyVersion is ignored.
func (PassthroughEncryptor) Decrypt(ciphertext []byte, aad []byte, keyVersion string) ([]byte, error) {
	if len(aad) == 0 {
		return nil, fmt.Errorf("credential_encryptor: aad is required")
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	return out, nil
}

// encryptSecretsMap marshals secrets to JSON and seals them via the
// supplied encryptor, returning the ciphertext + keyVersion pair to
// persist alongside the access_connectors row.
func encryptSecretsMap(enc CredentialEncryptor, secrets map[string]interface{}, aad string) (string, string, error) {
	if enc == nil {
		return "", "", fmt.Errorf("credential_encryptor: encryptor is required")
	}
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return "", "", fmt.Errorf("credential_encryptor: marshal secrets: %w", err)
	}
	ciphertext, kv, err := enc.Encrypt(plaintext, []byte(aad))
	if err != nil {
		return "", "", fmt.Errorf("credential_encryptor: encrypt: %w", err)
	}
	return string(ciphertext), kv, nil
}
