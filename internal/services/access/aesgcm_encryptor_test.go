package access

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// freshDEK returns a random 32-byte DEK for tests. Using a real
// random key instead of an all-zeros constant catches accidental
// short-circuits like "decrypt always returns the plaintext bytes
// passed in" because nothing in the test apparatus has the key
// material to forge a valid AES-GCM ciphertext.
func freshDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, aesGCMDEKSize)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return dek
}

// TestNewAESGCMEncryptor_RejectsWrongDEKSize is the boot-time
// guard: a typo in ACCESS_CREDENTIAL_DEK that produces a short or
// long key must surface as an error so the binary refuses to boot
// instead of silently downgrading encryption.
func TestNewAESGCMEncryptor_RejectsWrongDEKSize(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{"empty", 0},
		{"too short", aesGCMDEKSize - 1},
		{"too long", aesGCMDEKSize + 1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dek := make([]byte, tc.size)
			enc, err := NewAESGCMEncryptor(dek)
			if err == nil {
				t.Fatalf("NewAESGCMEncryptor(%d bytes): err = nil; want non-nil error", tc.size)
			}
			if enc != nil {
				t.Errorf("NewAESGCMEncryptor(%d bytes): enc != nil; want nil so callers cannot accidentally use the partial constructor", tc.size)
			}
			if !strings.Contains(err.Error(), "32 bytes") {
				t.Errorf("err = %q; want to mention the required key size so operators can debug", err.Error())
			}
		})
	}
}

// TestAESGCMEncryptor_RoundTrip_RestoresPlaintext is the happy
// path: a secrets map sealed with the adapter must decrypt to the
// same map when fed back to the adapter with the same AAD. This
// is the contract ConnectorManagementService.Connect and
// DefaultLoadConnector rely on.
func TestAESGCMEncryptor_RoundTrip_RestoresPlaintext(t *testing.T) {
	enc, err := NewAESGCMEncryptor(freshDEK(t))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	secrets := map[string]interface{}{
		"api_token":    "tok-123",
		"refresh_token": "ref-456",
	}
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	aad := []byte("conn_01HXXXXXXXXXXXXXXXXXXXXXXX")

	ciphertext, kv, err := enc.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if kv != staticDEKKeyVersion {
		t.Errorf("keyVersion = %q; want %q", kv, staticDEKKeyVersion)
	}
	if string(ciphertext) == string(plaintext) {
		t.Fatal("ciphertext == plaintext; encryptor returned the plaintext verbatim instead of sealing it")
	}

	roundTrip, err := enc.Decrypt(ciphertext, aad, kv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(roundTrip, &got); err != nil {
		t.Fatalf("Unmarshal round-trip: %v", err)
	}
	if got["api_token"] != "tok-123" || got["refresh_token"] != "ref-456" {
		t.Errorf("round-trip secrets = %v; want %v", got, secrets)
	}
}

// TestAESGCMEncryptor_DifferentCiphertextOnSamePlaintext asserts
// the GCM nonce is random per call — two encryptions of the same
// plaintext under the same AAD must produce different ciphertexts
// or an attacker watching the access_connectors table could
// detect when two rows share the same secret material.
func TestAESGCMEncryptor_DifferentCiphertextOnSamePlaintext(t *testing.T) {
	enc, err := NewAESGCMEncryptor(freshDEK(t))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	plaintext := []byte(`{"token":"same"}`)
	aad := []byte("conn-aad")

	c1, _, err := enc.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	c2, _, err := enc.Encrypt(plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if string(c1) == string(c2) {
		t.Fatal("identical ciphertexts on repeated Encrypt; GCM nonce must be random per call to avoid leaking equality of secret material")
	}
}

// TestAESGCMEncryptor_AADBinding asserts the AAD (the connector
// ULID) is bound into the AES-GCM tag: ciphertext sealed under
// one connector ID must NOT open under a different connector ID,
// preventing copy-paste of credentials between rows.
func TestAESGCMEncryptor_AADBinding(t *testing.T) {
	enc, err := NewAESGCMEncryptor(freshDEK(t))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	plaintext := []byte(`{"token":"abc"}`)
	ciphertext, kv, err := enc.Encrypt(plaintext, []byte("connectorA"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := enc.Decrypt(ciphertext, []byte("connectorB"), kv); err == nil {
		t.Fatal("Decrypt with wrong AAD: err = nil; want non-nil (AAD must be bound into the GCM tag)")
	}
}

// TestAESGCMEncryptor_RejectsEmptyAAD enforces the contract that
// AAD is required. Without this guard, callers that forgot to
// pass the connector ULID would still get a valid (but
// unbindable) ciphertext back, defeating the AAD pivot.
func TestAESGCMEncryptor_RejectsEmptyAAD(t *testing.T) {
	enc, err := NewAESGCMEncryptor(freshDEK(t))
	if err != nil {
		t.Fatalf("NewAESGCMEncryptor: %v", err)
	}
	if _, _, err := enc.Encrypt([]byte(`{"t":"v"}`), nil); err == nil {
		t.Error("Encrypt with empty AAD: err = nil; want non-nil")
	}
	if _, err := enc.Decrypt([]byte("ignored"), nil, "1"); err == nil {
		t.Error("Decrypt with empty AAD: err = nil; want non-nil")
	}
}

// TestLoadAESGCMEncryptorFromEnv covers the boot-time branch
// matrix. The three observable outcomes a binary's main() needs
// to distinguish are:
//
//  1. env unset → (nil, nil) → main wires PassthroughEncryptor with a warning.
//  2. env set + valid → (enc, nil) → main wires AES-GCM.
//  3. env set + malformed → (nil, err) → main log.Fatalfs and refuses to boot.
func TestLoadAESGCMEncryptorFromEnv(t *testing.T) {
	t.Run("unset returns nil,nil for passthrough fallback", func(t *testing.T) {
		t.Setenv(dekEnvVar, "")
		enc, err := LoadAESGCMEncryptorFromEnv()
		if err != nil {
			t.Fatalf("err = %v; want nil so main() can fall back to PassthroughEncryptor", err)
		}
		if enc != nil {
			t.Fatalf("enc = %v; want nil to signal the unset branch", enc)
		}
	})

	t.Run("valid base64 32-byte key returns encryptor", func(t *testing.T) {
		dek := freshDEK(t)
		t.Setenv(dekEnvVar, base64.StdEncoding.EncodeToString(dek))
		enc, err := LoadAESGCMEncryptorFromEnv()
		if err != nil {
			t.Fatalf("err = %v; want nil for a valid key", err)
		}
		if enc == nil {
			t.Fatal("enc = nil; want a real encryptor")
		}
	})

	t.Run("malformed base64 returns error", func(t *testing.T) {
		t.Setenv(dekEnvVar, "not-base64-!!!")
		enc, err := LoadAESGCMEncryptorFromEnv()
		if err == nil {
			t.Fatal("err = nil; want non-nil so main() log.Fatalfs instead of silently falling back to plaintext")
		}
		if enc != nil {
			t.Errorf("enc = %v; want nil on malformed input", enc)
		}
	})

	t.Run("valid base64 but wrong length returns error", func(t *testing.T) {
		short := make([]byte, 16) // valid base64, but only 16 bytes (AES-128)
		t.Setenv(dekEnvVar, base64.StdEncoding.EncodeToString(short))
		enc, err := LoadAESGCMEncryptorFromEnv()
		if err == nil {
			t.Fatal("err = nil; want non-nil so a 16-byte key cannot silently downgrade AES-256 to AES-128")
		}
		if enc != nil {
			t.Errorf("enc = %v; want nil on wrong-length input", enc)
		}
	})

	t.Run("explicitly unsetting env mirrors the unset branch", func(t *testing.T) {
		// Belt-and-braces: confirm the unset detection is
		// driven by "" (the empty-env semantics) rather than
		// any package-state cache.
		if err := os.Unsetenv(dekEnvVar); err != nil {
			t.Fatalf("Unsetenv: %v", err)
		}
		enc, err := LoadAESGCMEncryptorFromEnv()
		if err != nil {
			t.Fatalf("err = %v; want nil", err)
		}
		if enc != nil {
			t.Fatalf("enc = %v; want nil", enc)
		}
	})
}
