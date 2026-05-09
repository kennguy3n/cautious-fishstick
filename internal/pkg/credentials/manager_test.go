package credentials

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

func newTestDEK(t *testing.T) []byte {
	t.Helper()
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("read random DEK: %v", err)
	}
	return dek
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	cm := NewCredentialManager(nil)
	dek := newTestDEK(t)
	aad := "01HXYZ0000000000000000ABCD"

	secrets := map[string]interface{}{
		"client_secret": "shh-do-not-log-me",
		"api_token":     "tok_abcdef",
		"scopes":        []interface{}{"User.Read.All", "Group.Read.All"},
	}

	ciphertext, err := cm.Encrypt(secrets, dek, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == "" {
		t.Fatal("Encrypt returned empty ciphertext")
	}

	got, err := cm.Decrypt(ciphertext, dek, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got["client_secret"] != "shh-do-not-log-me" {
		t.Fatalf("Decrypt round-trip mismatch: %v", got)
	}
	if got["api_token"] != "tok_abcdef" {
		t.Fatalf("Decrypt round-trip mismatch: %v", got)
	}
}

func TestEncrypt_CiphertextIsNotPlaintext(t *testing.T) {
	cm := NewCredentialManager(nil)
	dek := newTestDEK(t)
	aad := "01HXYZ0000000000000000ABCD"

	secrets := map[string]interface{}{
		"client_secret": "marker_should_not_appear_in_ciphertext",
	}

	ciphertext, err := cm.Encrypt(secrets, dek, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if strings.Contains(ciphertext, "marker_should_not_appear_in_ciphertext") {
		t.Fatal("ciphertext leaks plaintext substring")
	}
}

func TestDecrypt_WrongAAD_Fails(t *testing.T) {
	cm := NewCredentialManager(nil)
	dek := newTestDEK(t)
	aad := "01HXYZ0000000000000000ABCD"

	ciphertext, err := cm.Encrypt(map[string]interface{}{"k": "v"}, dek, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := cm.Decrypt(ciphertext, dek, "01HABC9999999999999999XXXX"); err == nil {
		t.Fatal("Decrypt with wrong AAD: expected error, got nil")
	}
}

func TestDecrypt_WrongDEK_Fails(t *testing.T) {
	cm := NewCredentialManager(nil)
	dek := newTestDEK(t)
	otherDEK := newTestDEK(t)
	aad := "01HXYZ0000000000000000ABCD"

	ciphertext, err := cm.Encrypt(map[string]interface{}{"k": "v"}, dek, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := cm.Decrypt(ciphertext, otherDEK, aad); err == nil {
		t.Fatal("Decrypt with wrong DEK: expected error, got nil")
	}
}

func TestEncrypt_RejectsBadDEKAndAAD(t *testing.T) {
	cm := NewCredentialManager(nil)

	if _, err := cm.Encrypt(map[string]interface{}{"k": "v"}, []byte("short"), "aad"); !errors.Is(err, ErrInvalidDEK) {
		t.Fatalf("Encrypt with short DEK: got %v, want ErrInvalidDEK", err)
	}
	if _, err := cm.Encrypt(map[string]interface{}{"k": "v"}, newTestDEK(t), ""); !errors.Is(err, ErrEmptyAAD) {
		t.Fatalf("Encrypt with empty AAD: got %v, want ErrEmptyAAD", err)
	}
}

func TestDecrypt_RejectsBadDEKAndAAD(t *testing.T) {
	cm := NewCredentialManager(nil)

	if _, err := cm.Decrypt("aGVsbG8=", []byte("short"), "aad"); !errors.Is(err, ErrInvalidDEK) {
		t.Fatalf("Decrypt with short DEK: got %v, want ErrInvalidDEK", err)
	}
	if _, err := cm.Decrypt("aGVsbG8=", newTestDEK(t), ""); !errors.Is(err, ErrEmptyAAD) {
		t.Fatalf("Decrypt with empty AAD: got %v, want ErrEmptyAAD", err)
	}
}

// stubKeyManager implements KeyManager for unit tests.
type stubKeyManager struct {
	dek      []byte
	version  int
	getErr   error
	latestErr error
}

func (s *stubKeyManager) GetLatestOrgDEK(_ context.Context, _ string) ([]byte, int, error) {
	if s.latestErr != nil {
		return nil, 0, s.latestErr
	}
	return s.dek, s.version, nil
}

func (s *stubKeyManager) GetOrgDEK(_ context.Context, _ string, _ int) ([]byte, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.dek, nil
}

func TestGetCredentials_HappyPath(t *testing.T) {
	dek := newTestDEK(t)
	cm := NewCredentialManager(&stubKeyManager{dek: dek, version: 1})

	connectorID := "01HXYZ0000000000000000ABCD"
	ciphertext, err := cm.Encrypt(map[string]interface{}{"api_token": "abc"}, dek, connectorID)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := cm.GetCredentials(context.Background(), connectorID, "org-1", 1, ciphertext)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	if got["api_token"] != "abc" {
		t.Fatalf("GetCredentials returned wrong payload: %v", got)
	}
}

func TestGetCredentials_RejectsEmptyInputs(t *testing.T) {
	cm := NewCredentialManager(&stubKeyManager{})

	if _, err := cm.GetCredentials(context.Background(), "", "org", 1, "ciphertext"); err == nil {
		t.Fatal("GetCredentials with empty connectorID: expected error")
	}
	if _, err := cm.GetCredentials(context.Background(), "id", "org", 1, ""); !errors.Is(err, ErrEmptyCiphertext) {
		t.Fatalf("GetCredentials with empty ciphertext: got %v, want ErrEmptyCiphertext", err)
	}

	cmNoKM := NewCredentialManager(nil)
	if _, err := cmNoKM.GetCredentials(context.Background(), "id", "org", 1, "ciphertext"); err == nil {
		t.Fatal("GetCredentials without KeyManager: expected error")
	}
}
