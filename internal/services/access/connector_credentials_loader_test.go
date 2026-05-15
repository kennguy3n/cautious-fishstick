package access

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

func newLoaderTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("automigrate access_connectors: %v", err)
	}
	return db
}

// TestLoadConnectorCredentials_NilLoader verifies that calling
// LoadConnectorCredentials on a nil *ConnectorCredentialsLoader
// surfaces ErrValidation rather than panicking. Production wiring
// has the loader always set, but defensive tests guarantee the
// nil receiver path is not a crash bug.
func TestLoadConnectorCredentials_NilLoader(t *testing.T) {
	var loader *ConnectorCredentialsLoader
	_, _, err := loader.LoadConnectorCredentials(context.Background(), "01HCONN00")
	if err == nil {
		t.Fatal("nil loader = nil err; want ErrValidation")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want wraps ErrValidation", err)
	}
}

// TestLoadConnectorCredentials_NilDB verifies that a loader with
// a nil db field is detected at LoadConnectorCredentials time and
// surfaces ErrValidation.
func TestLoadConnectorCredentials_NilDB(t *testing.T) {
	loader := NewConnectorCredentialsLoader(nil, PassthroughEncryptor{})
	_, _, err := loader.LoadConnectorCredentials(context.Background(), "01HCONN00")
	if err == nil {
		t.Fatal("nil db = nil err; want ErrValidation")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want wraps ErrValidation", err)
	}
}

// TestLoadConnectorCredentials_NilEncryptor verifies that a loader
// constructed with a nil encryptor surfaces ErrValidation rather
// than panicking inside decodeConnectorCredentials.
func TestLoadConnectorCredentials_NilEncryptor(t *testing.T) {
	db := newLoaderTestDB(t)
	loader := NewConnectorCredentialsLoader(db, nil)
	_, _, err := loader.LoadConnectorCredentials(context.Background(), "01HCONN00")
	if err == nil {
		t.Fatal("nil encryptor = nil err; want ErrValidation")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want wraps ErrValidation", err)
	}
}

// TestLoadConnectorCredentials_BlankConnectorID asserts the
// loader rejects the empty connectorID up-front rather than
// issuing a wildcard SELECT against access_connectors.
func TestLoadConnectorCredentials_BlankConnectorID(t *testing.T) {
	db := newLoaderTestDB(t)
	loader := NewConnectorCredentialsLoader(db, PassthroughEncryptor{})
	_, _, err := loader.LoadConnectorCredentials(context.Background(), "")
	if err == nil {
		t.Fatal("blank id = nil err; want ErrValidation")
	}
	if !errors.Is(err, ErrValidation) {
		t.Errorf("err = %v; want wraps ErrValidation", err)
	}
}

// TestLoadConnectorCredentials_MissingRow verifies that asking
// the loader for a connector ID with no corresponding
// access_connectors row surfaces ErrConnectorRowNotFound.
func TestLoadConnectorCredentials_MissingRow(t *testing.T) {
	db := newLoaderTestDB(t)
	loader := NewConnectorCredentialsLoader(db, PassthroughEncryptor{})
	_, _, err := loader.LoadConnectorCredentials(context.Background(), "01HCONNMISSING000000000001")
	if err == nil {
		t.Fatal("missing row = nil err; want ErrConnectorRowNotFound")
	}
	if !errors.Is(err, ErrConnectorRowNotFound) {
		t.Errorf("err = %v; want wraps ErrConnectorRowNotFound", err)
	}
}

// erroringEncryptor returns a fixed Decrypt error to drive the
// decrypt-failure path of LoadConnectorCredentials.
type erroringEncryptor struct{}

func (erroringEncryptor) Encrypt(plaintext []byte, _ []byte) ([]byte, string, error) {
	return plaintext, "0", nil
}
func (erroringEncryptor) Decrypt(_ []byte, _ []byte, _ string) ([]byte, error) {
	return nil, errors.New("aes-gcm: tag mismatch")
}

// TestLoadConnectorCredentials_DecryptFailure asserts that when the
// AES-GCM unwrap fails (e.g. tampered ciphertext, mismatched DEK
// version), LoadConnectorCredentials surfaces a wrapped error.
func TestLoadConnectorCredentials_DecryptFailure(t *testing.T) {
	db := newLoaderTestDB(t)
	const id = "01HCONNDECRYPTFAIL00000001"
	if err := db.Create(&models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "test_provider",
		ConnectorType: "test",
		Status:        models.StatusConnected,
		Credentials:   "garbage",
		KeyVersion:    1,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	loader := NewConnectorCredentialsLoader(db, erroringEncryptor{})
	_, _, err := loader.LoadConnectorCredentials(context.Background(), id)
	if err == nil {
		t.Fatal("decrypt failure = nil err; want wrapped decrypt error")
	}
	if !strings.Contains(err.Error(), "tag mismatch") {
		t.Errorf("err = %v; want to contain 'tag mismatch'", err)
	}
}

// TestLoadConnectorCredentials_HappyPath_Passthrough wires the
// loader with a PassthroughEncryptor (the same test-only encryptor
// production tests use) and asserts the round-trip Config +
// Secrets decodes are surfaced verbatim.
func TestLoadConnectorCredentials_HappyPath_Passthrough(t *testing.T) {
	db := newLoaderTestDB(t)
	const id = "01HCONNHAPPY00000000000001"
	cipher, kv, err := encryptSecretsMap(PassthroughEncryptor{}, map[string]interface{}{
		"client_id":     "id-1",
		"client_secret": "secret-2",
	}, id)
	if err != nil {
		t.Fatalf("encryptSecretsMap: %v", err)
	}
	// kv is the string-encoded key version returned by the
	// encryptor (PassthroughEncryptor returns "0"). strconv.Atoi
	// keeps the parse honest — a non-numeric kv would error here
	// instead of being silently coerced to 0.
	kvInt, err := strconv.Atoi(kv)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", kv, err)
	}
	if err := db.Create(&models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "test_provider",
		ConnectorType: "test",
		Status:        models.StatusConnected,
		Config:        []byte(`{"region":"us-east-1","tenant":"acme"}`),
		Credentials:   cipher,
		KeyVersion:    kvInt,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	loader := NewConnectorCredentialsLoader(db, PassthroughEncryptor{})
	cfg, secrets, err := loader.LoadConnectorCredentials(context.Background(), id)
	if err != nil {
		t.Fatalf("LoadConnectorCredentials: %v", err)
	}
	if cfg["region"] != "us-east-1" || cfg["tenant"] != "acme" {
		t.Errorf("cfg = %+v; want region=us-east-1 tenant=acme", cfg)
	}
	if secrets["client_id"] != "id-1" || secrets["client_secret"] != "secret-2" {
		t.Errorf("secrets = %+v; want client_id=id-1 client_secret=secret-2", secrets)
	}
}

// TestLoadConnectorCredentials_HappyPath_NoCredentials verifies
// that a connector row with an empty Credentials column returns
// an empty secrets map (not a nil map and not an error) so callers
// can drive connectors that do not encrypt anything.
func TestLoadConnectorCredentials_HappyPath_NoCredentials(t *testing.T) {
	db := newLoaderTestDB(t)
	const id = "01HCONNNOCREDS00000000001A"
	if err := db.Create(&models.AccessConnector{
		ID:            id,
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "test_provider",
		ConnectorType: "test",
		Status:        models.StatusConnected,
		Config:        []byte(`{}`),
		Credentials:   "",
		KeyVersion:    0,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	loader := NewConnectorCredentialsLoader(db, PassthroughEncryptor{})
	cfg, secrets, err := loader.LoadConnectorCredentials(context.Background(), id)
	if err != nil {
		t.Fatalf("LoadConnectorCredentials: %v", err)
	}
	if cfg == nil || secrets == nil {
		t.Fatalf("cfg=%v secrets=%v; want non-nil empty maps", cfg, secrets)
	}
	if len(cfg) != 0 || len(secrets) != 0 {
		t.Errorf("cfg=%+v secrets=%+v; want empty maps", cfg, secrets)
	}
}
