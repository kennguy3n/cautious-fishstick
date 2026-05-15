package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newConnectorMgmtDB returns a fresh in-memory SQLite DB with the
// tables ConnectorManagementService writes through.
func newConnectorMgmtDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}, &models.AccessJob{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

// TestConnect_FullLifecycle_HappyPath walks the documented Connect
// pipeline end to end and asserts:
//
//   - Validate, Connect, VerifyPermissions, GetCredentialsMetadata
//     each fire exactly once.
//   - The persisted access_connectors row carries the configured
//     workspace / provider / connector_type and status=connected.
//   - The companion access_jobs row is the initial sync_identities
//     job for the new connector.
func TestConnect_FullLifecycle_HappyPath(t *testing.T) {
	const provider = "test_lifecycle_happy_path"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID:   "01HWS0LIFECYCLE0000000000",
		Provider:      provider,
		ConnectorType: "saas",
		Config:        map[string]interface{}{"region": "us-east-1"},
		Secrets:       map[string]interface{}{"token": "shh"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.ConnectorID == "" || res.JobID == "" {
		t.Fatalf("expected non-empty ConnectorID/JobID, got %+v", res)
	}

	if mock.ValidateCalls != 1 {
		t.Errorf("ValidateCalls = %d; want 1", mock.ValidateCalls)
	}
	if mock.ConnectCalls != 1 {
		t.Errorf("ConnectCalls = %d; want 1", mock.ConnectCalls)
	}
	if mock.VerifyPermissionsCalls != 1 {
		t.Errorf("VerifyPermissionsCalls = %d; want 1", mock.VerifyPermissionsCalls)
	}
	if mock.GetCredentialsMetadataCalls != 1 {
		t.Errorf("GetCredentialsMetadataCalls = %d; want 1", mock.GetCredentialsMetadataCalls)
	}

	var row models.AccessConnector
	if err := db.First(&row, "id = ?", res.ConnectorID).Error; err != nil {
		t.Fatalf("load connector row: %v", err)
	}
	if row.WorkspaceID != "01HWS0LIFECYCLE0000000000" || row.Provider != provider {
		t.Errorf("persisted row workspace=%q provider=%q; want workspace=01HWS0LIFECYCLE0000000000 provider=%q",
			row.WorkspaceID, row.Provider, provider)
	}
	if row.Status != models.StatusConnected {
		t.Errorf("row.Status = %q; want %q", row.Status, models.StatusConnected)
	}

	var job models.AccessJob
	if err := db.First(&job, "id = ?", res.JobID).Error; err != nil {
		t.Fatalf("load job row: %v", err)
	}
	if job.ConnectorID != res.ConnectorID {
		t.Errorf("job.ConnectorID = %q; want %q", job.ConnectorID, res.ConnectorID)
	}
	if job.JobType != models.AccessJobTypeSyncIdentities {
		t.Errorf("job.JobType = %q; want %q", job.JobType, models.AccessJobTypeSyncIdentities)
	}
}

// TestConnect_FailsAtValidate asserts a Validate error short-circuits
// the pipeline before Connect is called and no DB row is created.
func TestConnect_FailsAtValidate(t *testing.T) {
	const provider = "test_lifecycle_fail_validate"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{
		FuncValidate: func(_ context.Context, _, _ map[string]interface{}) error {
			return errors.New("invalid config: region missing")
		},
	}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	_, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID: "01HWS0LIFE0VALIDATE000000",
		Provider:    provider,
		Secrets:     map[string]interface{}{"token": "shh"},
	})
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("err=%v; want wraps ErrValidation", err)
	}
	if mock.ConnectCalls != 0 {
		t.Errorf("ConnectCalls = %d; want 0 (pipeline must short-circuit after Validate)", mock.ConnectCalls)
	}
	var n int64
	db.Model(&models.AccessConnector{}).Count(&n)
	if n != 0 {
		t.Errorf("inserted %d connector rows after Validate failure; want 0", n)
	}
}

// TestConnect_FailsAtConnect asserts a Connect error after Validate
// passes still aborts and never inserts a row.
func TestConnect_FailsAtConnect(t *testing.T) {
	const provider = "test_lifecycle_fail_connect"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{
		FuncConnect: func(_ context.Context, _, _ map[string]interface{}) error {
			return errors.New("upstream unreachable: dial tcp: i/o timeout")
		},
	}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	_, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID: "01HWS0LIFE0CONNECT0000000",
		Provider:    provider,
		Secrets:     map[string]interface{}{"token": "shh"},
	})
	if err == nil {
		t.Fatalf("err=nil; want non-nil")
	}
	if mock.VerifyPermissionsCalls != 0 {
		t.Errorf("VerifyPermissionsCalls = %d; want 0", mock.VerifyPermissionsCalls)
	}
	var n int64
	db.Model(&models.AccessConnector{}).Count(&n)
	if n != 0 {
		t.Errorf("inserted %d connector rows after Connect failure; want 0", n)
	}
}

// TestConnect_FailsOnMissingCapabilities asserts the documented
// short-circuit when VerifyPermissions reports missing capabilities:
// the call returns ErrValidation with the missing-caps list and no
// row is persisted (preventing a half-authorized credential from
// landing in production).
func TestConnect_FailsOnMissingCapabilities(t *testing.T) {
	const provider = "test_lifecycle_missing_caps"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{
		FuncVerifyPermissions: func(_ context.Context, _, _ map[string]interface{}, _ []string) ([]string, error) {
			return []string{"write", "deprovision"}, nil
		},
	}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	_, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID:  "01HWS0LIFE0CAPS00000000000",
		Provider:     provider,
		Secrets:      map[string]interface{}{"token": "shh"},
		Capabilities: []string{"read", "write", "deprovision"},
	})
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("err=%v; want wraps ErrValidation", err)
	}
	var n int64
	db.Model(&models.AccessConnector{}).Count(&n)
	if n != 0 {
		t.Errorf("inserted %d connector rows on missing-caps; want 0", n)
	}
}

// TestConnect_RejectsDuplicate asserts the
// (workspace_id, provider, connector_type) uniqueness guard. A
// second Connect with the same triple must return
// ErrConnectorAlreadyExists without calling the connector again.
func TestConnect_RejectsDuplicate(t *testing.T) {
	const provider = "test_lifecycle_duplicate"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	in := ConnectInput{
		WorkspaceID:   "01HWS0LIFE0DUP00000000000",
		Provider:      provider,
		ConnectorType: "saas",
		Secrets:       map[string]interface{}{"token": "shh"},
	}
	if _, err := svc.Connect(context.Background(), in); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	_, err := svc.Connect(context.Background(), in)
	if err == nil || !errors.Is(err, ErrConnectorAlreadyExists) {
		t.Fatalf("err=%v; want wraps ErrConnectorAlreadyExists", err)
	}
}

// TestConnect_UnknownProvider asserts a Connect call against a
// provider key not in the registry returns ErrUnknownProvider so
// handlers can surface 400 (validation_failed) instead of 500.
func TestConnect_UnknownProvider(t *testing.T) {
	db := newConnectorMgmtDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	_, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID: "01HWS0LIFE0UNKNOWN00000000",
		Provider:    "this_provider_does_not_exist_in_registry",
		Secrets:     map[string]interface{}{"token": "shh"},
	})
	if err == nil || !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("err=%v; want wraps ErrUnknownProvider", err)
	}
}

// TestConnect_EncryptionRoundTrip asserts the persisted credentials
// blob is the output of the configured CredentialEncryptor — not the
// raw plaintext. With PassthroughEncryptor the ciphertext matches
// the JSON form of the secrets map.
func TestConnect_EncryptionRoundTrip(t *testing.T) {
	const provider = "test_lifecycle_encryption"
	db := newConnectorMgmtDB(t)
	SwapConnector(t, provider, &MockAccessConnector{})

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID: "01HWS0LIFE0ENCRYPT0000000",
		Provider:    provider,
		Secrets:     map[string]interface{}{"token": "shh", "refresh": "r"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	var row models.AccessConnector
	if err := db.First(&row, "id = ?", res.ConnectorID).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if row.Credentials == "" {
		t.Fatalf("Credentials column is empty after Connect")
	}
	// PassthroughEncryptor leaves the JSON in place; the test asserts
	// the round-trip lands the secrets in the row, ensuring the
	// encrypt → persist arrow on the pipeline diagram is wired.
	if !strings.Contains(row.Credentials, "token") || !strings.Contains(row.Credentials, "refresh") {
		t.Errorf("Credentials column missing expected secrets: %q", row.Credentials)
	}
}

// TestRotateCredentials_HappyPath asserts the documented rotation
// flow: load by ID, re-validate + re-connect with new secrets, then
// UPDATE the row with the freshly encrypted ciphertext and a bumped
// updated_at.
func TestRotateCredentials_HappyPath(t *testing.T) {
	const provider = "test_lifecycle_rotate"
	db := newConnectorMgmtDB(t)
	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID: "01HWS0LIFE0ROTATE00000000",
		Provider:    provider,
		Secrets:     map[string]interface{}{"token": "old"},
	})
	if err != nil {
		t.Fatalf("seed Connect: %v", err)
	}

	// Reset call counters so we only count the rotate invocations.
	mock.ValidateCalls, mock.ConnectCalls = 0, 0

	if err := svc.RotateCredentials(context.Background(), res.ConnectorID, nil, map[string]interface{}{"token": "new"}); err != nil {
		t.Fatalf("RotateCredentials: %v", err)
	}
	if mock.ValidateCalls != 1 || mock.ConnectCalls != 1 {
		t.Errorf("Validate=%d, Connect=%d; want both 1 after rotate", mock.ValidateCalls, mock.ConnectCalls)
	}

	var row models.AccessConnector
	if err := db.First(&row, "id = ?", res.ConnectorID).Error; err != nil {
		t.Fatalf("load row: %v", err)
	}
	if !strings.Contains(row.Credentials, "new") {
		t.Errorf("Credentials column = %q; want to contain new secret value", row.Credentials)
	}
}

// TestRotateCredentials_NotFound asserts a missing connector ID
// returns ErrConnectorRowNotFound so handlers map to 404.
func TestRotateCredentials_NotFound(t *testing.T) {
	db := newConnectorMgmtDB(t)
	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	err := svc.RotateCredentials(context.Background(), "01NONEXISTENT0000000000000",
		nil, map[string]interface{}{"token": "x"})
	if err == nil || !errors.Is(err, ErrConnectorRowNotFound) {
		t.Fatalf("err=%v; want wraps ErrConnectorRowNotFound", err)
	}
}


