package access

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newAccessModeTestDB returns a fresh in-memory SQLite DB with the
// access-platform tables touched by the Phase 11 access_mode flow:
// the connectors registry (Connect inserts + UpdateAccessMode
// reads / writes) and the access_jobs ledger (Connect always
// enqueues a sync_identities job).
func newAccessModeTestDB(t *testing.T) *gorm.DB {
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

// TestConnectorManagementService_Connect_ClassifiesAPIOnlyDefault
// asserts the docs/PROPOSAL.md §13 default: a SaaS connector with
// no SSO realm configured and no private-resource hints lands at
// access_mode == "api_only" and the value is persisted to the
// access_connectors row.
func TestConnectorManagementService_Connect_ClassifiesAPIOnlyDefault(t *testing.T) {
	const provider = "test_provider_access_mode_apionly"
	db := newAccessModeTestDB(t)
	SwapConnector(t, provider, &MockAccessConnector{})

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID:   "01HWS0AMODE0APIONLY000000",
		Provider:      provider,
		ConnectorType: "saas",
		Config:        map[string]interface{}{"region": "us-east-1"},
		Secrets:       map[string]interface{}{"token": "shh"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.AccessMode != models.AccessModeAPIOnly {
		t.Fatalf("AccessMode=%q, want %q", res.AccessMode, models.AccessModeAPIOnly)
	}

	var row models.AccessConnector
	if err := db.First(&row, "id = ?", res.ConnectorID).Error; err != nil {
		t.Fatalf("load connector row: %v", err)
	}
	if row.AccessMode != models.AccessModeAPIOnly {
		t.Fatalf("row.AccessMode=%q, want %q", row.AccessMode, models.AccessModeAPIOnly)
	}
}

// TestConnectorManagementService_Connect_PrivateHintClassifiesTunnel
// asserts that config["is_private"] = true causes the classifier
// to pick "tunnel" even when no SSO realm is configured.
func TestConnectorManagementService_Connect_PrivateHintClassifiesTunnel(t *testing.T) {
	const provider = "test_provider_access_mode_tunnel"
	db := newAccessModeTestDB(t)
	SwapConnector(t, provider, &MockAccessConnector{})

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID:   "01HWS0AMODE0TUNNEL0000000",
		Provider:      provider,
		ConnectorType: "directory",
		Config: map[string]interface{}{
			"is_private": true,
			"host":       "private.corp.internal",
		},
		Secrets: map[string]interface{}{"token": "shh"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.AccessMode != models.AccessModeTunnel {
		t.Fatalf("AccessMode=%q, want %q", res.AccessMode, models.AccessModeTunnel)
	}
}

// TestConnectorManagementService_Connect_ExplicitOverride asserts
// that config["access_mode"] takes precedence over every other
// signal, so operators bootstrapping a connector via the API can
// always pin the classification themselves.
func TestConnectorManagementService_Connect_ExplicitOverride(t *testing.T) {
	const provider = "test_provider_access_mode_override"
	db := newAccessModeTestDB(t)
	SwapConnector(t, provider, &MockAccessConnector{})

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)
	res, err := svc.Connect(context.Background(), ConnectInput{
		WorkspaceID:   "01HWS0AMODE0OVERRIDE00000",
		Provider:      provider,
		ConnectorType: "directory",
		Config: map[string]interface{}{
			"is_private":  true,
			"access_mode": "sso_only",
		},
		Secrets: map[string]interface{}{"token": "shh"},
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if res.AccessMode != models.AccessModeSSOOnly {
		t.Fatalf("AccessMode=%q, want %q (explicit override should beat is_private)",
			res.AccessMode, models.AccessModeSSOOnly)
	}
}

// TestConnectorManagementService_UpdateAccessMode covers the admin
// override path: PATCH /access/connectors/:id mutates the
// access_mode column in place and rejects invalid values via
// ErrValidation. The function is the service-layer companion of
// the HTTP handler — exercising it here means the handler test
// only needs to cover the routing / body-parsing surface.
func TestConnectorManagementService_UpdateAccessMode(t *testing.T) {
	const provider = "test_provider_update_access_mode"
	db := newAccessModeTestDB(t)
	SwapConnector(t, provider, &MockAccessConnector{})

	svc := NewConnectorManagementService(db, PassthroughEncryptor{}, nil, nil)

	cfgJSON, err := json.Marshal(map[string]interface{}{})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	connectorID := "01HUPD0AMODE0CONN00000000"
	if err := db.Create(&models.AccessConnector{
		ID:            connectorID,
		WorkspaceID:   "01HUPD0AMODE0WS0000000000",
		Provider:      provider,
		ConnectorType: "directory",
		Status:        models.StatusConnected,
		Config:        datatypes.JSON(cfgJSON),
		AccessMode:    models.AccessModeAPIOnly,
		KeyVersion:    1,
	}).Error; err != nil {
		t.Fatalf("seed connector: %v", err)
	}

	ctx := context.Background()

	// happy path: api_only -> tunnel
	if err := svc.UpdateAccessMode(ctx, connectorID, models.AccessModeTunnel); err != nil {
		t.Fatalf("UpdateAccessMode tunnel: %v", err)
	}
	var row models.AccessConnector
	if err := db.First(&row, "id = ?", connectorID).Error; err != nil {
		t.Fatalf("load connector: %v", err)
	}
	if row.AccessMode != models.AccessModeTunnel {
		t.Fatalf("row.AccessMode=%q, want %q", row.AccessMode, models.AccessModeTunnel)
	}

	// validation: empty connector id
	if err := svc.UpdateAccessMode(ctx, "", models.AccessModeTunnel); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for empty connector_id, got %v", err)
	}

	// validation: malformed mode
	if err := svc.UpdateAccessMode(ctx, connectorID, "garbage"); !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation for malformed mode, got %v", err)
	}

	// not-found
	err = svc.UpdateAccessMode(ctx, "01HMISSING000000000000000", models.AccessModeSSOOnly)
	if !errors.Is(err, ErrConnectorRowNotFound) {
		t.Fatalf("expected ErrConnectorRowNotFound, got %v", err)
	}
}
