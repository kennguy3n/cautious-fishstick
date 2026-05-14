package access

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// catTestConnector is a tiny AccessConnector implementation used by
// the catalogue tests. It satisfies the mandatory contract with
// no-ops so we can swap it into the registry under arbitrary
// provider keys.
type catTestConnector struct{}

func (catTestConnector) Validate(context.Context, map[string]interface{}, map[string]interface{}) error {
	return nil
}
func (catTestConnector) Connect(context.Context, map[string]interface{}, map[string]interface{}) error {
	return nil
}
func (catTestConnector) VerifyPermissions(context.Context, map[string]interface{}, map[string]interface{}, []string) ([]string, error) {
	return nil, nil
}
func (catTestConnector) CountIdentities(context.Context, map[string]interface{}, map[string]interface{}) (int, error) {
	return 0, nil
}
func (catTestConnector) SyncIdentities(context.Context, map[string]interface{}, map[string]interface{}, string, func([]*Identity, string) error) error {
	return nil
}
func (catTestConnector) ProvisionAccess(context.Context, map[string]interface{}, map[string]interface{}, AccessGrant) error {
	return nil
}
func (catTestConnector) RevokeAccess(context.Context, map[string]interface{}, map[string]interface{}, AccessGrant) error {
	return nil
}
func (catTestConnector) ListEntitlements(context.Context, map[string]interface{}, map[string]interface{}, string) ([]Entitlement, error) {
	return nil, nil
}
func (catTestConnector) GetSSOMetadata(context.Context, map[string]interface{}, map[string]interface{}) (*SSOMetadata, error) {
	return nil, nil
}
func (catTestConnector) GetCredentialsMetadata(context.Context, map[string]interface{}, map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

// catAuditorConnector additionally satisfies AccessAuditor.
type catAuditorConnector struct{ catTestConnector }

func (catAuditorConnector) FetchAccessAuditLogs(context.Context, map[string]interface{}, map[string]interface{}, map[string]time.Time, func([]*AuditLogEntry, time.Time, string) error) error {
	return nil
}

// withRegistered registers connector under provider for the duration of
// the test, restoring whatever was there before (typically nothing).
func withRegistered(t *testing.T, provider string, connector AccessConnector) {
	t.Helper()
	registryMu.Lock()
	previous, hadPrevious := registry[provider]
	registry[provider] = connector
	registryMu.Unlock()
	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		if hadPrevious {
			registry[provider] = previous
		} else {
			delete(registry, provider)
		}
	})
}

func newCatalogueTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	return db
}

// TestConnectorCatalogueService_ListCatalogue_EmptyRegistry asserts the
// service returns an empty slice (not nil error) when no connectors
// are registered AND no DB rows exist.
func TestConnectorCatalogueService_ListCatalogue_EmptyRegistry(t *testing.T) {
	db := newCatalogueTestDB(t)
	svc := NewAccessConnectorCatalogueService(db)

	out, err := svc.ListCatalogue(context.Background(), ConnectorCatalogueQuery{
		WorkspaceID: "01H000000000000000WORKSPACE",
	})
	if err != nil {
		t.Fatalf("ListCatalogue err = %v; want nil", err)
	}
	// Other tests may have registered connectors via package-level
	// init() side-effects. The empty-registry assertion is about
	// shape (no error, slice typed correctly), not length.
	for i := range out {
		if out[i].Connected {
			t.Fatalf("entry %q reports Connected=true with no DB rows; out=%#v", out[i].Provider, out)
		}
	}
}

// TestConnectorCatalogueService_ListCatalogue_HappyPath registers a
// vanilla connector + an auditor-capable connector, seeds an
// access_connectors row for the auditor, and asserts the catalogue
// carries both with the correct capability flags and the auditor's
// Connected=true / Status enrichment.
func TestConnectorCatalogueService_ListCatalogue_HappyPath(t *testing.T) {
	withRegistered(t, "_test_catalogue_plain", catTestConnector{})
	withRegistered(t, "_test_catalogue_auditor", catAuditorConnector{})

	db := newCatalogueTestDB(t)
	now := time.Now()
	if err := db.Create(&models.AccessConnector{
		ID:            "01H00000000000000CONN0001",
		WorkspaceID:   "01H000000000000000WORKSPACE",
		Provider:      "_test_catalogue_auditor",
		ConnectorType: "saas",
		Status:        "connected",
		CreatedAt:     now,
		UpdatedAt:     now,
	}).Error; err != nil {
		t.Fatalf("seed connector row: %v", err)
	}

	svc := NewAccessConnectorCatalogueService(db)
	out, err := svc.ListCatalogue(context.Background(), ConnectorCatalogueQuery{
		WorkspaceID: "01H000000000000000WORKSPACE",
	})
	if err != nil {
		t.Fatalf("ListCatalogue err = %v; want nil", err)
	}

	var plain, auditor *ConnectorCatalogueEntry
	for i := range out {
		switch out[i].Provider {
		case "_test_catalogue_plain":
			plain = &out[i]
		case "_test_catalogue_auditor":
			auditor = &out[i]
		}
	}
	if plain == nil {
		t.Fatal("plain provider missing from catalogue")
	}
	if auditor == nil {
		t.Fatal("auditor provider missing from catalogue")
	}
	if !plain.Capabilities.Registered || plain.Capabilities.GetAccessLog {
		t.Fatalf("plain caps = %+v; want Registered=true, GetAccessLog=false", plain.Capabilities)
	}
	if plain.Connected {
		t.Fatalf("plain Connected = true; want false (no DB row)")
	}
	if !auditor.Capabilities.GetAccessLog {
		t.Fatal("auditor Capabilities.GetAccessLog = false; want true")
	}
	if !auditor.Connected {
		t.Fatal("auditor Connected = false; want true (seeded DB row)")
	}
	if auditor.ConnectorID != "01H00000000000000CONN0001" {
		t.Fatalf("auditor ConnectorID = %q; want seed ULID", auditor.ConnectorID)
	}
	if auditor.Status != "connected" {
		t.Fatalf("auditor Status = %q; want %q", auditor.Status, "connected")
	}
}

// TestConnectorCatalogueService_ListCatalogue_MissingWorkspaceID asserts
// the service rejects a query with an empty WorkspaceID, surfacing
// ErrValidation so the handler can map to 400 Bad Request.
func TestConnectorCatalogueService_ListCatalogue_MissingWorkspaceID(t *testing.T) {
	db := newCatalogueTestDB(t)
	svc := NewAccessConnectorCatalogueService(db)
	_, err := svc.ListCatalogue(context.Background(), ConnectorCatalogueQuery{})
	if err == nil {
		t.Fatal("err = nil; want ErrValidation")
	}
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want errors.Is(err, ErrValidation)", err)
	}
}

// TestConnectorCatalogueService_ListCatalogue_NilDB asserts the service
// can still enumerate the registry with a nil DB — Connected is
// always false and no DB query is made.
func TestConnectorCatalogueService_ListCatalogue_NilDB(t *testing.T) {
	withRegistered(t, "_test_catalogue_nil_db", catTestConnector{})

	svc := NewAccessConnectorCatalogueService(nil)
	out, err := svc.ListCatalogue(context.Background(), ConnectorCatalogueQuery{
		WorkspaceID: "01H000000000000000WORKSPACE",
	})
	if err != nil {
		t.Fatalf("ListCatalogue err = %v; want nil", err)
	}

	var found bool
	for i := range out {
		if out[i].Provider == "_test_catalogue_nil_db" {
			found = true
			if out[i].Connected {
				t.Fatal("Connected = true with nil DB; want false")
			}
		}
	}
	if !found {
		t.Fatal("registered provider not in catalogue")
	}
}
