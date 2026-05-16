package pam

import (
	"context"
	"errors"
	"testing"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// newPAMDB returns an in-memory SQLite DB with the eight PAM tables
// migrated. Tests are intentionally narrow — only the PAM models
// are migrated so unrelated schema churn never enters the test
// loop.
func newPAMDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(
		&models.PAMAsset{},
		&models.PAMAccount{},
		&models.PAMSecret{},
		&models.PAMSession{},
		&models.PAMSessionCommand{},
		&models.PAMLease{},
		&models.PAMCommandPolicy{},
		&models.PAMRotationSchedule{},
		&models.AccessRequest{},
	); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func TestPAMAssetService_CreateAsset_HappyPath(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name:        "prod-bastion",
		Protocol:    "ssh",
		Host:        "10.0.0.1",
		Port:        22,
		Criticality: "high",
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if asset.ID == "" {
		t.Fatalf("expected ULID, got empty")
	}
	if asset.Status != models.PAMAssetStatusActive {
		t.Fatalf("status = %q; want %q", asset.Status, models.PAMAssetStatusActive)
	}
	if asset.WorkspaceID != "ws-1" {
		t.Fatalf("workspace = %q; want ws-1", asset.WorkspaceID)
	}
}

func TestPAMAssetService_CreateAsset_DefaultsCriticality(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name:     "host",
		Protocol: "ssh",
		Host:     "10.0.0.1",
		Port:     22,
	})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if asset.Criticality != models.PAMCriticalityMedium {
		t.Fatalf("criticality = %q; want medium default", asset.Criticality)
	}
}

func TestPAMAssetService_CreateAsset_ValidationFailures(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	cases := []struct {
		name string
		in   CreateAssetInput
	}{
		{"missing name", CreateAssetInput{Protocol: "ssh", Host: "h", Port: 22}},
		{"missing host", CreateAssetInput{Name: "a", Protocol: "ssh", Port: 22}},
		{"invalid protocol", CreateAssetInput{Name: "a", Protocol: "telnet", Host: "h", Port: 22}},
		{"port too low", CreateAssetInput{Name: "a", Protocol: "ssh", Host: "h", Port: 0}},
		{"port too high", CreateAssetInput{Name: "a", Protocol: "ssh", Host: "h", Port: 70000}},
		{"invalid criticality", CreateAssetInput{Name: "a", Protocol: "ssh", Host: "h", Port: 22, Criticality: "ULTRA"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateAsset(context.Background(), "ws-1", tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}

func TestPAMAssetService_CreateAsset_MissingWorkspace(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	_, err := svc.CreateAsset(context.Background(), "", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

func TestPAMAssetService_GetAsset_NotFound(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	_, err := svc.GetAsset(context.Background(), "ws-1", "nope")
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("err = %v; want ErrAssetNotFound", err)
	}
}

func TestPAMAssetService_GetAsset_ScopedByWorkspace(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Same workspace finds the row.
	if _, err := svc.GetAsset(context.Background(), "ws-1", asset.ID); err != nil {
		t.Fatalf("GetAsset same workspace: %v", err)
	}
	// Different workspace cannot.
	_, err = svc.GetAsset(context.Background(), "ws-other", asset.ID)
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("err = %v; want ErrAssetNotFound for cross-workspace", err)
	}
}

func TestPAMAssetService_ListAssets_FiltersAndPagination(t *testing.T) {
	db := newPAMDB(t)
	svc := NewPAMAssetService(db)
	mk := func(name, protocol, criticality string) {
		if _, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
			Name: name, Protocol: protocol, Host: "h", Port: 22, Criticality: criticality,
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	mk("a", "ssh", "low")
	mk("b", "ssh", "high")
	mk("c", "rdp", "high")
	mk("d", "postgres", "medium")

	out, err := svc.ListAssets(context.Background(), "ws-1", ListAssetsFilters{})
	if err != nil {
		t.Fatalf("ListAssets: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("listed %d; want 4", len(out))
	}

	out, err = svc.ListAssets(context.Background(), "ws-1", ListAssetsFilters{Protocol: "ssh"})
	if err != nil {
		t.Fatalf("ListAssets ssh: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("ssh filtered = %d; want 2", len(out))
	}

	out, err = svc.ListAssets(context.Background(), "ws-1", ListAssetsFilters{Criticality: "high"})
	if err != nil {
		t.Fatalf("ListAssets crit: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("high filtered = %d; want 2", len(out))
	}

	out, err = svc.ListAssets(context.Background(), "ws-1", ListAssetsFilters{Limit: 2})
	if err != nil {
		t.Fatalf("ListAssets limit: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("limit 2 = %d", len(out))
	}
}

func TestPAMAssetService_UpdateAsset_Partial(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22, Criticality: "low",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	newName := "renamed"
	upd, err := svc.UpdateAsset(context.Background(), "ws-1", asset.ID, UpdateAssetInput{Name: &newName})
	if err != nil {
		t.Fatalf("UpdateAsset: %v", err)
	}
	if upd.Name != "renamed" {
		t.Fatalf("name = %q; want renamed", upd.Name)
	}
	if upd.Host != "h" {
		t.Fatalf("host should be unchanged, got %q", upd.Host)
	}
}

func TestPAMAssetService_UpdateAsset_InvalidStatus(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	bad := "not-a-status"
	_, err = svc.UpdateAsset(context.Background(), "ws-1", asset.ID, UpdateAssetInput{Status: &bad})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v; want ErrValidation", err)
	}
}

func TestPAMAssetService_DeleteAsset_SoftDelete(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := svc.DeleteAsset(context.Background(), "ws-1", asset.ID); err != nil {
		t.Fatalf("DeleteAsset: %v", err)
	}
	reloaded, err := svc.GetAsset(context.Background(), "ws-1", asset.ID)
	if err != nil {
		t.Fatalf("GetAsset after delete: %v", err)
	}
	if reloaded.Status != models.PAMAssetStatusArchived {
		t.Fatalf("status after delete = %q; want archived", reloaded.Status)
	}
}

func TestPAMAssetService_CreateAccount_OnExistingAsset(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	acct, err := svc.CreateAccount(context.Background(), "ws-1", asset.ID, CreateAccountInput{
		Username:    "root",
		AccountType: "shared",
		IsDefault:   true,
	})
	if err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if acct.ID == "" {
		t.Fatalf("empty account ID")
	}
	if acct.Username != "root" {
		t.Fatalf("username = %q", acct.Username)
	}
}

func TestPAMAssetService_CreateAccount_NonExistentAsset(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	_, err := svc.CreateAccount(context.Background(), "ws-1", "no-such", CreateAccountInput{
		Username:    "root",
		AccountType: "shared",
	})
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("err = %v; want ErrAssetNotFound", err)
	}
}

// TestPAMAssetService_CreateAccount_RejectsCrossWorkspace asserts that
// passing a workspaceID different from the asset's owning workspace
// surfaces ErrAssetNotFound — the service-layer scoping check is the
// last line of defence behind the handler's body validation.
func TestPAMAssetService_CreateAccount_RejectsCrossWorkspace(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err = svc.CreateAccount(context.Background(), "ws-other", asset.ID, CreateAccountInput{
		Username: "root", AccountType: "shared",
	})
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("cross-workspace = %v; want ErrAssetNotFound", err)
	}
}

// TestPAMAssetService_CreateAccount_RejectsMissingWorkspace covers the
// explicit workspace_id validation guard.
func TestPAMAssetService_CreateAccount_RejectsMissingWorkspace(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	_, err := svc.CreateAccount(context.Background(), "", "asset-1", CreateAccountInput{
		Username: "root", AccountType: "shared",
	})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("missing workspace = %v; want ErrValidation", err)
	}
}

func TestPAMAssetService_CreateAccount_ValidationFailures(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	cases := []struct {
		name string
		in   CreateAccountInput
	}{
		{"missing username", CreateAccountInput{AccountType: "shared"}},
		{"missing account_type", CreateAccountInput{Username: "u"}},
		{"invalid account_type", CreateAccountInput{Username: "u", AccountType: "robot"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateAccount(context.Background(), "ws-1", asset.ID, tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}

func TestPAMAssetService_ListAccounts(t *testing.T) {
	svc := NewPAMAssetService(newPAMDB(t))
	asset, err := svc.CreateAsset(context.Background(), "ws-1", CreateAssetInput{
		Name: "a", Protocol: "ssh", Host: "h", Port: 22,
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	for i, u := range []string{"alice", "bob", "carol"} {
		if _, err := svc.CreateAccount(context.Background(), "ws-1", asset.ID, CreateAccountInput{
			Username:    u,
			AccountType: "personal",
			IsDefault:   i == 0,
		}); err != nil {
			t.Fatalf("seed %s: %v", u, err)
		}
	}
	out, err := svc.ListAccounts(context.Background(), asset.ID)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("listed %d; want 3", len(out))
	}
}
