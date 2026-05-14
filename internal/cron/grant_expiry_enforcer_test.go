package cron

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

func newGrantDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.AutoMigrate(&models.AccessGrant{}, &models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate: %v", err)
	}
	return db
}

func seedGrant(t *testing.T, db *gorm.DB, id string, expiresAt *time.Time) {
	t.Helper()
	now := time.Now()
	reqID := "01HREQ00000000000000000001"
	row := &models.AccessGrant{
		ID:                 id,
		RequestID:          &reqID,
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		UserID:             "01HUSER00000000000000000A",
		ConnectorID:        "01HCONN00000000000000000A",
		ResourceExternalID: "projects/foo",
		Role:               "viewer",
		GrantedAt:          now,
		ExpiresAt:          expiresAt,
	}
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("seed grant: %v", err)
	}
}

// captureRevoker records every Revoke call along with the
// (config, secrets) pair it was given so tests can assert the
// enforcer actually plumbed real credentials through instead of
// nil. Mirrors *access.AccessProvisioningService's update of the
// access_grants row on success.
type captureRevoker struct {
	calls   []string
	configs []map[string]interface{}
	secrets []map[string]interface{}
	now     func() time.Time
	db      *gorm.DB
}

func (c *captureRevoker) Revoke(ctx context.Context, grant *models.AccessGrant, cfg map[string]interface{}, secrets map[string]interface{}) error {
	c.calls = append(c.calls, grant.ID)
	c.configs = append(c.configs, cfg)
	c.secrets = append(c.secrets, secrets)
	if grant.RevokedAt != nil {
		return access.ErrAlreadyRevoked
	}
	now := c.now()
	return c.db.WithContext(ctx).
		Model(&models.AccessGrant{}).
		Where("id = ?", grant.ID).
		Updates(map[string]interface{}{
			"revoked_at": now,
			"updated_at": now,
		}).Error
}

// stubCredentialsLoader is the test ConnectorCredentialsLoader.
// It is NOT a mock — it implements the real interface contract; its
// semantics happen to be a fixed in-memory lookup so tests can
// assert which (config, secrets) pair each connector resolves to.
type stubCredentialsLoader struct {
	entries map[string]struct {
		cfg     map[string]interface{}
		secrets map[string]interface{}
		err     error
	}
	calls map[string]int
}

func newStubCredentialsLoader() *stubCredentialsLoader {
	return &stubCredentialsLoader{
		entries: map[string]struct {
			cfg     map[string]interface{}
			secrets map[string]interface{}
			err     error
		}{},
		calls: map[string]int{},
	}
}

func (s *stubCredentialsLoader) set(connectorID string, cfg, secrets map[string]interface{}, err error) {
	s.entries[connectorID] = struct {
		cfg     map[string]interface{}
		secrets map[string]interface{}
		err     error
	}{cfg: cfg, secrets: secrets, err: err}
}

func (s *stubCredentialsLoader) LoadConnectorCredentials(_ context.Context, connectorID string) (map[string]interface{}, map[string]interface{}, error) {
	s.calls[connectorID]++
	entry, ok := s.entries[connectorID]
	if !ok {
		return nil, nil, access.ErrConnectorRowNotFound
	}
	return entry.cfg, entry.secrets, entry.err
}

func TestGrantExpiryEnforcer_RevokesExpiredGrants(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	futureT := now.Add(1 * time.Hour)
	seedGrant(t, db, "01HGRANT0EXPIRED000000000A", &pastT)
	seedGrant(t, db, "01HGRANT0LIVE0000000000000A", &futureT)
	seedGrant(t, db, "01HGRANT0NEVER0000000000A", nil) // no expiry

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{"tenant": "acme"},
		map[string]interface{}{"api_key": "shhh"},
		nil)
	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })

	revoked, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if revoked != 1 {
		t.Errorf("revoked = %d; want 1", revoked)
	}
	if len(rev.calls) != 1 || rev.calls[0] != "01HGRANT0EXPIRED000000000A" {
		t.Errorf("calls = %v; want [01HGRANT0EXPIRED000000000A]", rev.calls)
	}
	if len(rev.configs) != 1 || rev.configs[0]["tenant"] != "acme" {
		t.Errorf("configs[0] = %v; want tenant=acme", rev.configs)
	}
	if len(rev.secrets) != 1 || rev.secrets[0]["api_key"] != "shhh" {
		t.Errorf("secrets[0] = %v; want api_key=shhh", rev.secrets)
	}
	if loader.calls["01HCONN00000000000000000A"] != 1 {
		t.Errorf("loader called %d times; want 1 (per-connector cache)", loader.calls["01HCONN00000000000000000A"])
	}

	var expired models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0EXPIRED000000000A").First(&expired).Error; err != nil {
		t.Fatalf("load expired: %v", err)
	}
	if expired.RevokedAt == nil {
		t.Error("expired grant did not get revoked_at set")
	}
	var live models.AccessGrant
	if err := db.Where("id = ?", "01HGRANT0LIVE0000000000000A").First(&live).Error; err != nil {
		t.Fatalf("load live: %v", err)
	}
	if live.RevokedAt != nil {
		t.Error("live grant was incorrectly revoked")
	}
}

func TestGrantExpiryEnforcer_IdempotentAcrossRuns(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)
	seedGrant(t, db, "01HGRANT0EXPIRED000000000A", &pastT)

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A",
		map[string]interface{}{},
		map[string]interface{}{"api_key": "shhh"},
		nil)
	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })

	if _, err := e.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Second run should be a no-op — the grant already has revoked_at.
	revoked2, err := e.Run(context.Background())
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if revoked2 != 0 {
		t.Errorf("second run revoked = %d; want 0", revoked2)
	}
}

// TestGrantExpiryEnforcer_LoaderFailureSkipsConnector verifies that a
// loader error for a particular connector skips every grant pointing
// at that connector without aborting the whole loop, and that the
// last per-grant load error is surfaced as the Run return value.
func TestGrantExpiryEnforcer_LoaderFailureSkipsConnector(t *testing.T) {
	db := newGrantDB(t)
	now := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	pastT := now.Add(-1 * time.Hour)

	// Two expired grants on connector A (loader will fail) and one
	// on connector B (loader will succeed).
	seedGrant(t, db, "01HGRANT0FAIL000000000000A", &pastT)
	seedGrant(t, db, "01HGRANT0FAIL000000000000B", &pastT)
	okGrantReq := "01HREQ00000000000000000002"
	if err := db.Create(&models.AccessGrant{
		ID:                 "01HGRANT0OK00000000000000A",
		RequestID:          &okGrantReq,
		WorkspaceID:        "01HWORKSPACE0000000000000A",
		UserID:             "01HUSER00000000000000000A",
		ConnectorID:        "01HCONN00000000000000000B",
		ResourceExternalID: "projects/bar",
		Role:               "viewer",
		GrantedAt:          time.Now(),
		ExpiresAt:          &pastT,
	}).Error; err != nil {
		t.Fatalf("seed ok grant: %v", err)
	}

	rev := &captureRevoker{now: func() time.Time { return now }, db: db}
	loader := newStubCredentialsLoader()
	loader.set("01HCONN00000000000000000A", nil, nil, errors.New("decrypt failed"))
	loader.set("01HCONN00000000000000000B",
		map[string]interface{}{},
		map[string]interface{}{"api_key": "ok"},
		nil)

	e := NewGrantExpiryEnforcer(db, rev, loader, 100)
	e.SetClock(func() time.Time { return now })

	revoked, err := e.Run(context.Background())
	if err == nil {
		t.Fatal("Run: expected loader error to surface, got nil")
	}
	if revoked != 1 {
		t.Errorf("revoked = %d; want 1 (only connector B's grant)", revoked)
	}
	if len(rev.calls) != 1 || rev.calls[0] != "01HGRANT0OK00000000000000A" {
		t.Errorf("calls = %v; want [01HGRANT0OK00000000000000A]", rev.calls)
	}
	// Per-connector caching: connector A loaded exactly once across
	// both failing grants.
	if loader.calls["01HCONN00000000000000000A"] != 1 {
		t.Errorf("loader for failing connector called %d times; want 1", loader.calls["01HCONN00000000000000000A"])
	}
}
