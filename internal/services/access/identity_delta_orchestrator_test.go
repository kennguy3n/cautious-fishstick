package access

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// mapCursorStore is the test-only IdentitySyncCursorStore: a thread-
// safe map keyed on (connectorID, kind). Records Set calls so tests
// can assert the expected lifecycle (drop expired cursor, persist new
// cursor on success).
type mapCursorStore struct {
	mu       sync.Mutex
	cursors  map[string]string
	setCalls []cursorSetCall
}

type cursorSetCall struct {
	ConnectorID string
	Kind        string
	DeltaLink   string
}

func newMapCursorStore() *mapCursorStore {
	return &mapCursorStore{cursors: map[string]string{}}
}

func (m *mapCursorStore) key(connectorID, kind string) string {
	return connectorID + "|" + kind
}

func (m *mapCursorStore) Get(_ context.Context, connectorID, kind string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursors[m.key(connectorID, kind)], nil
}

func (m *mapCursorStore) Set(_ context.Context, connectorID, kind, deltaLink string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursors[m.key(connectorID, kind)] = deltaLink
	m.setCalls = append(m.setCalls, cursorSetCall{ConnectorID: connectorID, Kind: kind, DeltaLink: deltaLink})
	return nil
}

// fakeConnector is the minimum AccessConnector test surface: it
// records every call and emits scripted batches on SyncIdentities /
// SyncIdentitiesDelta. Optionally returns ErrDeltaTokenExpired on
// the first delta call so tests can pin the fallback path.
type fakeConnector struct {
	fullBatches  [][]*Identity
	deltaBatches [][]*Identity

	deltaErr        error
	deltaInvocations int
	fullInvocations  int

	finalDeltaLink string
}

var _ AccessConnector = (*fakeConnector)(nil)
var _ IdentityDeltaSyncer = (*fakeConnector)(nil)

func (f *fakeConnector) Validate(_ context.Context, _, _ map[string]interface{}) error {
	return nil
}
func (f *fakeConnector) Connect(_ context.Context, _, _ map[string]interface{}) error { return nil }
func (f *fakeConnector) VerifyPermissions(_ context.Context, _, _ map[string]interface{}, _ []string) ([]string, error) {
	return nil, nil
}
func (f *fakeConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}
func (f *fakeConnector) SyncIdentities(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*Identity, string) error) error {
	f.fullInvocations++
	for i, batch := range f.fullBatches {
		next := ""
		if i+1 < len(f.fullBatches) {
			next = fmt.Sprintf("page-%d", i+1)
		}
		if err := handler(batch, next); err != nil {
			return err
		}
	}
	return nil
}
func (f *fakeConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
	return nil
}
func (f *fakeConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ AccessGrant) error {
	return nil
}
func (f *fakeConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]Entitlement, error) {
	return nil, nil
}
func (f *fakeConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*SSOMetadata, error) {
	return nil, nil
}
func (f *fakeConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return nil, nil
}

func (f *fakeConnector) SyncIdentitiesDelta(_ context.Context, _, _ map[string]interface{}, _ string, handler func([]*Identity, []string, string) error) (string, error) {
	f.deltaInvocations++
	if f.deltaErr != nil {
		return "", f.deltaErr
	}
	for i, batch := range f.deltaBatches {
		next := ""
		if i+1 < len(f.deltaBatches) {
			next = fmt.Sprintf("d-page-%d", i+1)
		}
		if err := handler(batch, nil, next); err != nil {
			return "", err
		}
	}
	return f.finalDeltaLink, nil
}

// TestOrchestrator_DeltaPath_HappyPath verifies that when a cursor
// exists and the delta call succeeds, the orchestrator returns the
// new finalDeltaLink and persists it via the cursor store.
func TestOrchestrator_DeltaPath_HappyPath(t *testing.T) {
	store := newMapCursorStore()
	_ = store.Set(context.Background(), "01HCONN", "identity", "cursor-original")
	store.setCalls = nil // reset capture after seeding

	conn := &fakeConnector{
		deltaBatches: [][]*Identity{{
			{ExternalID: "u1", Type: IdentityTypeUser},
			{ExternalID: "u2", Type: IdentityTypeUser},
		}},
		finalDeltaLink: "cursor-new",
	}
	orch := NewIdentityDeltaSyncOrchestrator(store)
	var seen []*Identity
	res, err := orch.Run(context.Background(), "01HCONN", conn, nil, nil,
		func(batch []*Identity, _ []string) error {
			seen = append(seen, batch...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "delta" {
		t.Errorf("mode = %q; want delta", res.Mode)
	}
	if conn.deltaInvocations != 1 || conn.fullInvocations != 0 {
		t.Errorf("invocations: delta=%d full=%d; want delta=1 full=0", conn.deltaInvocations, conn.fullInvocations)
	}
	if len(seen) != 2 {
		t.Errorf("seen = %d; want 2", len(seen))
	}
	if got := store.cursors["01HCONN|identity"]; got != "cursor-new" {
		t.Errorf("persisted cursor = %q; want cursor-new", got)
	}
}

// TestOrchestrator_DeltaTokenExpired_FallsBackToFullSync is the T27
// regression test: when SyncIdentitiesDelta returns
// ErrDeltaTokenExpired the orchestrator MUST drop the stored cursor
// and call SyncIdentities for a full re-sync.
func TestOrchestrator_DeltaTokenExpired_FallsBackToFullSync(t *testing.T) {
	store := newMapCursorStore()
	_ = store.Set(context.Background(), "01HCONN", "identity", "cursor-stale")
	store.setCalls = nil

	conn := &fakeConnector{
		deltaErr: ErrDeltaTokenExpired,
		fullBatches: [][]*Identity{{
			{ExternalID: "u1", Type: IdentityTypeUser},
			{ExternalID: "u2", Type: IdentityTypeUser},
			{ExternalID: "u3", Type: IdentityTypeUser},
		}},
	}
	orch := NewIdentityDeltaSyncOrchestrator(store)
	var seen []*Identity
	res, err := orch.Run(context.Background(), "01HCONN", conn, nil, nil,
		func(batch []*Identity, _ []string) error {
			seen = append(seen, batch...)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "delta_then_full_fallback" {
		t.Errorf("mode = %q; want delta_then_full_fallback", res.Mode)
	}
	if conn.deltaInvocations != 1 {
		t.Errorf("delta invocations = %d; want 1", conn.deltaInvocations)
	}
	if conn.fullInvocations != 1 {
		t.Errorf("full invocations = %d; want 1", conn.fullInvocations)
	}
	if len(seen) != 3 {
		t.Errorf("identities seen = %d; want 3", len(seen))
	}
	if got := store.cursors["01HCONN|identity"]; got != "" {
		t.Errorf("cursor = %q; want empty after fallback", got)
	}
	// Verify the cursor was dropped *before* the full sync ran by
	// inspecting the call order — the first Set after the delta call
	// must be a drop, and the last Set must be the post-full-sync
	// reset (both empty in this scenario).
	if len(store.setCalls) < 2 {
		t.Fatalf("expected at least 2 Set calls during fallback, got %d", len(store.setCalls))
	}
	if store.setCalls[0].DeltaLink != "" {
		t.Errorf("first Set during fallback = %q; want empty (drop expired cursor)", store.setCalls[0].DeltaLink)
	}
}

// TestOrchestrator_NoCursor_FullSyncFirstRun verifies that on the
// very first run (no cursor in the store) the orchestrator goes
// straight to a full sync — delta-from-epoch semantics are too
// provider-specific to rely on.
func TestOrchestrator_NoCursor_FullSyncFirstRun(t *testing.T) {
	store := newMapCursorStore()
	conn := &fakeConnector{
		fullBatches: [][]*Identity{{
			{ExternalID: "u1", Type: IdentityTypeUser},
		}},
	}
	orch := NewIdentityDeltaSyncOrchestrator(store)
	res, err := orch.Run(context.Background(), "01HCONN", conn, nil, nil,
		func(_ []*Identity, _ []string) error { return nil },
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "full" {
		t.Errorf("mode = %q; want full", res.Mode)
	}
	if conn.deltaInvocations != 0 {
		t.Errorf("delta invocations = %d; want 0 on first run", conn.deltaInvocations)
	}
	if conn.fullInvocations != 1 {
		t.Errorf("full invocations = %d; want 1", conn.fullInvocations)
	}
}

// TestOrchestrator_DeltaError_NonExpiredPropagates verifies that a
// non-expiry error from the delta path is surfaced — we don't want
// to silently mask transient 5xx errors as "expired token + full
// sync".
func TestOrchestrator_DeltaError_NonExpiredPropagates(t *testing.T) {
	store := newMapCursorStore()
	_ = store.Set(context.Background(), "01HCONN", "identity", "cursor-stale")

	conn := &fakeConnector{
		deltaErr: errors.New("transient 503"),
	}
	orch := NewIdentityDeltaSyncOrchestrator(store)
	_, err := orch.Run(context.Background(), "01HCONN", conn, nil, nil,
		func(_ []*Identity, _ []string) error { return nil },
	)
	if err == nil {
		t.Fatal("expected non-expiry error to propagate, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error %q does not surface underlying 503", err.Error())
	}
	if conn.fullInvocations != 0 {
		t.Errorf("full invocations = %d; full sync must NOT run for non-expiry errors", conn.fullInvocations)
	}
	// Cursor must NOT be dropped on a non-expiry failure — the next
	// run gets to retry the delta.
	if got, _ := store.Get(context.Background(), "01HCONN", "identity"); got != "cursor-stale" {
		t.Errorf("cursor = %q; want cursor-stale (must not be dropped on transient error)", got)
	}
}

// TestOrchestrator_ConnectorWithoutDeltaInterface_FullSyncOnly is
// the path for providers that don't implement IdentityDeltaSyncer at
// all — the orchestrator should still complete via the full-sync
// path without touching the delta-interface code.
func TestOrchestrator_ConnectorWithoutDeltaInterface_FullSyncOnly(t *testing.T) {
	store := newMapCursorStore()
	// Wrapping fakeConnector in an interface-narrowed struct so the
	// type assertion to IdentityDeltaSyncer fails.
	conn := &fullOnlyConnector{inner: &fakeConnector{
		fullBatches: [][]*Identity{{
			{ExternalID: "u1", Type: IdentityTypeUser},
		}},
	}}
	orch := NewIdentityDeltaSyncOrchestrator(store)
	res, err := orch.Run(context.Background(), "01HCONN", conn, nil, nil,
		func(_ []*Identity, _ []string) error { return nil },
	)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Mode != "full" {
		t.Errorf("mode = %q; want full", res.Mode)
	}
}

// fullOnlyConnector wraps fakeConnector while shadowing only the
// SyncIdentities method, so it satisfies AccessConnector but NOT
// IdentityDeltaSyncer.
type fullOnlyConnector struct{ inner *fakeConnector }

var _ AccessConnector = (*fullOnlyConnector)(nil)

func (f *fullOnlyConnector) Validate(ctx context.Context, c, s map[string]interface{}) error {
	return f.inner.Validate(ctx, c, s)
}
func (f *fullOnlyConnector) Connect(ctx context.Context, c, s map[string]interface{}) error {
	return f.inner.Connect(ctx, c, s)
}
func (f *fullOnlyConnector) VerifyPermissions(ctx context.Context, c, s map[string]interface{}, caps []string) ([]string, error) {
	return f.inner.VerifyPermissions(ctx, c, s, caps)
}
func (f *fullOnlyConnector) CountIdentities(ctx context.Context, c, s map[string]interface{}) (int, error) {
	return f.inner.CountIdentities(ctx, c, s)
}
func (f *fullOnlyConnector) SyncIdentities(ctx context.Context, c, s map[string]interface{}, ck string, h func([]*Identity, string) error) error {
	return f.inner.SyncIdentities(ctx, c, s, ck, h)
}
func (f *fullOnlyConnector) ProvisionAccess(ctx context.Context, c, s map[string]interface{}, g AccessGrant) error {
	return f.inner.ProvisionAccess(ctx, c, s, g)
}
func (f *fullOnlyConnector) RevokeAccess(ctx context.Context, c, s map[string]interface{}, g AccessGrant) error {
	return f.inner.RevokeAccess(ctx, c, s, g)
}
func (f *fullOnlyConnector) ListEntitlements(ctx context.Context, c, s map[string]interface{}, u string) ([]Entitlement, error) {
	return f.inner.ListEntitlements(ctx, c, s, u)
}
func (f *fullOnlyConnector) GetSSOMetadata(ctx context.Context, c, s map[string]interface{}) (*SSOMetadata, error) {
	return f.inner.GetSSOMetadata(ctx, c, s)
}
func (f *fullOnlyConnector) GetCredentialsMetadata(ctx context.Context, c, s map[string]interface{}) (map[string]interface{}, error) {
	return f.inner.GetCredentialsMetadata(ctx, c, s)
}
