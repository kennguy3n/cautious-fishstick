package access

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// stubOpenZitiClient captures every DisableIdentity call made during
// the leaver flow. Calls is the call count; UserIDs is the ordered
// list of identifiers seen; Err drives the failure-path branch.
type stubOpenZitiClient struct {
	mu      sync.Mutex
	Calls   atomic.Int64
	UserIDs []string
	Err     error
}

func (s *stubOpenZitiClient) DisableIdentity(_ context.Context, userExternalID string) error {
	s.Calls.Add(1)
	s.mu.Lock()
	s.UserIDs = append(s.UserIDs, userExternalID)
	s.mu.Unlock()
	return s.Err
}

// TestHandleLeaver_CallsOpenZitiClientWhenWired asserts the Phase 6
// wire-in: when an OpenZitiClient is set on the JMLService, the
// leaver flow calls DisableIdentity exactly once, with the leaver's
// user ID.
func TestHandleLeaver_CallsOpenZitiClientWhenWired(t *testing.T) {
	const provider = "mock_jml_leaver_ziti"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNZITI", provider)
	team := seedJMLTeam(t, db, "01H00000000000000JMLTMZITI", "team-ziti")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)

	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER08",
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/z-1", Role: "viewer"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER08")
	if err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}

	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("DisableIdentity calls = %d; want 1", got)
	}
	zClient.mu.Lock()
	defer zClient.mu.Unlock()
	if len(zClient.UserIDs) != 1 || zClient.UserIDs[0] != "01H00000000000000JMLUSER08" {
		t.Errorf("UserIDs = %v; want [01H00000000000000JMLUSER08]", zClient.UserIDs)
	}
}

// TestHandleLeaver_NoOpenZitiClientIsNoop asserts the default
// behaviour: without a wired client, the leaver flow logs and
// returns without panicking. This is the cmd/ztna-api default
// today — the ZTNA business layer owns the OpenZiti integration
// out-of-band.
func TestHandleLeaver_NoOpenZitiClientIsNoop(t *testing.T) {
	db := newJMLTestDB(t)
	jml := NewJMLService(db, NewAccessProvisioningService(db))
	// Intentionally do NOT wire an OpenZiti client.

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER09"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}
}

// TestHandleLeaver_OpenZitiClientErrorDoesNotFailLeaver asserts the
// best-effort semantics documented on OpenZitiClient: a
// DisableIdentity error logs but does NOT roll back the leaver. By
// the time we reach the DisableIdentity branch, every grant has
// already been revoked and team memberships dropped, so the
// source-of-truth state is "deactivated"; the OpenZiti control
// plane reconciles eventually.
func TestHandleLeaver_OpenZitiClientErrorDoesNotFailLeaver(t *testing.T) {
	const provider = "mock_jml_leaver_ziti_err"
	db := newJMLTestDB(t)
	conn := seedConnectorWithID(t, db, "01H00000000000000JMLCONNZITIE", provider)
	team := seedJMLTeam(t, db, "01H00000000000000JMLTMZITIE", "team-ziti-err")

	mock := &MockAccessConnector{}
	SwapConnector(t, provider, mock)

	provSvc := NewAccessProvisioningService(db)
	jml := NewJMLService(db, provSvc)
	zClient := &stubOpenZitiClient{Err: errors.New("ziti controller unreachable")}
	jml.SetOpenZitiClient(zClient)

	if _, err := jml.HandleJoiner(context.Background(), JoinerInput{
		WorkspaceID: "01H000000000000000WORKSPACE",
		UserID:      "01H00000000000000JMLUSER10",
		TeamIDs:     []string{team.ID},
		DefaultGrants: []JMLAccessGrant{
			{ConnectorID: conn.ID, ResourceExternalID: "projects/z-2", Role: "viewer"},
		},
	}); err != nil {
		t.Fatalf("seed joiner: %v", err)
	}

	res, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01H00000000000000JMLUSER10")
	if err != nil {
		t.Fatalf("HandleLeaver: %v (writer failure must not surface as HandleLeaver error)", err)
	}
	if !res.AllOK() {
		t.Fatalf("AllOK = false; failed: %+v", res.Failed)
	}
	if got := zClient.Calls.Load(); got != 1 {
		t.Errorf("DisableIdentity calls = %d; want 1 (must dispatch even when controller errors)", got)
	}
}

// TestOpenZitiClientFunc_AdapterRoundTrip asserts the function
// adapter satisfies the interface and forwards args verbatim.
func TestOpenZitiClientFunc_AdapterRoundTrip(t *testing.T) {
	var seen string
	fn := OpenZitiClientFunc(func(_ context.Context, userExternalID string) error {
		seen = userExternalID
		return nil
	})
	var c OpenZitiClient = fn
	if err := c.DisableIdentity(context.Background(), "user-z"); err != nil {
		t.Fatalf("DisableIdentity: %v", err)
	}
	if seen != "user-z" {
		t.Errorf("seen = %q; want user-z", seen)
	}
}
