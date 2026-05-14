package access

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// captureAuditProducer records every PublishAccessAuditLogs invocation.
// The Phase 11 leaver kill-switch audit trail tests assert that one
// event per kill-switch layer is emitted (success / failed / skipped).
type captureAuditProducer struct {
	mu      sync.Mutex
	entries []*AuditLogEntry
	keys    []string
	err     error
}

func (c *captureAuditProducer) PublishAccessAuditLogs(_ context.Context, connectorID string, entries []*AuditLogEntry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.entries = append(c.entries, entries...)
	for range entries {
		c.keys = append(c.keys, connectorID)
	}
	return nil
}

func (c *captureAuditProducer) Close() error { return nil }

func (c *captureAuditProducer) snapshot() []*AuditLogEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*AuditLogEntry, len(c.entries))
	copy(out, c.entries)
	return out
}

func layersByStatus(entries []*AuditLogEntry) map[LeaverStatus]map[LeaverLayer]int {
	out := map[LeaverStatus]map[LeaverLayer]int{}
	for _, e := range entries {
		status, _ := e.RawData["status"].(string)
		layer, _ := e.RawData["layer"].(string)
		if _, ok := out[LeaverStatus(status)]; !ok {
			out[LeaverStatus(status)] = map[LeaverLayer]int{}
		}
		out[LeaverStatus(status)][LeaverLayer(layer)]++
	}
	return out
}

// TestHandleLeaver_EmitsOneAuditEventPerLayer asserts the full
// kill-switch run with all hooks wired emits a LeaverKillSwitchEvent
// for each layer (grant_revoke / team_remove / keycloak_disable /
// session_revoke / scim_deprovision / openziti_disable) with
// status=success.
func TestHandleLeaver_EmitsOneAuditEventPerLayer(t *testing.T) {
	const provider = "mock_jml_audit_ok"
	db := newJMLTestDB(t)
	conn := seedConnectorWithSecrets(t, db, "01HCONN0AUDIT00000000000001", provider)

	revoker := &stubSessionRevokerConnector{MockAccessConnector: &MockAccessConnector{}}
	SwapConnector(t, provider, revoker)

	if err := db.Create(&models.TeamMember{
		ID:          "01HTM0AUDIT0000000000000001",
		TeamID:      "01HTEAM0AUDIT000000000000001",
		UserID:      "01HUSER0AUDIT000000000000001",
		ExternalID:  "okta-id-audit",
		ConnectorID: conn.ID,
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	zClient := &stubOpenZitiClient{}
	jml.SetOpenZitiClient(zClient)
	admin := &stubKeycloakAdmin{mockKeycloakClient: newMockKeycloak()}
	jml.SetSSOFederationService(NewSSOFederationService(admin))
	jml.SetConnectorCredentialsLoader(NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))

	cap := &captureAuditProducer{}
	jml.SetAuditProducer(cap)

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0AUDIT000000000000001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}

	got := layersByStatus(cap.snapshot())
	want := []LeaverLayer{
		LeaverLayerTeamRemove,
		LeaverLayerKeycloakDisable,
		LeaverLayerSessionRevoke,
		LeaverLayerOpenZitiDisable,
	}
	for _, l := range want {
		if got[LeaverStatusSuccess][l] != 1 {
			t.Errorf("layer %s success count = %d; want 1", l, got[LeaverStatusSuccess][l])
		}
	}
	// scim_deprovision is skipped because the mock connector doesn't
	// implement SCIMProvisioner.
	if got[LeaverStatusSkipped][LeaverLayerSCIMDeprovision] != 1 {
		t.Errorf("layer %s skipped count = %d; want 1",
			LeaverLayerSCIMDeprovision,
			got[LeaverStatusSkipped][LeaverLayerSCIMDeprovision])
	}
}

// TestHandleLeaver_EmitsFailedEventOnLayerError asserts that a
// connector-side RevokeUserSessions error produces a session_revoke
// event with status=failed and the error message populated.
func TestHandleLeaver_EmitsFailedEventOnLayerError(t *testing.T) {
	const provider = "mock_jml_audit_err"
	db := newJMLTestDB(t)
	conn := seedConnectorWithSecrets(t, db, "01HCONN0AUDITERR000000000001", provider)

	revoker := &stubSessionRevokerConnector{
		MockAccessConnector: &MockAccessConnector{},
		Err:                 errors.New("upstream boom"),
	}
	SwapConnector(t, provider, revoker)

	if err := db.Create(&models.TeamMember{
		ID:          "01HTM0AUDITERR000000000000001",
		TeamID:      "01HTEAM0AUDITERR000000000001",
		UserID:      "01HUSER0AUDITERR000000000001",
		ExternalID:  "okta-id-err",
		ConnectorID: conn.ID,
	}).Error; err != nil {
		t.Fatalf("seed team_member: %v", err)
	}

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	jml.SetConnectorCredentialsLoader(NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	cap := &captureAuditProducer{}
	jml.SetAuditProducer(cap)

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0AUDITERR000000000001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}

	var sessionFailures int
	var sawErrorMsg bool
	for _, e := range cap.snapshot() {
		layer, _ := e.RawData["layer"].(string)
		status, _ := e.RawData["status"].(string)
		if LeaverLayer(layer) == LeaverLayerSessionRevoke && LeaverStatus(status) == LeaverStatusFailed {
			sessionFailures++
			if msg, ok := e.RawData["error"].(string); ok && msg == "upstream boom" {
				sawErrorMsg = true
			}
		}
	}
	if sessionFailures != 1 {
		t.Errorf("session_revoke failed count = %d; want 1", sessionFailures)
	}
	if !sawErrorMsg {
		t.Error("session_revoke failed event did not carry error=\"upstream boom\"")
	}
}

// TestHandleLeaver_EmitsSkippedEventWhenHookNotWired asserts that
// unwired layers (no Keycloak / OpenZiti hook) produce skipped
// events instead of being dropped.
func TestHandleLeaver_EmitsSkippedEventWhenHookNotWired(t *testing.T) {
	const provider = "mock_jml_audit_skip"
	db := newJMLTestDB(t)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0AUDITSKIP000000000001", provider)
	SwapConnector(t, provider, &MockAccessConnector{})

	jml := NewJMLService(db, NewAccessProvisioningService(db))
	cap := &captureAuditProducer{}
	jml.SetAuditProducer(cap)

	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0AUDITSKIP00000000001"); err != nil {
		t.Fatalf("HandleLeaver: %v", err)
	}

	got := layersByStatus(cap.snapshot())
	for _, l := range []LeaverLayer{
		LeaverLayerKeycloakDisable,
		LeaverLayerSessionRevoke,
		LeaverLayerSCIMDeprovision,
		LeaverLayerOpenZitiDisable,
	} {
		if got[LeaverStatusSkipped][l] != 1 {
			t.Errorf("layer %s skipped count = %d; want 1", l, got[LeaverStatusSkipped][l])
		}
	}
}

// TestHandleLeaver_NoAuditProducerIsNoOp asserts that HandleLeaver
// works without an AuditProducer wired — emitLeaverEvent is a
// no-op so dev / test binaries do not need Kafka.
func TestHandleLeaver_NoAuditProducerIsNoOp(t *testing.T) {
	const provider = "mock_jml_audit_nopub"
	db := newJMLTestDB(t)
	_ = seedConnectorWithSecrets(t, db, "01HCONN0AUDITNOPUB000000001", provider)
	SwapConnector(t, provider, &MockAccessConnector{})
	jml := NewJMLService(db, NewAccessProvisioningService(db))
	if _, err := jml.HandleLeaver(context.Background(), "01H000000000000000WORKSPACE", "01HUSER0AUDITNOPUB00000001"); err != nil {
		t.Fatalf("HandleLeaver without audit producer: %v", err)
	}
}
