//go:build integration

package access

import (
	"context"
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestOrphanReconciler_DetectAndRevoke_Integration seeds a
// workspace with 2 connectors, each returning 5 upstream identities
// from a mocked SyncIdentities, and team_members rows for 4 of the
// 5 identities (so each connector contributes exactly 1 orphan).
// It then drives ReconcileWorkspace + RevokeOrphan end-to-end and
// asserts the resulting access_orphan_accounts rows.
func TestOrphanReconciler_DetectAndRevoke_Integration(t *testing.T) {
	const (
		ws    = "01H000000000000000WORKSPACE"
		teamID = "01HTEAMINTORPHANS00000001"
		userPrefix = "01HUSERINTORPHANS0000000"
		provA = "mock_int_orphan_a"
		provB = "mock_int_orphan_b"
	)

	db := newJMLTestDB(t)
	if err := db.AutoMigrate(&models.AccessOrphanAccount{}); err != nil {
		t.Fatalf("automigrate orphan: %v", err)
	}
	connA := seedConnectorWithSecrets(t, db, "01HCONNINTORPHANS000000A01", provA)
	connB := seedConnectorWithSecrets(t, db, "01HCONNINTORPHANS000000B01", provB)

	emit5 := func(connectorTag string) *MockAccessConnector {
		return &MockAccessConnector{
			FuncSyncIdentities: func(_ context.Context, _, _ map[string]interface{}, _ string, h func([]*Identity, string) error) error {
				return h([]*Identity{
					{ExternalID: connectorTag + "-u1"},
					{ExternalID: connectorTag + "-u2"},
					{ExternalID: connectorTag + "-u3"},
					{ExternalID: connectorTag + "-u4"},
					{ExternalID: connectorTag + "-u5"}, // orphan
				}, "")
			},
		}
	}
	SwapConnector(t, provA, emit5("a"))
	SwapConnector(t, provB, emit5("b"))

	// Seed team_members for 4 of 5 users on each connector. The
	// fifth (u5) is the orphan on each.
	for i, c := range []*models.AccessConnector{connA, connB} {
		tag := "a"
		if i == 1 {
			tag = "b"
		}
		for j := 1; j <= 4; j++ {
			if err := db.Create(&models.TeamMember{
				ID:          "01HTMINTORPHANS00000" + string(rune('A'+i)) + string(rune('0'+j)) + "ZZZ",
				TeamID:      teamID,
				UserID:      userPrefix + string(rune('A'+i)) + string(rune('0'+j)),
				ExternalID:  tag + "-u" + string(rune('0'+j)),
				ConnectorID: c.ID,
			}).Error; err != nil {
				t.Fatalf("seed team_member: %v", err)
			}
		}
	}

	rec := NewOrphanReconciler(db, NewAccessProvisioningService(db), NewConnectorCredentialsLoader(db, PassthroughEncryptor{}))
	rec.SetPerConnectorDelay(0)

	got, err := rec.ReconcileWorkspace(context.Background(), ws)
	if err != nil {
		t.Fatalf("ReconcileWorkspace: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("orphan detections = %d; want 2 (one per connector)", len(got))
	}

	var persisted []models.AccessOrphanAccount
	if err := db.Find(&persisted).Error; err != nil {
		t.Fatalf("list orphan rows: %v", err)
	}
	if len(persisted) != 2 {
		t.Fatalf("persisted orphan rows = %d; want 2", len(persisted))
	}
	for _, r := range persisted {
		if r.Status != models.OrphanStatusDetected {
			t.Errorf("orphan %s status = %q; want %q", r.UserExternalID, r.Status, models.OrphanStatusDetected)
		}
	}

	// Revoke each orphan and assert it transitions to auto_revoked.
	for _, r := range persisted {
		if err := rec.RevokeOrphan(context.Background(), r.ID); err != nil {
			t.Fatalf("RevokeOrphan %s: %v", r.ID, err)
		}
	}
	var revoked []models.AccessOrphanAccount
	if err := db.Find(&revoked).Error; err != nil {
		t.Fatalf("list revoked: %v", err)
	}
	for _, r := range revoked {
		if r.Status != models.OrphanStatusAutoRevoked {
			t.Errorf("orphan %s status post-revoke = %q; want %q", r.UserExternalID, r.Status, models.OrphanStatusAutoRevoked)
		}
	}
}
