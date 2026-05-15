package access

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"

	"gorm.io/datatypes"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// stubOpenZitiEventWriter is the Phase 11 richer-event writer test
// double. It implements BOTH OpenZitiPolicyWriter (legacy narrow
// contract) and OpenZitiPolicyEventWriter (the new docs/PROPOSAL
// §13 contract) so PolicyService.Promote should prefer the richer
// interface and never call the narrow one.
type stubOpenZitiEventWriter struct {
	NarrowCalls atomic.Int64
	EventCalls  atomic.Int64
	LastEvent   *PolicyPromotionEvent
	NarrowErr   error
	EventErr    error
}

func (s *stubOpenZitiEventWriter) WriteServicePolicy(_ context.Context, _ *models.Policy) error {
	s.NarrowCalls.Add(1)
	return s.NarrowErr
}

func (s *stubOpenZitiEventWriter) WriteServicePolicyEvent(_ context.Context, event *PolicyPromotionEvent) error {
	s.EventCalls.Add(1)
	s.LastEvent = event
	return s.EventErr
}

// TestPolicyService_Promote_EmitsEventWithWorkspaceAccessModes is
// the Phase 11 (docs/overview.md §13) integration test. When the
// configured writer implements OpenZitiPolicyEventWriter the
// service must:
//
//  1. Collect the workspace's distinct access_mode values from
//     access_connectors (sorted, de-duplicated).
//  2. Invoke WriteServicePolicyEvent exactly once with the
//     promoted policy + the access-mode snapshot.
//  3. NOT invoke the legacy WriteServicePolicy on the same writer.
//
// The negative-space check is critical so a writer that opts in to
// the richer interface does not see two callbacks per promotion.
func TestPolicyService_Promote_EmitsEventWithWorkspaceAccessModes(t *testing.T) {
	db := newPhase3DB(t)
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate access_connectors: %v", err)
	}
	const ws = "01H000000000000000WORKSPACE"

	// Seed three connectors across two modes so the collector
	// must both de-dup and sort the result.
	rows := []models.AccessConnector{
		{
			ID: "01HCONN0PROMOTE0EVENT0001", WorkspaceID: ws,
			Provider: "p1", ConnectorType: "saas",
			Status: models.StatusConnected, AccessMode: models.AccessModeTunnel,
			Config: datatypes.JSON([]byte("{}")), KeyVersion: 1,
		},
		{
			ID: "01HCONN0PROMOTE0EVENT0002", WorkspaceID: ws,
			Provider: "p2", ConnectorType: "saas",
			Status: models.StatusConnected, AccessMode: models.AccessModeAPIOnly,
			Config: datatypes.JSON([]byte("{}")), KeyVersion: 1,
		},
		{
			ID: "01HCONN0PROMOTE0EVENT0003", WorkspaceID: ws,
			Provider: "p3", ConnectorType: "saas",
			Status: models.StatusConnected, AccessMode: models.AccessModeAPIOnly,
			Config: datatypes.JSON([]byte("{}")), KeyVersion: 1,
		},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seed connector %d: %v", i, err)
		}
	}

	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	writer := &stubOpenZitiEventWriter{}
	svc.SetOpenZitiPolicyWriter(writer)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	promoted, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     ")
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}

	if got := writer.EventCalls.Load(); got != 1 {
		t.Fatalf("EventCalls=%d; want 1", got)
	}
	if got := writer.NarrowCalls.Load(); got != 0 {
		t.Fatalf("NarrowCalls=%d; want 0 (richer writer should preempt legacy fallback)", got)
	}
	if writer.LastEvent == nil {
		t.Fatal("LastEvent is nil; want populated")
	}
	if writer.LastEvent.Policy == nil || writer.LastEvent.Policy.ID != promoted.ID {
		t.Fatalf("LastEvent.Policy mismatch: got %+v; want id %q",
			writer.LastEvent.Policy, promoted.ID)
	}
	want := []string{models.AccessModeAPIOnly, models.AccessModeTunnel}
	if !reflect.DeepEqual(writer.LastEvent.WorkspaceAccessModes, want) {
		t.Fatalf("WorkspaceAccessModes=%v; want %v", writer.LastEvent.WorkspaceAccessModes, want)
	}
}

// TestPolicyService_Promote_EventWriterEmptyAccessModes asserts the
// "no connectors in workspace" edge case: the event is still
// emitted (downstream consumers must know promotion happened),
// but WorkspaceAccessModes is an empty slice — not nil — so JSON
// callers see [] rather than null.
func TestPolicyService_Promote_EventWriterEmptyAccessModes(t *testing.T) {
	db := newPhase3DB(t)
	if err := db.AutoMigrate(&models.AccessConnector{}); err != nil {
		t.Fatalf("auto migrate access_connectors: %v", err)
	}
	const ws = "01H000000000000000WORKSPACE"

	seedTeam(t, db, ws, "team-eng", "Engineering", map[string]string{"department": "engineering"})
	seedTeamMember(t, db, "team-eng", "user-alice")
	seedResource(t, db, ws, "res-1", "prod-db-01", "ssh-host", nil)

	svc := NewPolicyService(db)
	writer := &stubOpenZitiEventWriter{}
	svc.SetOpenZitiPolicyWriter(writer)

	draft, err := svc.CreateDraft(context.Background(), validDraftInput(t))
	if err != nil {
		t.Fatalf("CreateDraft: %v", err)
	}
	if _, err := svc.Simulate(context.Background(), ws, draft.ID); err != nil {
		t.Fatalf("Simulate: %v", err)
	}
	if _, err := svc.Promote(context.Background(), ws, draft.ID, "01H000000000000000ADMIN     "); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if got := writer.EventCalls.Load(); got != 1 {
		t.Fatalf("EventCalls=%d; want 1 even when no connectors exist", got)
	}
	if writer.LastEvent == nil {
		t.Fatal("LastEvent is nil; want populated event")
	}
	if len(writer.LastEvent.WorkspaceAccessModes) != 0 {
		t.Fatalf("WorkspaceAccessModes len=%d; want 0", len(writer.LastEvent.WorkspaceAccessModes))
	}
}
