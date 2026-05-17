package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/pam"
)

// auditStubReplayer is a minimal ReplaySignedURLer for handler tests
// that returns a deterministic URL embedding the requested key so
// tests can assert the wiring without dragging an S3 SDK in.
type auditStubReplayer struct {
	prefix string
}

func (s *auditStubReplayer) PresignGet(_ context.Context, key string, ttl time.Duration) (string, error) {
	return fmt.Sprintf("%s/%s?ttl=%s", s.prefix, key, ttl), nil
}

// newPAMAuditEngine wires a router with only the PAMAuditService
// dependency bound. The producer is a no-op so the audit-emit calls
// inside TerminateSession do not require a Kafka broker.
func newPAMAuditEngine(t *testing.T) (http.Handler, *pam.PAMAuditService, *gorm.DB) {
	t.Helper()
	db := newTestDB(t)
	svc, err := pam.NewPAMAuditService(pam.PAMAuditServiceConfig{
		DB:              db,
		Producer:        &pam.NoOpPAMAuditProducer{},
		Replayer:        &auditStubReplayer{prefix: "https://s3.example/replay"},
		ReplayURLExpiry: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewPAMAuditService: %v", err)
	}
	r := Router(Dependencies{PAMAuditService: svc, DisableRateLimiter: true})
	return r, svc, db
}

func seedAuditSession(t *testing.T, db *gorm.DB, session models.PAMSession) {
	t.Helper()
	if session.ID == "" {
		session.ID = pam.NewULID()
	}
	if err := db.Create(&session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func seedAuditCommand(t *testing.T, db *gorm.DB, cmd models.PAMSessionCommand) {
	t.Helper()
	if cmd.ID == "" {
		cmd.ID = pam.NewULID()
	}
	if cmd.Timestamp.IsZero() {
		cmd.Timestamp = time.Now().UTC()
	}
	if err := db.Create(&cmd).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
}

func TestPAMAuditHandler_ListSessions_RequiresWorkspaceID(t *testing.T) {
	r, _, _ := newPAMAuditEngine(t)
	w := doJSON(t, r, http.MethodGet, "/pam/sessions", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s; want 400", w.Code, w.Body.String())
	}
}

func TestPAMAuditHandler_ListSessions_FiltersByState(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-2", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateCompleted,
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions?workspace_id=ws-1&state=active", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.PAMSession
	decodeJSON(t, w, &got)
	if len(got) != 1 || got[0].State != models.PAMSessionStateActive {
		t.Fatalf("filter returned %+v", got)
	}
}

func TestPAMAuditHandler_GetSession_HappyPath(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
}

func TestPAMAuditHandler_GetSession_CrossWorkspaceReturns404(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-a", WorkspaceID: "ws-a", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-a?workspace_id=ws-other", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

func TestPAMAuditHandler_GetReplay_HappyPath(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-1/replay.bin",
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1/replay?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got pam.SessionReplay
	decodeJSON(t, w, &got)
	if !strings.HasPrefix(got.SignedURL, "https://s3.example/replay/sessions/sess-1/replay.bin") {
		t.Fatalf("SignedURL = %q", got.SignedURL)
	}
}

func TestPAMAuditHandler_GetReplay_NoReplayKeyReturns409(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateRequested,
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1/replay?workspace_id=ws-1", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s; want 409", w.Code, w.Body.String())
	}
}

func TestPAMAuditHandler_GetReplay_NotFoundReturns404(t *testing.T) {
	r, _, _ := newPAMAuditEngine(t)
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/missing/replay?workspace_id=ws-1", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

func TestPAMAuditHandler_GetCommands_HappyPath(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	for _, seq := range []int{2, 1, 3} {
		seedAuditCommand(t, db, models.PAMSessionCommand{
			SessionID: "sess-1", Sequence: seq, Input: fmt.Sprintf("cmd-%d", seq),
		})
	}
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1/commands?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got []models.PAMSessionCommand
	decodeJSON(t, w, &got)
	if len(got) != 3 {
		t.Fatalf("rows = %d; want 3", len(got))
	}
	if got[0].Sequence != 1 || got[1].Sequence != 2 || got[2].Sequence != 3 {
		t.Fatalf("unordered timeline: %+v", got)
	}
}

func TestPAMAuditHandler_GetCommands_CrossWorkspaceReturns404(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1/commands?workspace_id=ws-other", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}

func TestPAMAuditHandler_GetEvidence_HappyPath(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-1/replay.bin",
	})
	seedAuditCommand(t, db, models.PAMSessionCommand{
		SessionID: "sess-1", Sequence: 1, Input: "whoami",
	})
	w := doJSON(t, r, http.MethodGet, "/pam/sessions/sess-1/evidence?workspace_id=ws-1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var pack pam.EvidencePack
	decodeJSON(t, w, &pack)
	if pack.Session.ID != "sess-1" {
		t.Fatalf("Session.ID = %q", pack.Session.ID)
	}
	if len(pack.Commands) != 1 || pack.Commands[0].Input != "whoami" {
		t.Fatalf("Commands = %+v", pack.Commands)
	}
	if pack.SignedReplayURL == "" {
		t.Fatal("SignedReplayURL was empty")
	}
}

func TestPAMAuditHandler_TerminateSession_HappyPath(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-1", WorkspaceID: "ws-1", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	w := doJSON(t, r, http.MethodPost, "/pam/sessions/sess-1/terminate", map[string]interface{}{
		"workspace_id":  "ws-1",
		"actor_user_id": "admin-1",
		"reason":        "policy violation",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Code, w.Body.String())
	}
	var got models.PAMSession
	decodeJSON(t, w, &got)
	if got.State != models.PAMSessionStateTerminated {
		t.Fatalf("state = %q; want terminated", got.State)
	}
}

func TestPAMAuditHandler_TerminateSession_RejectsMissingWorkspaceOrActor(t *testing.T) {
	r, _, _ := newPAMAuditEngine(t)
	tests := []struct {
		name string
		body map[string]interface{}
	}{
		{"missing workspace", map[string]interface{}{"actor_user_id": "a"}},
		{"missing actor", map[string]interface{}{"workspace_id": "ws-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := doJSON(t, r, http.MethodPost, "/pam/sessions/sess-1/terminate", tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400", w.Code)
			}
		})
	}
}

func TestPAMAuditHandler_TerminateSession_CrossWorkspaceReturns404(t *testing.T) {
	r, _, db := newPAMAuditEngine(t)
	seedAuditSession(t, db, models.PAMSession{
		ID: "sess-a", WorkspaceID: "ws-a", UserID: "u", AssetID: "a", AccountID: "acct",
		Protocol: "ssh", State: models.PAMSessionStateActive,
	})
	w := doJSON(t, r, http.MethodPost, "/pam/sessions/sess-a/terminate", map[string]interface{}{
		"workspace_id":  "ws-other",
		"actor_user_id": "admin",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", w.Code)
	}
}
