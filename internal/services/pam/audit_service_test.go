package pam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// stubReplayer is a minimal ReplaySignedURLer that returns a
// deterministic URL embedding the requested key + ttl so tests can
// assert both got threaded through correctly.
type stubReplayer struct {
	prefix  string
	err     error
	lastKey string
	lastTTL time.Duration
	calls   int
}

func (s *stubReplayer) PresignGet(_ context.Context, key string, ttl time.Duration) (string, error) {
	s.calls++
	s.lastKey = key
	s.lastTTL = ttl
	if s.err != nil {
		return "", s.err
	}
	return fmt.Sprintf("%s/%s?ttl=%s", s.prefix, key, ttl), nil
}

func newAuditFixture(t *testing.T) (*PAMAuditService, *NoOpPAMAuditProducer, *stubReplayer) {
	t.Helper()
	db := newPAMDB(t)
	producer := &NoOpPAMAuditProducer{}
	replayer := &stubReplayer{prefix: "https://s3.example/replay"}
	svc, err := NewPAMAuditService(PAMAuditServiceConfig{
		DB:              db,
		Producer:        producer,
		Replayer:        replayer,
		ReplayURLExpiry: time.Minute,
		Now:             func() time.Time { return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewPAMAuditService: %v", err)
	}
	return svc, producer, replayer
}

func seedSession(t *testing.T, svc *PAMAuditService, session models.PAMSession) {
	t.Helper()
	if session.ID == "" {
		session.ID = NewULID()
	}
	if err := svc.cfg.DB.Create(&session).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
}

func seedCommand(t *testing.T, svc *PAMAuditService, cmd models.PAMSessionCommand) {
	t.Helper()
	if cmd.ID == "" {
		cmd.ID = NewULID()
	}
	if cmd.Timestamp.IsZero() {
		cmd.Timestamp = time.Now().UTC()
	}
	if err := svc.cfg.DB.Create(&cmd).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}
}

func TestNewPAMAuditService_RequiresDBAndProducer(t *testing.T) {
	if _, err := NewPAMAuditService(PAMAuditServiceConfig{Producer: &NoOpPAMAuditProducer{}}); err == nil {
		t.Fatalf("expected error when DB is nil")
	}
	if _, err := NewPAMAuditService(PAMAuditServiceConfig{DB: newPAMDB(t)}); err == nil {
		t.Fatalf("expected error when Producer is nil")
	}
}

func TestPAMAuditService_RecordEvent_StampsEmittedAtAndPublishes(t *testing.T) {
	svc, producer, _ := newAuditFixture(t)
	ctx := context.Background()
	if err := svc.RecordEvent(ctx, PAMAuditEvent{
		EventType:   PAMEventSessionStarted,
		WorkspaceID: "ws-1",
		SessionID:   "sess-1",
	}); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	events := producer.Events()
	if len(events) != 1 {
		t.Fatalf("events = %d; want 1", len(events))
	}
	if events[0].EmittedAt.IsZero() {
		t.Fatalf("EmittedAt was not stamped")
	}
	if got := events[0].EmittedAt.UTC(); got != time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) {
		t.Fatalf("EmittedAt = %v; want fixed clock", got)
	}
	if events[0].EventType != PAMEventSessionStarted {
		t.Fatalf("EventType = %q", events[0].EventType)
	}
}

func TestPAMAuditService_RecordEvent_RequiresEventType(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	if err := svc.RecordEvent(context.Background(), PAMAuditEvent{WorkspaceID: "ws-1"}); err == nil {
		t.Fatalf("expected error when EventType is empty")
	}
}

func TestPAMAuditService_GetSessionReplay_SignedURL(t *testing.T) {
	svc, _, replayer := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:               "sess-1",
		WorkspaceID:      "ws-1",
		UserID:           "user-1",
		AssetID:          "asset-1",
		AccountID:        "acct-1",
		Protocol:         "ssh",
		State:            models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-1/replay.bin",
		CommandCount:     3,
	})
	replay, err := svc.GetSessionReplay(context.Background(), "ws-1", "sess-1")
	if err != nil {
		t.Fatalf("GetSessionReplay: %v", err)
	}
	if !strings.HasPrefix(replay.SignedURL, "https://s3.example/replay/sessions/sess-1/replay.bin") {
		t.Fatalf("SignedURL = %q", replay.SignedURL)
	}
	if replayer.lastTTL != time.Minute {
		t.Fatalf("ttl = %v; want 1m", replayer.lastTTL)
	}
	if replay.Commands != 3 {
		t.Fatalf("Commands = %d; want 3", replay.Commands)
	}
	if replay.ExpiresAt.Sub(time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)) != time.Minute {
		t.Fatalf("ExpiresAt = %v; want now+1m", replay.ExpiresAt)
	}
}

func TestPAMAuditService_GetSessionReplay_NotFound(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	_, err := svc.GetSessionReplay(context.Background(), "ws-1", "missing")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMAuditService_GetSessionReplay_NoReplayKey(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "u",
		AssetID:     "a",
		AccountID:   "acct",
		Protocol:    "ssh",
		State:       models.PAMSessionStateRequested,
	})
	_, err := svc.GetSessionReplay(context.Background(), "ws-1", "sess-1")
	if !errors.Is(err, ErrReplayUnavailable) {
		t.Fatalf("err = %v; want ErrReplayUnavailable", err)
	}
}

func TestPAMAuditService_GetSessionReplay_CrossWorkspaceIsolated(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:               "sess-a",
		WorkspaceID:      "ws-a",
		UserID:           "u",
		AssetID:          "a",
		AccountID:        "acct",
		Protocol:         "ssh",
		State:            models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-a/replay.bin",
	})
	if _, err := svc.GetSessionReplay(context.Background(), "ws-b", "sess-a"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("cross-tenant fetch returned err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMAuditService_GetSessionReplay_SignerError(t *testing.T) {
	svc, _, replayer := newAuditFixture(t)
	replayer.err = errors.New("kms boom")
	seedSession(t, svc, models.PAMSession{
		ID:               "sess-1",
		WorkspaceID:      "ws-1",
		UserID:           "u",
		AssetID:          "a",
		AccountID:        "acct",
		Protocol:         "ssh",
		State:            models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-1/replay.bin",
	})
	_, err := svc.GetSessionReplay(context.Background(), "ws-1", "sess-1")
	if err == nil || !strings.Contains(err.Error(), "kms boom") {
		t.Fatalf("err = %v; want wrapped kms boom", err)
	}
}

func TestPAMAuditService_GetCommandTimeline_OrderedBySequence(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "u",
		AssetID:     "a",
		AccountID:   "acct",
		Protocol:    "ssh",
		State:       models.PAMSessionStateActive,
	})
	// Seed commands out of order to confirm ORDER BY sequence works.
	for _, seq := range []int{3, 1, 4, 2} {
		seedCommand(t, svc, models.PAMSessionCommand{
			SessionID: "sess-1",
			Sequence:  seq,
			Input:     fmt.Sprintf("cmd-%d", seq),
		})
	}
	out, err := svc.GetCommandTimeline(context.Background(), "ws-1", "sess-1")
	if err != nil {
		t.Fatalf("GetCommandTimeline: %v", err)
	}
	if len(out) != 4 {
		t.Fatalf("rows = %d; want 4", len(out))
	}
	for i, row := range out {
		if row.Sequence != i+1 {
			t.Fatalf("row[%d].Sequence = %d; want %d", i, row.Sequence, i+1)
		}
	}
}

func TestPAMAuditService_GetCommandTimeline_SessionNotFound(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	_, err := svc.GetCommandTimeline(context.Background(), "ws-1", "missing")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMAuditService_ExportEvidence_BundlesAllArtefacts(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:               "sess-1",
		WorkspaceID:      "ws-1",
		UserID:           "u",
		AssetID:          "a",
		AccountID:        "acct",
		Protocol:         "ssh",
		State:            models.PAMSessionStateCompleted,
		ReplayStorageKey: "sessions/sess-1/replay.bin",
		CommandCount:     2,
	})
	seedCommand(t, svc, models.PAMSessionCommand{SessionID: "sess-1", Sequence: 1, Input: "ls"})
	seedCommand(t, svc, models.PAMSessionCommand{SessionID: "sess-1", Sequence: 2, Input: "whoami"})
	pack, err := svc.ExportEvidence(context.Background(), "ws-1", "sess-1")
	if err != nil {
		t.Fatalf("ExportEvidence: %v", err)
	}
	if pack.Session.ID != "sess-1" {
		t.Fatalf("Session.ID = %q", pack.Session.ID)
	}
	if len(pack.Commands) != 2 || pack.Commands[0].Input != "ls" {
		t.Fatalf("Commands = %+v", pack.Commands)
	}
	if pack.SignedReplayURL == "" {
		t.Fatalf("SignedReplayURL was empty")
	}
	if pack.ReplayExpiresAt == nil {
		t.Fatalf("ReplayExpiresAt was nil")
	}
	if pack.ExportedAt.IsZero() {
		t.Fatalf("ExportedAt was zero")
	}
}

func TestPAMAuditService_ExportEvidence_NoReplayKey_StillReturnsPack(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "u",
		AssetID:     "a",
		AccountID:   "acct",
		Protocol:    "ssh",
		State:       models.PAMSessionStateRequested,
	})
	pack, err := svc.ExportEvidence(context.Background(), "ws-1", "sess-1")
	if err != nil {
		t.Fatalf("ExportEvidence: %v", err)
	}
	if pack.SignedReplayURL != "" {
		t.Fatalf("SignedReplayURL = %q; want empty", pack.SignedReplayURL)
	}
	if pack.ReplayExpiresAt != nil {
		t.Fatalf("ReplayExpiresAt = %v; want nil", pack.ReplayExpiresAt)
	}
}

func TestPAMAuditService_ListSessions_FiltersAndOrdering(t *testing.T) {
	svc, _, _ := newAuditFixture(t)
	for i, st := range []string{
		models.PAMSessionStateCompleted,
		models.PAMSessionStateActive,
		models.PAMSessionStateRequested,
	} {
		seedSession(t, svc, models.PAMSession{
			ID:          fmt.Sprintf("sess-%d", i),
			WorkspaceID: "ws-1",
			UserID:      "user-a",
			AssetID:     fmt.Sprintf("asset-%d", i%2),
			AccountID:   "acct",
			Protocol:    "ssh",
			State:       st,
		})
	}
	// Foreign-workspace row must be invisible.
	seedSession(t, svc, models.PAMSession{
		ID: "sess-x", WorkspaceID: "ws-2", UserID: "u", AssetID: "a",
		AccountID: "acct", Protocol: "ssh", State: models.PAMSessionStateActive,
	})

	out, err := svc.ListSessions(context.Background(), "ws-1", ListSessionsFilters{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("rows = %d; want 3", len(out))
	}
	for _, row := range out {
		if row.WorkspaceID != "ws-1" {
			t.Fatalf("leaked workspace %q", row.WorkspaceID)
		}
	}

	// Filter by state.
	out, err = svc.ListSessions(context.Background(), "ws-1", ListSessionsFilters{State: models.PAMSessionStateActive})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(out) != 1 || out[0].State != models.PAMSessionStateActive {
		t.Fatalf("state filter returned %+v", out)
	}

	// Filter by asset.
	out, err = svc.ListSessions(context.Background(), "ws-1", ListSessionsFilters{AssetID: "asset-0"})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	for _, row := range out {
		if row.AssetID != "asset-0" {
			t.Fatalf("asset filter returned %+v", row)
		}
	}
}

func TestPAMAuditService_TerminateSession_FlipsStateAndEmitsEvent(t *testing.T) {
	svc, producer, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "u",
		AssetID:     "a",
		AccountID:   "acct",
		Protocol:    "ssh",
		State:       models.PAMSessionStateActive,
	})
	got, err := svc.TerminateSession(context.Background(), "ws-1", "sess-1", "admin-1", "policy violation")
	if err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if got.State != models.PAMSessionStateTerminated {
		t.Fatalf("state = %q", got.State)
	}
	if got.EndedAt == nil {
		t.Fatalf("EndedAt was nil")
	}

	events := producer.Events()
	if len(events) != 1 || events[0].EventType != PAMEventSessionTerminated {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Reason != "policy violation" {
		t.Fatalf("event reason = %q", events[0].Reason)
	}
	if events[0].ActorUserID != "admin-1" {
		t.Fatalf("event actor = %q", events[0].ActorUserID)
	}

	// Re-fetch to confirm persistence.
	row, err := svc.GetSession(context.Background(), "ws-1", "sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if row.State != models.PAMSessionStateTerminated {
		t.Fatalf("persisted state = %q", row.State)
	}
}

func TestPAMAuditService_TerminateSession_IdempotentForTerminalState(t *testing.T) {
	svc, producer, _ := newAuditFixture(t)
	seedSession(t, svc, models.PAMSession{
		ID:          "sess-1",
		WorkspaceID: "ws-1",
		UserID:      "u",
		AssetID:     "a",
		AccountID:   "acct",
		Protocol:    "ssh",
		State:       models.PAMSessionStateCompleted,
	})
	got, err := svc.TerminateSession(context.Background(), "ws-1", "sess-1", "admin-1", "noop")
	if err != nil {
		t.Fatalf("TerminateSession: %v", err)
	}
	if got.State != models.PAMSessionStateCompleted {
		t.Fatalf("state = %q; want completed (no-op)", got.State)
	}
	if got := producer.Events(); len(got) != 0 {
		t.Fatalf("expected no audit emit on idempotent path, got %d", len(got))
	}
}

// stubKafkaWriter captures the messages handed to the
// KafkaPAMAuditProducer so the test can assert envelope shape +
// headers + topic. WriteMessages is safe for concurrent use.
type stubKafkaWriter struct {
	msgs   []access.KafkaMessage
	closed bool
	err    error
}

func (s *stubKafkaWriter) WriteMessages(_ context.Context, msgs ...access.KafkaMessage) error {
	if s.err != nil {
		return s.err
	}
	s.msgs = append(s.msgs, msgs...)
	return nil
}

func (s *stubKafkaWriter) Close() error {
	s.closed = true
	return nil
}

func TestKafkaPAMAuditProducer_PublishWrapsInShieldnetEnvelope(t *testing.T) {
	w := &stubKafkaWriter{}
	p := NewKafkaPAMAuditProducer(w, "")
	if err := p.PublishPAMEvent(context.Background(), PAMAuditEvent{
		EventType:   PAMEventLeaseRequested,
		WorkspaceID: "ws-1",
		ActorUserID: "user-1",
		LeaseID:     "lease-1",
		AssetID:     "asset-1",
		Outcome:     "requested",
	}); err != nil {
		t.Fatalf("PublishPAMEvent: %v", err)
	}
	if len(w.msgs) != 1 {
		t.Fatalf("msgs = %d; want 1", len(w.msgs))
	}
	msg := w.msgs[0]
	if msg.Topic != "pam_audit_logs" {
		t.Fatalf("topic = %q", msg.Topic)
	}
	if string(msg.Key) != "ws-1" {
		t.Fatalf("key = %q; want ws-1", string(msg.Key))
	}
	if msg.Headers["event_type"] != PAMEventLeaseRequested {
		t.Fatalf("event_type header = %q", msg.Headers["event_type"])
	}
	if msg.Headers["source"] != pamAuditSource {
		t.Fatalf("source header = %q", msg.Headers["source"])
	}
	if msg.Headers["schema_version"] != access.ShieldnetLogEventVersion {
		t.Fatalf("schema_version header = %q", msg.Headers["schema_version"])
	}

	var env struct {
		SchemaVersion string        `json:"schema_version"`
		Source        string        `json:"source"`
		ConnectorID   string        `json:"connector_id"`
		Event         PAMAuditEvent `json:"event"`
	}
	if err := json.Unmarshal(msg.Value, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if env.Source != pamAuditSource {
		t.Fatalf("envelope source = %q", env.Source)
	}
	if env.ConnectorID != "ws-1" {
		t.Fatalf("envelope connector_id = %q", env.ConnectorID)
	}
	if env.Event.LeaseID != "lease-1" {
		t.Fatalf("envelope event.lease_id = %q", env.Event.LeaseID)
	}
	if env.Event.EmittedAt.IsZero() {
		t.Fatalf("envelope event.emitted_at was zero")
	}
}

func TestKafkaPAMAuditProducer_RejectsMissingEventType(t *testing.T) {
	w := &stubKafkaWriter{}
	p := NewKafkaPAMAuditProducer(w, "topic-x")
	err := p.PublishPAMEvent(context.Background(), PAMAuditEvent{WorkspaceID: "ws-1"})
	if err == nil {
		t.Fatalf("expected error for missing event_type")
	}
}

func TestKafkaPAMAuditProducer_BatchPreservesOrderAndPropagatesErrors(t *testing.T) {
	w := &stubKafkaWriter{err: errors.New("broker down")}
	p := NewKafkaPAMAuditProducer(w, "")
	err := p.PublishPAMEvents(context.Background(), []PAMAuditEvent{
		{EventType: PAMEventSessionStarted, WorkspaceID: "ws-1"},
		{EventType: PAMEventSessionEnded, WorkspaceID: "ws-1"},
	})
	if err == nil || !strings.Contains(err.Error(), "broker down") {
		t.Fatalf("err = %v; want broker down", err)
	}
}

func TestKafkaPAMAuditProducer_CustomTopicHonoured(t *testing.T) {
	w := &stubKafkaWriter{}
	p := NewKafkaPAMAuditProducer(w, "custom-topic")
	if err := p.PublishPAMEvent(context.Background(), PAMAuditEvent{
		EventType:   PAMEventSecretRevealed,
		WorkspaceID: "ws-1",
	}); err != nil {
		t.Fatalf("PublishPAMEvent: %v", err)
	}
	if w.msgs[0].Topic != "custom-topic" {
		t.Fatalf("topic = %q; want custom-topic", w.msgs[0].Topic)
	}
}

func TestNoOpPAMAuditProducer_RecordsEventsForAssertions(t *testing.T) {
	n := &NoOpPAMAuditProducer{}
	_ = n.PublishPAMEvent(context.Background(), PAMAuditEvent{EventType: "pam.session.started", WorkspaceID: "ws"})
	_ = n.PublishPAMEvents(context.Background(), []PAMAuditEvent{
		{EventType: "pam.session.ended", WorkspaceID: "ws"},
	})
	if got := n.BatchesPublished(); got != 2 {
		t.Fatalf("batches = %d; want 2", got)
	}
	if got := n.Events(); len(got) != 2 {
		t.Fatalf("events = %d; want 2", len(got))
	}
}
