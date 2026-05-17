package pam

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// fakeRiskAssessor stubs PAMRiskAssessor for session-service tests
// without standing up the access-ai-agent. The default zero value
// reports the AI as unavailable; tests opt into specific verdicts by
// populating the fields below.
type fakeRiskAssessor struct {
	calls          int
	lastPayload    PAMSessionRiskPayload
	returnScore    string
	returnFactors  []string
	returnRec      string
	returnOK       bool
}

func (f *fakeRiskAssessor) AssessSessionRisk(
	_ context.Context,
	payload PAMSessionRiskPayload,
) (string, []string, string, bool) {
	f.calls++
	f.lastPayload = payload
	return f.returnScore, f.returnFactors, f.returnRec, f.returnOK
}

// fakeLeaseLookup stubs PAMLeaseLookup. The default zero value
// returns ErrLeaseNotFound; tests opt into a lease being present by
// populating Lease.
type fakeLeaseLookup struct {
	calls       int
	lastLeaseID string
	lease       *models.PAMLease
	err         error
}

func (f *fakeLeaseLookup) GetLease(_ context.Context, _, leaseID string) (*models.PAMLease, error) {
	f.calls++
	f.lastLeaseID = leaseID
	if f.err != nil {
		return nil, f.err
	}
	if f.lease == nil {
		return nil, ErrLeaseNotFound
	}
	return f.lease, nil
}

// newSessionFixture wires a PAMSessionService against an in-memory
// SQLite DB + NoOp producer + present-by-default lease lookup. The
// lease lookup is opt-out via SetLease(nil) so tests for the
// validation path can disable it.
func newSessionFixture(t *testing.T) (*PAMSessionService, *NoOpPAMAuditProducer, *fakeLeaseLookup, *fakeRiskAssessor) {
	t.Helper()
	db := newPAMDB(t)
	producer := &NoOpPAMAuditProducer{}
	lookup := &fakeLeaseLookup{lease: &models.PAMLease{
		ID:          "lease-1",
		WorkspaceID: "ws-1",
		UserID:      "user-1",
		AssetID:     "asset-1",
		AccountID:   "account-1",
	}}
	assessor := &fakeRiskAssessor{}
	svc, err := NewPAMSessionService(PAMSessionServiceConfig{
		DB:           db,
		LeaseLookup:  lookup,
		Producer:     producer,
		RiskAssessor: assessor,
		Now:          func() time.Time { return time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("NewPAMSessionService: %v", err)
	}
	return svc, producer, lookup, assessor
}

func defaultCreateInput() CreateSessionInput {
	return CreateSessionInput{
		UserID:      "user-1",
		AssetID:     "asset-1",
		AccountID:   "account-1",
		LeaseID:     "lease-1",
		Protocol:    "ssh",
		Criticality: "high",
	}
}

func TestNewPAMSessionService_RequiresDBAndProducer(t *testing.T) {
	if _, err := NewPAMSessionService(PAMSessionServiceConfig{Producer: &NoOpPAMAuditProducer{}}); err == nil {
		t.Fatalf("expected error when DB is nil")
	}
	if _, err := NewPAMSessionService(PAMSessionServiceConfig{DB: newPAMDB(t)}); err == nil {
		t.Fatalf("expected error when Producer is nil")
	}
}

func TestPAMSessionService_CreateSession_Validation(t *testing.T) {
	svc, _, lookup, _ := newSessionFixture(t)
	// Disable the lease lookup so we exclusively exercise the input
	// validation branch — otherwise a missing LeaseID would surface
	// as ErrLeaseNotFound first.
	lookup.lease = nil
	cases := []struct {
		name string
		ws   string
		in   CreateSessionInput
	}{
		{"missing workspace", "", defaultCreateInput()},
		{"missing user_id", "ws-1", CreateSessionInput{AssetID: "a", AccountID: "c", LeaseID: "l", Protocol: "ssh", Criticality: "high"}},
		{"missing asset_id", "ws-1", CreateSessionInput{UserID: "u", AccountID: "c", LeaseID: "l", Protocol: "ssh", Criticality: "high"}},
		{"missing account_id", "ws-1", CreateSessionInput{UserID: "u", AssetID: "a", LeaseID: "l", Protocol: "ssh", Criticality: "high"}},
		{"missing lease_id", "ws-1", CreateSessionInput{UserID: "u", AssetID: "a", AccountID: "c", Protocol: "ssh", Criticality: "high"}},
		{"missing protocol", "ws-1", CreateSessionInput{UserID: "u", AssetID: "a", AccountID: "c", LeaseID: "l", Criticality: "high"}},
		{"missing criticality", "ws-1", CreateSessionInput{UserID: "u", AssetID: "a", AccountID: "c", LeaseID: "l", Protocol: "ssh"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.CreateSession(context.Background(), tc.ws, tc.in)
			if !errors.Is(err, ErrValidation) {
				t.Fatalf("err = %v; want ErrValidation", err)
			}
		})
	}
}

// TestPAMSessionService_CreateSession_LeaseLookupRequired guards the
// gate that ensures CreateSession refuses to persist a session for a
// lease that doesn't exist (or belongs to another workspace). This
// is the workspace-scoping primary defence — without it a caller
// could create a session row tied to any ULID it cares to invent.
func TestPAMSessionService_CreateSession_LeaseLookupRequired(t *testing.T) {
	svc, _, lookup, _ := newSessionFixture(t)
	lookup.lease = nil // no lease present
	_, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if !errors.Is(err, ErrLeaseNotFound) {
		t.Fatalf("err = %v; want ErrLeaseNotFound", err)
	}
}

func TestPAMSessionService_CreateSession_HappyPath_NoAssessor(t *testing.T) {
	svc, producer, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil) // explicit no AI

	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if result.Session == nil {
		t.Fatalf("session not returned")
	}
	if result.Session.State != models.PAMSessionStateRequested {
		t.Fatalf("state = %q; want requested", result.Session.State)
	}
	if result.Session.RiskScore != nil {
		t.Fatalf("risk_score = %v; want nil when AI is off", *result.Session.RiskScore)
	}
	if result.AIAvailable {
		t.Fatalf("ai_available = true; want false")
	}
	if len(producer.Events()) != 1 {
		t.Fatalf("expected 1 audit event; got %d", len(producer.Events()))
	}
	ev := producer.Events()[0]
	if ev.EventType != PAMEventSessionRequested {
		t.Fatalf("event_type = %q; want %q", ev.EventType, PAMEventSessionRequested)
	}
	if ev.SessionID != result.Session.ID {
		t.Fatalf("event session id mismatch")
	}
	if ev.WorkspaceID != "ws-1" {
		t.Fatalf("event workspace id = %q", ev.WorkspaceID)
	}
}

func TestPAMSessionService_CreateSession_StampsRiskWhenAIAvailable(t *testing.T) {
	svc, _, _, assessor := newSessionFixture(t)
	assessor.returnScore = "high"
	assessor.returnFactors = []string{"unusual_time:02", "first_time_asset_access"}
	assessor.returnRec = PAMRecommendationRequireApproval
	assessor.returnOK = true

	in := defaultCreateInput()
	in.TimeOfDay = 2
	in.IsFirstAccess = true
	result, err := svc.CreateSession(context.Background(), "ws-1", in)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !result.AIAvailable {
		t.Fatalf("ai_available = false; want true")
	}
	if result.Recommendation != PAMRecommendationRequireApproval {
		t.Fatalf("recommendation = %q", result.Recommendation)
	}
	if result.Session.RiskScore == nil || *result.Session.RiskScore != 75 {
		t.Fatalf("risk_score = %v; want 75 (high band)", result.Session.RiskScore)
	}
	if assessor.calls != 1 {
		t.Fatalf("assessor calls = %d", assessor.calls)
	}
	if assessor.lastPayload.UserID != "user-1" {
		t.Fatalf("payload user_id = %q", assessor.lastPayload.UserID)
	}
	if assessor.lastPayload.TimeOfDay != 2 {
		t.Fatalf("payload time_of_day = %d", assessor.lastPayload.TimeOfDay)
	}
	if !assessor.lastPayload.IsFirstAccess {
		t.Fatalf("payload is_first_access = false; want true")
	}
}

// TestPAMSessionService_CreateSession_FallbackPersisted exercises
// the docs/pam/architecture.md §6 fallback: when the AI agent is
// unreachable the session must still land, with the medium score
// stamped (or empty) and recommendation=require_approval so the
// caller does not auto-approve a session it could not score.
func TestPAMSessionService_CreateSession_FallbackPersisted(t *testing.T) {
	svc, producer, _, assessor := newSessionFixture(t)
	assessor.returnScore = "medium"
	assessor.returnFactors = []string{"ai_unavailable"}
	assessor.returnRec = PAMRecommendationRequireApproval
	assessor.returnOK = false // fallback path

	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if result.AIAvailable {
		t.Fatalf("ai_available = true; want false")
	}
	if result.Recommendation != PAMRecommendationRequireApproval {
		t.Fatalf("recommendation = %q; want require_approval", result.Recommendation)
	}
	if result.Session.RiskScore == nil || *result.Session.RiskScore != 50 {
		t.Fatalf("risk_score = %v; want 50", result.Session.RiskScore)
	}
	if len(producer.Events()) != 1 {
		t.Fatalf("expected 1 audit event; got %d", len(producer.Events()))
	}
}

// TestPAMSessionService_CreateSession_AuditEventCarriesFactors makes
// sure the operator-visible Kafka envelope retains both the AI
// recommendation and the factor list so the admin UI never loses
// audit context, even when the row's RiskScore band is coarse.
func TestPAMSessionService_CreateSession_AuditEventCarriesFactors(t *testing.T) {
	svc, producer, _, assessor := newSessionFixture(t)
	assessor.returnScore = "high"
	assessor.returnFactors = []string{"unusual_time:02"}
	assessor.returnRec = PAMRecommendationRequireApproval
	assessor.returnOK = true

	_, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	ev := producer.Events()[0]
	if ev.Metadata["recommendation"] != PAMRecommendationRequireApproval {
		t.Fatalf("metadata.recommendation = %v", ev.Metadata["recommendation"])
	}
	factors, ok := ev.Metadata["risk_factors"].([]string)
	if !ok || len(factors) != 1 || factors[0] != "unusual_time:02" {
		t.Fatalf("metadata.risk_factors = %v", ev.Metadata["risk_factors"])
	}
	if ev.Metadata["ai_available"] != true {
		t.Fatalf("metadata.ai_available = %v", ev.Metadata["ai_available"])
	}
}

func TestPAMSessionService_AuthorizeSession_FlipsToActive(t *testing.T) {
	svc, producer, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	producer.Reset()

	updated, err := svc.AuthorizeSession(context.Background(), "ws-1", result.Session.ID, "ws-1/sess-1/replay.bin")
	if err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	if updated.State != models.PAMSessionStateActive {
		t.Fatalf("state = %q; want active", updated.State)
	}
	if updated.StartedAt == nil {
		t.Fatalf("started_at = nil; want stamped")
	}
	if updated.ReplayStorageKey != "ws-1/sess-1/replay.bin" {
		t.Fatalf("replay_storage_key = %q", updated.ReplayStorageKey)
	}
	events := producer.Events()
	if len(events) != 2 {
		t.Fatalf("expected 2 audit events (authorized + started); got %d", len(events))
	}
	if events[0].EventType != PAMEventSessionAuthorized {
		t.Fatalf("first event = %q; want %q", events[0].EventType, PAMEventSessionAuthorized)
	}
	if events[1].EventType != PAMEventSessionStarted {
		t.Fatalf("second event = %q; want %q", events[1].EventType, PAMEventSessionStarted)
	}
}

func TestPAMSessionService_AuthorizeSession_NotFoundForWrongWorkspace(t *testing.T) {
	svc, _, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	_, err = svc.AuthorizeSession(context.Background(), "ws-2", result.Session.ID, "key")
	if !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMSessionService_AuthorizeSession_RejectsNonRequestedState(t *testing.T) {
	svc, _, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := svc.AuthorizeSession(context.Background(), "ws-1", result.Session.ID, "key"); err != nil {
		t.Fatalf("first AuthorizeSession: %v", err)
	}
	// Second AuthorizeSession should refuse — the session is already
	// active, not requested. The handler maps this to 404 so an
	// operator cannot race-double-authorize.
	if _, err := svc.AuthorizeSession(context.Background(), "ws-1", result.Session.ID, "key"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("second AuthorizeSession err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMSessionService_CompleteSession_StampsEndedAndCommandCount(t *testing.T) {
	svc, producer, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := svc.AuthorizeSession(context.Background(), "ws-1", result.Session.ID, "key"); err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	producer.Reset()

	done, err := svc.CompleteSession(context.Background(), "ws-1", result.Session.ID, 7)
	if err != nil {
		t.Fatalf("CompleteSession: %v", err)
	}
	if done.State != models.PAMSessionStateCompleted {
		t.Fatalf("state = %q; want completed", done.State)
	}
	if done.EndedAt == nil {
		t.Fatalf("ended_at = nil; want stamped")
	}
	if done.CommandCount != 7 {
		t.Fatalf("command_count = %d; want 7", done.CommandCount)
	}
	events := producer.Events()
	if len(events) != 1 || events[0].EventType != PAMEventSessionEnded {
		t.Fatalf("expected single pam.session.ended event; got %+v", events)
	}
	if events[0].Metadata["command_count"] != 7 {
		t.Fatalf("metadata.command_count = %v; want 7", events[0].Metadata["command_count"])
	}
}

func TestPAMSessionService_CompleteSession_RejectsNonActive(t *testing.T) {
	svc, _, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	// CompleteSession is only valid from the active state — a
	// freshly-requested session should not flip directly to
	// completed.
	if _, err := svc.CompleteSession(context.Background(), "ws-1", result.Session.ID, 0); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err = %v; want ErrSessionNotFound", err)
	}
}

func TestPAMSessionService_FailSession_StampsFailedAndReason(t *testing.T) {
	svc, producer, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	producer.Reset()

	failed, err := svc.FailSession(context.Background(), "ws-1", result.Session.ID, "upstream refused")
	if err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	if failed.State != models.PAMSessionStateFailed {
		t.Fatalf("state = %q; want failed", failed.State)
	}
	if failed.EndedAt == nil {
		t.Fatalf("ended_at = nil; want stamped")
	}
	events := producer.Events()
	if len(events) != 1 || events[0].EventType != PAMEventSessionFailed {
		t.Fatalf("expected single pam.session.failed event; got %+v", events)
	}
	if events[0].Reason != "upstream refused" {
		t.Fatalf("event reason = %q", events[0].Reason)
	}
}

func TestPAMSessionService_FailSession_AcceptsActiveSession(t *testing.T) {
	svc, _, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := svc.AuthorizeSession(context.Background(), "ws-1", result.Session.ID, "k"); err != nil {
		t.Fatalf("AuthorizeSession: %v", err)
	}
	failed, err := svc.FailSession(context.Background(), "ws-1", result.Session.ID, "ssh handshake error")
	if err != nil {
		t.Fatalf("FailSession: %v", err)
	}
	if failed.State != models.PAMSessionStateFailed {
		t.Fatalf("state = %q; want failed", failed.State)
	}
}

func TestPAMSessionService_GetSession_ScopedByWorkspace(t *testing.T) {
	svc, _, _, _ := newSessionFixture(t)
	svc.SetRiskAssessor(nil)
	result, err := svc.CreateSession(context.Background(), "ws-1", defaultCreateInput())
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, err := svc.GetSession(context.Background(), "ws-1", result.Session.ID)
	if err != nil {
		t.Fatalf("GetSession ws-1: %v", err)
	}
	if got.ID != result.Session.ID {
		t.Fatalf("id = %q; want %q", got.ID, result.Session.ID)
	}
	if _, err := svc.GetSession(context.Background(), "ws-2", result.Session.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("cross-workspace lookup err = %v; want ErrSessionNotFound", err)
	}
}

func TestRiskScoreBand_MapsKnownBands(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"low", 25},
		{"medium", 50},
		{"high", 75},
		{"", 0},
		{"unknown", 0},
	}
	for _, tc := range cases {
		if got := riskScoreBand(tc.in); got != tc.want {
			t.Fatalf("riskScoreBand(%q) = %d; want %d", tc.in, got, tc.want)
		}
	}
}
