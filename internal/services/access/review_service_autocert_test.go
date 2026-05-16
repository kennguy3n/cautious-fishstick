package access

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
	"github.com/kennguy3n/cautious-fishstick/internal/pkg/aiclient"
)

// stubReviewAutomator captures every AutomateReview call for the
// auto-certification tests. The Decision / Reason / Ok values drive
// the AI verdict per call; OnPerGrant lets a test return a different
// verdict per grant ID without writing a switch in every case.
type stubReviewAutomator struct {
	Decision    string
	Reason      string
	Ok          bool
	Err         error
	Calls       []aiclient.ReviewAutomationPayload
	OnPerGrant  func(grantID string) (decision, reason string, ok bool)
}

func (s *stubReviewAutomator) AutomateReview(_ context.Context, payload aiclient.ReviewAutomationPayload) (string, string, bool) {
	s.Calls = append(s.Calls, payload)
	if s.OnPerGrant != nil {
		return s.OnPerGrant(payload.GrantID)
	}
	if s.Err != nil {
		return "", "", false
	}
	return s.Decision, s.Reason, s.Ok
}

// TestStartCampaign_AutoCertify_HappyPath asserts that when the AI
// agent returns decision=certify for every pending decision, the
// rows are flipped to decision=certify, auto_certified=true,
// decided_at set. Reviewers should NOT be notified for auto-
// certified rows.
func TestStartCampaign_AutoCertify_HappyPath(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTAC001", ws, "u1", conn, "viewer", "host-a")
	seedActiveGrant(t, db, "01H000000000000000GRANTAC002", ws, "u2", conn, "viewer", "host-b")

	automator := &stubReviewAutomator{Decision: "certify", Reason: "looks fine", Ok: true}
	notif := &stubReviewNotifier{}
	resolver := &stubReviewerResolver{}
	svc := NewAccessReviewService(db, nil)
	svc.SetReviewAutomator(automator)
	svc.SetNotifier(notif, resolver)

	_, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Auto-cert review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: true,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("len(decisions) = %d; want 2", len(decisions))
	}
	if len(automator.Calls) != 2 {
		t.Errorf("automator.Calls = %d; want 2", len(automator.Calls))
	}
	for _, d := range decisions {
		if d.Decision != models.DecisionCertify {
			t.Errorf("decision %s: got %q; want certify", d.GrantID, d.Decision)
		}
		if !d.AutoCertified {
			t.Errorf("decision %s: AutoCertified=false; want true", d.GrantID)
		}
		if d.DecidedAt == nil {
			t.Errorf("decision %s: DecidedAt is nil; want set", d.GrantID)
		}
		if d.Reason != "looks fine" {
			t.Errorf("decision %s: Reason = %q; want %q", d.GrantID, d.Reason, "looks fine")
		}
	}

	// Verify persistence — re-load the rows and assert the same.
	var rows []models.AccessReviewDecision
	if err := db.Where("review_id = ?", decisions[0].ReviewID).Find(&rows).Error; err != nil {
		t.Fatalf("reload decisions: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("reloaded %d rows; want 2", len(rows))
	}
	for _, d := range rows {
		if d.Decision != models.DecisionCertify || !d.AutoCertified {
			t.Errorf("persisted row %s: decision=%q auto_certified=%v; want certify/true", d.ID, d.Decision, d.AutoCertified)
		}
	}

	// No reviewer should be notified about auto-certified rows.
	for _, c := range notif.Calls {
		if len(c.Decisions) != 0 {
			t.Errorf("notifier got %d pending refs; want 0 (auto-certified rows must not page reviewers)", len(c.Decisions))
		}
	}
}

// TestStartCampaign_AutoCertify_EscalateLeavesPending asserts that
// AI verdicts of "escalate" or "revoke" leave the row pending so a
// human reviewer still weighs in. Phase 5 only auto-flips on
// certify; escalate / revoke route through the existing reviewer
// notification path.
func TestStartCampaign_AutoCertify_EscalateLeavesPending(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTAC010", ws, "u1", conn, "admin", "host-a")
	seedActiveGrant(t, db, "01H000000000000000GRANTAC011", ws, "u2", conn, "viewer", "host-b")

	automator := &stubReviewAutomator{
		OnPerGrant: func(grantID string) (string, string, bool) {
			if grantID == "01H000000000000000GRANTAC010" {
				return "escalate", "Privileged role requires manual review.", true
			}
			return "certify", "ok", true
		},
	}
	svc := NewAccessReviewService(db, nil)
	svc.SetReviewAutomator(automator)

	_, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Mixed review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: true,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("len(decisions) = %d; want 2", len(decisions))
	}

	var got map[string]models.AccessReviewDecision = make(map[string]models.AccessReviewDecision)
	for _, d := range decisions {
		got[d.GrantID] = d
	}
	if d := got["01H000000000000000GRANTAC010"]; d.Decision != models.DecisionPending || d.AutoCertified {
		t.Errorf("escalate grant: got decision=%q auto=%v; want pending/false", d.Decision, d.AutoCertified)
	}
	if d := got["01H000000000000000GRANTAC011"]; d.Decision != models.DecisionCertify || !d.AutoCertified {
		t.Errorf("certify grant: got decision=%q auto=%v; want certify/true", d.Decision, d.AutoCertified)
	}
}

// TestStartCampaign_AutoCertify_AIUnreachableLeavesPending asserts
// the docs/architecture.md §9 fallback: when the automator returns ok=false
// (AI unreachable / unconfigured / unrecognised verdict) every row
// stays pending. The campaign succeeds without error — AI is
// decision-support, not critical path.
func TestStartCampaign_AutoCertify_AIUnreachableLeavesPending(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTAC020", ws, "u1", conn, "viewer", "host-a")
	seedActiveGrant(t, db, "01H000000000000000GRANTAC021", ws, "u2", conn, "viewer", "host-b")

	automator := &stubReviewAutomator{Ok: false}
	svc := NewAccessReviewService(db, nil)
	svc.SetReviewAutomator(automator)

	_, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "AI-down review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: true,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 2 {
		t.Fatalf("len(decisions) = %d; want 2", len(decisions))
	}
	for _, d := range decisions {
		if d.Decision != models.DecisionPending {
			t.Errorf("decision %s: got %q; want pending (AI unreachable must not auto-certify)", d.GrantID, d.Decision)
		}
		if d.AutoCertified {
			t.Errorf("decision %s: AutoCertified=true; want false", d.GrantID)
		}
	}
	if len(automator.Calls) != 2 {
		t.Errorf("automator.Calls = %d; want 2 (one per pending decision)", len(automator.Calls))
	}
}

// TestStartCampaign_AutoCertify_RespectsAutoCertifyDisabled asserts
// that when the review's AutoCertifyEnabled flag is false, no AI
// call is made even if an automator is wired in. This protects the
// admin's "I want manual-only" toggle from accidentally firing AI
// auto-cert.
func TestStartCampaign_AutoCertify_RespectsAutoCertifyDisabled(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTAC030", ws, "u1", conn, "viewer", "host-a")

	automator := &stubReviewAutomator{Decision: "certify", Ok: true}
	svc := NewAccessReviewService(db, nil)
	svc.SetReviewAutomator(automator)

	_, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "Manual-only review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: false,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 1 {
		t.Fatalf("len(decisions) = %d; want 1", len(decisions))
	}
	if decisions[0].Decision != models.DecisionPending {
		t.Errorf("decision = %q; want pending (AutoCertifyEnabled=false must skip AI)", decisions[0].Decision)
	}
	if len(automator.Calls) != 0 {
		t.Errorf("automator.Calls = %d; want 0 (AutoCertifyEnabled=false must skip AI)", len(automator.Calls))
	}
}

// TestStartCampaign_AutoCertify_NoAutomatorIsNoop asserts that a
// service without an automator wired in skips the auto-cert pass
// silently — no panic, no failure, every row pending.
func TestStartCampaign_AutoCertify_NoAutomatorIsNoop(t *testing.T) {
	db := newReviewTestDB(t)
	const ws = "01H000000000000000WORKSPACE"
	const conn = "01H000000000000000CONNECTOR"
	seedActiveGrant(t, db, "01H000000000000000GRANTAC040", ws, "u1", conn, "viewer", "host-a")

	svc := NewAccessReviewService(db, nil)
	// Intentionally do not call SetReviewAutomator.

	_, decisions, err := svc.StartCampaign(context.Background(), StartCampaignInput{
		WorkspaceID:        ws,
		Name:               "No-AI review",
		DueAt:              time.Now().Add(7 * 24 * time.Hour),
		ScopeFilter:        scopeJSON(t, map[string]string{"connector_id": conn}),
		AutoCertifyEnabled: true,
	})
	if err != nil {
		t.Fatalf("StartCampaign: %v", err)
	}
	if len(decisions) != 1 || decisions[0].Decision != models.DecisionPending {
		t.Errorf("decisions = %+v; want one pending row", decisions)
	}
}

// TestReviewAutomatorAdapter_NilInner asserts the adapter falls back
// to ok=false when Inner is nil. This makes it cheap to wire the
// adapter in unconditionally at boot even when the AI agent is
// intentionally unconfigured.
func TestReviewAutomatorAdapter_NilInner(t *testing.T) {
	a := &ReviewAutomatorAdapter{Inner: nil}
	_, _, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Error("ok = true; want false (nil Inner must hit fallback)")
	}
}

// TestReviewAutomatorAdapter_NilReceiver asserts a nil receiver also
// hits the fallback. Defensive — keeps the adapter safe to call
// from a service that holds it as an interface field.
func TestReviewAutomatorAdapter_NilReceiver(t *testing.T) {
	var a *ReviewAutomatorAdapter
	_, _, ok := a.AutomateReview(context.Background(), aiclient.ReviewAutomationPayload{GrantID: "g1"})
	if ok {
		t.Error("ok = true; want false (nil receiver must hit fallback)")
	}
}

