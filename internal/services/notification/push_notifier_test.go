package notification

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pushSubResolverStub is a deterministic resolver used by the push
// notifier tests. Each test seeds the map with the per-user
// subscriptions it wants the notifier to fan out to.
type pushSubResolverStub struct {
	subs map[string][]PushSubscription
	err  error
}

func (s *pushSubResolverStub) ResolvePushSubscriptions(_ context.Context, userID string) ([]PushSubscription, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.subs[userID], nil
}

// httpRecorder captures every request the notifier dispatches so the
// tests can assert payload + headers without spinning a real HTTP
// server.
type httpRecorder struct {
	calls    []*http.Request
	bodies   [][]byte
	respCode int
	respErr  error
}

func (r *httpRecorder) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		r.bodies = append(r.bodies, body)
		req.Body.Close()
	}
	r.calls = append(r.calls, req)
	if r.respErr != nil {
		return nil, r.respErr
	}
	code := r.respCode
	if code == 0 {
		code = http.StatusCreated
	}
	return &http.Response{
		StatusCode: code,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

func TestWebPushNotifier_PostsEnvelopeToEveryEndpoint(t *testing.T) {
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{
		"u1": {
			{UserID: "u1", Endpoint: "https://push.example.com/abc", P256DH: "dh1", Auth: "auth1"},
			{UserID: "u1", Endpoint: "https://push2.example.com/xyz"},
		},
	}}
	rec := &httpRecorder{}
	n := NewWebPushNotifier(resolver, rec, 0)
	if name := n.Name(); name != "webpush" {
		t.Errorf("Name() = %q; want webpush", name)
	}

	notif := Notification{
		Kind:            KindReviewerPending,
		RecipientUserID: "u1",
		Subject:         "Pending review",
		Body:            "You have 1 pending review",
		Metadata:        map[string]interface{}{"review_id": "01HREVIEW0000000000000001"},
		CreatedAt:       time.Date(2026, 5, 10, 18, 0, 0, 0, time.UTC),
	}
	if err := n.Send(context.Background(), notif); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := len(rec.calls); got != 2 {
		t.Fatalf("dispatched %d requests; want 2", got)
	}
	if rec.calls[0].Header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", rec.calls[0].Header.Get("Content-Type"))
	}
	if rec.calls[0].Header.Get("X-Push-P256DH") != "dh1" {
		t.Errorf("P256DH header = %q; want dh1", rec.calls[0].Header.Get("X-Push-P256DH"))
	}
	// 2nd subscription has no keys → headers stripped.
	if rec.calls[1].Header.Get("X-Push-P256DH") != "" {
		t.Errorf("2nd request P256DH = %q; want empty", rec.calls[1].Header.Get("X-Push-P256DH"))
	}
	// Payload decodes back into the envelope shape.
	var got pushEnvelope
	if err := json.Unmarshal(rec.bodies[0], &got); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if got.Subject != notif.Subject || got.Body != notif.Body || got.RecipientUserID != notif.RecipientUserID {
		t.Errorf("envelope mismatch: %+v", got)
	}
}

func TestWebPushNotifier_NoSubscriptionsIsNoop(t *testing.T) {
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{}}
	rec := &httpRecorder{}
	n := NewWebPushNotifier(resolver, rec, 0)

	if err := n.Send(context.Background(), Notification{RecipientUserID: "u-nobody"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(rec.calls) != 0 {
		t.Errorf("calls = %d; want 0", len(rec.calls))
	}
}

func TestWebPushNotifier_HTTPFailureSurfacedButLooped(t *testing.T) {
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{
		"u1": {
			{UserID: "u1", Endpoint: "https://push.example.com/a"},
			{UserID: "u1", Endpoint: "https://push.example.com/b"},
		},
	}}
	// Both fail with the same transport error.
	rec := &httpRecorder{respErr: errors.New("dial timeout")}
	n := NewWebPushNotifier(resolver, rec, 0)

	err := n.Send(context.Background(), Notification{RecipientUserID: "u1"})
	if err == nil {
		t.Fatal("expected aggregate error from failed dispatch")
	}
	if got := len(rec.calls); got != 2 {
		t.Errorf("calls = %d; want 2 (failure should not abort fan-out)", got)
	}
}

func TestWebPushNotifier_NonSuccessStatusCounted(t *testing.T) {
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{
		"u1": {{UserID: "u1", Endpoint: "https://push.example.com/a"}},
	}}
	rec := &httpRecorder{respCode: http.StatusGone}
	n := NewWebPushNotifier(resolver, rec, 0)
	err := n.Send(context.Background(), Notification{RecipientUserID: "u1"})
	if err == nil {
		t.Fatal("expected error for HTTP 410")
	}
}

func TestWebPushNotifier_ResolverErrorPropagates(t *testing.T) {
	resolver := &pushSubResolverStub{err: errors.New("db down")}
	n := NewWebPushNotifier(resolver, &httpRecorder{}, 0)
	err := n.Send(context.Background(), Notification{RecipientUserID: "u1"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestWebPushNotifier_EmptyEndpointSkipped(t *testing.T) {
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{
		"u1": {
			{UserID: "u1", Endpoint: ""},
			{UserID: "u1", Endpoint: "https://push.example.com/a"},
		},
	}}
	rec := &httpRecorder{}
	n := NewWebPushNotifier(resolver, rec, 0)
	if err := n.Send(context.Background(), Notification{RecipientUserID: "u1"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(rec.calls) != 1 {
		t.Errorf("calls = %d; want 1 (empty endpoint skipped)", len(rec.calls))
	}
}

func TestRedactEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://push.example.com/abc/def":       "https://push.example.com/…",
		"https://push.example.com":               "https://push.example.com",
		"http://localhost:9000/secret-token":     "http://localhost:9000/…",
		"weird-no-scheme":                        "weird-no-scheme",
	}
	for in, want := range cases {
		if got := redactEndpoint(in); got != want {
			t.Errorf("redactEndpoint(%q) = %q; want %q", in, got, want)
		}
	}
}

func TestNewWebPushNotifier_PanicsOnNilResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic")
		}
	}()
	NewWebPushNotifier(nil, &httpRecorder{}, 0)
}

func TestWebPushNotifier_IntegratesWithRealHTTP(t *testing.T) {
	// Round-trip through httptest.Server to validate that the
	// notifier composes with stdlib *http.Client without surprises.
	var got []byte
	var contentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = io.ReadAll(r.Body)
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	resolver := &pushSubResolverStub{subs: map[string][]PushSubscription{
		"u1": {{UserID: "u1", Endpoint: srv.URL}},
	}}
	n := NewWebPushNotifier(resolver, &http.Client{Timeout: time.Second}, time.Second)
	if err := n.Send(context.Background(), Notification{RecipientUserID: "u1", Subject: "hi"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if contentType != "application/json" {
		t.Errorf("contentType = %q", contentType)
	}
	if !strings.Contains(string(got), `"subject":"hi"`) {
		t.Errorf("body missing subject: %s", got)
	}
}
