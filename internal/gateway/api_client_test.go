package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIAuthorizer_AuthorizeConnectToken_HappyPath(t *testing.T) {
	want := AuthorizedSession{
		SessionID:  "sess-1",
		LeaseID:    "lease-1",
		AssetID:    "asset-1",
		AccountID:  "acc-1",
		Protocol:   "ssh",
		TargetHost: "10.0.0.1",
		TargetPort: 22,
		Username:   "root",
	}
	var capturedAuth string
	var capturedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pam/sessions/authorize" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		capturedAuth = r.Header.Get("Authorization")
		var body struct {
			ConnectToken string `json:"connect_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		capturedToken = body.ConnectToken
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	auth := NewAPIAuthorizer(srv.URL, "secret-key", nil)
	got, err := auth.AuthorizeConnectToken(context.Background(), "token-abc")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if got.SessionID != want.SessionID {
		t.Fatalf("session_id = %q; want %q", got.SessionID, want.SessionID)
	}
	if capturedAuth != "Bearer secret-key" {
		t.Fatalf("auth header = %q; want Bearer secret-key", capturedAuth)
	}
	if capturedToken != "token-abc" {
		t.Fatalf("token = %q; want token-abc", capturedToken)
	}
}

func TestAPIAuthorizer_AuthorizeConnectToken_EmptyTokenReturnsError(t *testing.T) {
	auth := NewAPIAuthorizer("http://unused", "key", nil)
	if _, err := auth.AuthorizeConnectToken(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty token")
	}
}

func TestAPIAuthorizer_AuthorizeConnectToken_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad token"}`))
	}))
	defer srv.Close()
	auth := NewAPIAuthorizer(srv.URL, "key", nil)
	_, err := auth.AuthorizeConnectToken(context.Background(), "t")
	if err == nil {
		t.Fatal("expected error on 401")
	}
	if !strings.Contains(err.Error(), "status=401") {
		t.Fatalf("error = %v; want status=401 included", err)
	}
}

func TestAPIAuthorizer_AuthorizeConnectToken_IncompletePayloadRejected(t *testing.T) {
	// The authorizer rejects responses missing required routing
	// fields so a misconfigured control plane cannot trick the
	// gateway into dialling 0.0.0.0:0.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"session_id":"s","target_host":"","target_port":0}`))
	}))
	defer srv.Close()
	auth := NewAPIAuthorizer(srv.URL, "", nil)
	if _, err := auth.AuthorizeConnectToken(context.Background(), "t"); err == nil {
		t.Fatal("expected error for incomplete payload")
	}
}

func TestAPIAuthorizer_NilReceiverReturnsError(t *testing.T) {
	var auth *APIAuthorizer
	if _, err := auth.AuthorizeConnectToken(context.Background(), "t"); err == nil {
		t.Fatal("expected error on nil receiver")
	}
}

func TestAPISecretInjector_InjectSecret_HappyPath(t *testing.T) {
	want := injectResponse{
		SessionID:  "sess-1",
		SecretType: "password",
		Plaintext:  "hunter2",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pam/sessions/sess-1/inject-secret" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	inj := NewAPISecretInjector(srv.URL, "", nil)
	typ, plaintext, err := inj.InjectSecret(context.Background(), "sess-1", "acc-1")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if typ != "password" {
		t.Fatalf("type = %q; want password", typ)
	}
	if string(plaintext) != "hunter2" {
		t.Fatalf("plaintext = %q; want hunter2", string(plaintext))
	}
}

func TestAPISecretInjector_InjectSecret_EmptyArgsRejected(t *testing.T) {
	inj := NewAPISecretInjector("http://unused", "", nil)
	if _, _, err := inj.InjectSecret(context.Background(), "", "acc-1"); err == nil {
		t.Fatal("expected error for empty session id")
	}
	if _, _, err := inj.InjectSecret(context.Background(), "sess-1", ""); err == nil {
		t.Fatal("expected error for empty account id")
	}
}

func TestAPISecretInjector_InjectSecret_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	inj := NewAPISecretInjector(srv.URL, "", nil)
	if _, _, err := inj.InjectSecret(context.Background(), "s", "a"); err == nil {
		t.Fatal("expected error on 403")
	}
}

func TestAPISecretInjector_InjectSecret_EmptyPlaintextRejected(t *testing.T) {
	// A response with an empty plaintext must NOT be passed back to
	// the caller — that would result in injecting an empty
	// password / key into the upstream connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"session_id":"s","secret_type":"password","plaintext":""}`))
	}))
	defer srv.Close()
	inj := NewAPISecretInjector(srv.URL, "", nil)
	if _, _, err := inj.InjectSecret(context.Background(), "s", "a"); err == nil {
		t.Fatal("expected error for empty plaintext")
	}
}

func TestAPISecretInjector_NilReceiverReturnsError(t *testing.T) {
	var inj *APISecretInjector
	if _, _, err := inj.InjectSecret(context.Background(), "s", "a"); err == nil {
		t.Fatal("expected error on nil receiver")
	}
}

// TestAPISecretInjector_InjectSecret_K8sToken proves the injector
// transparently passes through the k8s_token secret_type ztna-api
// hands back, and that the bytes round-trip cleanly into a
// ParseK8sUpstream-ready payload — i.e. the K8s listener can dial
// the upstream cluster with the injected token without further
// massaging.
func TestAPISecretInjector_InjectSecret_K8sToken(t *testing.T) {
	want := injectResponse{
		SessionID:  "sess-k8s",
		SecretType: "k8s_token",
		Plaintext:  `{"server":"https://k8s.example.test","token":"sa-token-abc","insecure_skip_verify":true}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pam/sessions/sess-k8s/inject-secret" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	inj := NewAPISecretInjector(srv.URL, "", nil)
	typ, plaintext, err := inj.InjectSecret(context.Background(), "sess-k8s", "acc-1")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if typ != "k8s_token" {
		t.Fatalf("type = %q; want k8s_token", typ)
	}
	upstream, err := ParseK8sUpstream(typ, plaintext)
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if upstream.Server != "https://k8s.example.test" {
		t.Fatalf("upstream.Server = %q; want https://k8s.example.test", upstream.Server)
	}
	if upstream.Token != "sa-token-abc" {
		t.Fatalf("upstream.Token = %q; want sa-token-abc", upstream.Token)
	}
	if !upstream.InsecureSkipVerify {
		t.Fatal("upstream.InsecureSkipVerify = false; want true")
	}
}

// TestAPISecretInjector_InjectSecret_Kubeconfig mirrors the
// k8s_token test but with a kubeconfig YAML payload — the same
// path the operator-installed cluster-admin credential would take.
func TestAPISecretInjector_InjectSecret_Kubeconfig(t *testing.T) {
	const kubeconfigYAML = `apiVersion: v1
kind: Config
current-context: pam
contexts:
  - name: pam
    context:
      cluster: pam-cluster
      user: pam-sa
clusters:
  - name: pam-cluster
    cluster:
      server: https://k8s.pam.example.test
      insecure-skip-tls-verify: true
users:
  - name: pam-sa
    user:
      token: kubecfg-token-xyz
`
	want := injectResponse{
		SessionID:  "sess-cfg",
		SecretType: "kubeconfig",
		Plaintext:  kubeconfigYAML,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	inj := NewAPISecretInjector(srv.URL, "", nil)
	typ, plaintext, err := inj.InjectSecret(context.Background(), "sess-cfg", "acc-1")
	if err != nil {
		t.Fatalf("inject: %v", err)
	}
	if typ != "kubeconfig" {
		t.Fatalf("type = %q; want kubeconfig", typ)
	}
	upstream, err := ParseK8sUpstream(typ, plaintext)
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if upstream.Server != "https://k8s.pam.example.test" {
		t.Fatalf("upstream.Server = %q; want https://k8s.pam.example.test", upstream.Server)
	}
	if upstream.Token != "kubecfg-token-xyz" {
		t.Fatalf("upstream.Token = %q; want kubecfg-token-xyz", upstream.Token)
	}
	if !upstream.InsecureSkipVerify {
		t.Fatal("upstream.InsecureSkipVerify = false; want true (kubeconfig requested insecure-skip-tls-verify)")
	}
}
