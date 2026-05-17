package gateway

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseK8sUpstream_K8sToken(t *testing.T) {
	t.Parallel()
	ca := "-----BEGIN CERTIFICATE-----\nMIIBYjCCARigAwIBAgIJAJ+test\n-----END CERTIFICATE-----\n"
	payload := []byte(`{
		"server": "https://api.cluster.example:6443/",
		"ca_data": "` + base64.StdEncoding.EncodeToString([]byte(ca)) + `",
		"token": "sa-token-abc"
	}`)
	got, err := ParseK8sUpstream("k8s_token", payload)
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if got.Server != "https://api.cluster.example:6443" {
		t.Errorf("Server = %q, want https://api.cluster.example:6443 (trailing slash trimmed)", got.Server)
	}
	if got.Token != "sa-token-abc" {
		t.Errorf("Token = %q, want sa-token-abc", got.Token)
	}
	if string(got.CAPEM) != ca {
		t.Errorf("CAPEM mismatch:\n got=%q\nwant=%q", got.CAPEM, ca)
	}
	if got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = true, want false")
	}
}

func TestParseK8sUpstream_K8sToken_InsecureSkip(t *testing.T) {
	t.Parallel()
	payload := []byte(`{
		"server": "https://10.0.0.1:6443",
		"token": "tk",
		"insecure_skip_verify": true
	}`)
	got, err := ParseK8sUpstream("k8s_token", payload)
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if !got.InsecureSkipVerify {
		t.Errorf("InsecureSkipVerify = false, want true")
	}
	if len(got.CAPEM) != 0 {
		t.Errorf("CAPEM = %x, want empty", got.CAPEM)
	}
}

func TestParseK8sUpstream_K8sToken_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		payload string
		wantSub string
	}{
		{"empty", "", "empty"},
		{"missing token", `{"server":"https://x:6443"}`, "missing 'token'"},
		{"empty server", `{"server":"","token":"x"}`, "empty"},
		{"http scheme rejected for ca_data corruption", `{"server":"https://x:6443","token":"x","ca_data":"!!!not-b64"}`, "ca_data"},
		{"invalid json", `not-json`, "decode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseK8sUpstream("k8s_token", []byte(tc.payload))
			if err == nil {
				t.Fatalf("ParseK8sUpstream(%q) returned nil error", tc.payload)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestParseK8sUpstream_Kubeconfig(t *testing.T) {
	t.Parallel()
	caPEM := "-----BEGIN CERTIFICATE-----\nMIIBYjCCARigAwIBAgIJAJ+kc\n-----END CERTIFICATE-----\n"
	yaml := `apiVersion: v1
kind: Config
current-context: prod-ops
contexts:
- name: prod-ops
  context:
    cluster: prod-cluster
    user: ops
    namespace: payments
clusters:
- name: prod-cluster
  cluster:
    server: https://prod.k8s.example:443
    certificate-authority-data: ` + base64.StdEncoding.EncodeToString([]byte(caPEM)) + `
users:
- name: ops
  user:
    token: ops-token-xyz
`
	got, err := ParseK8sUpstream("kubeconfig", []byte(yaml))
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if got.Server != "https://prod.k8s.example:443" {
		t.Errorf("Server = %q", got.Server)
	}
	if got.Token != "ops-token-xyz" {
		t.Errorf("Token = %q", got.Token)
	}
	if string(got.CAPEM) != caPEM {
		t.Errorf("CAPEM mismatch:\n got=%q\nwant=%q", got.CAPEM, caPEM)
	}
}

func TestParseK8sUpstream_Kubeconfig_Errors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name:    "empty",
			yaml:    "",
			wantSub: "empty",
		},
		{
			name: "missing context",
			yaml: `apiVersion: v1
kind: Config
contexts: []
clusters: []
users: []
`,
			wantSub: "missing current-context",
		},
		{
			name: "context not found",
			yaml: `apiVersion: v1
kind: Config
current-context: ghost
contexts:
- name: prod
  context:
    cluster: c
    user: u
clusters:
- name: c
  cluster:
    server: https://x:443
users:
- name: u
  user:
    token: t
`,
			wantSub: "current-context",
		},
		{
			name: "user has no token",
			yaml: `apiVersion: v1
kind: Config
current-context: ctx
contexts:
- name: ctx
  context:
    cluster: c
    user: u
clusters:
- name: c
  cluster:
    server: https://x:443
users:
- name: u
  user: {}
`,
			wantSub: "missing token",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseK8sUpstream("kubeconfig", []byte(tc.yaml))
			if err == nil {
				t.Fatalf("ParseK8sUpstream returned nil error")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestParseK8sUpstream_UnknownType(t *testing.T) {
	t.Parallel()
	_, err := ParseK8sUpstream("password", []byte("anything"))
	if err == nil || !strings.Contains(err.Error(), "unsupported k8s secret type") {
		t.Fatalf("err = %v, want unsupported-type error", err)
	}
	// Also ensure case-insensitive matching works.
	_, err = ParseK8sUpstream("KUBECONFIG", []byte(""))
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want empty-payload error after case-insensitive match", err)
	}
}

func TestParseK8sUpstream_HTTPSchemeAllowed(t *testing.T) {
	t.Parallel()
	// http:// is allowed for tests so a httptest.Server can stand in
	// for the upstream API server without spinning up TLS material.
	payload := []byte(`{"server":"http://127.0.0.1:18080","token":"x"}`)
	got, err := ParseK8sUpstream("k8s_token", payload)
	if err != nil {
		t.Fatalf("ParseK8sUpstream: %v", err)
	}
	if got.Server != "http://127.0.0.1:18080" {
		t.Errorf("Server = %q", got.Server)
	}
}
