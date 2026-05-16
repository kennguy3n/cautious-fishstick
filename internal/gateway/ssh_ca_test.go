package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// newTestCA returns a CA signer + the bound SSHCertificateAuthority
// for the supplied validity window.
func newTestCA(t *testing.T, validity time.Duration) (*SSHCertificateAuthority, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("ca signer: %v", err)
	}
	return NewSSHCertificateAuthority(signer, validity), signer
}

func TestSSHCertificateAuthority_DefaultValidity(t *testing.T) {
	ca, _ := newTestCA(t, 0)
	if got := ca.Validity(); got != 5*time.Minute {
		t.Fatalf("validity = %v; want 5m default", got)
	}
}

func TestSSHCertificateAuthority_CustomValidity(t *testing.T) {
	ca, _ := newTestCA(t, 30*time.Second)
	if got := ca.Validity(); got != 30*time.Second {
		t.Fatalf("validity = %v; want 30s", got)
	}
}

func TestSSHCertificateAuthority_Fingerprint_NonEmpty(t *testing.T) {
	ca, _ := newTestCA(t, time.Minute)
	if fp := ca.Fingerprint(); fp == "" {
		t.Fatal("fingerprint should not be empty")
	}
}

func TestSSHCertificateAuthority_Fingerprint_NilSafe(t *testing.T) {
	var ca *SSHCertificateAuthority
	if fp := ca.Fingerprint(); fp != "" {
		t.Fatalf("fingerprint on nil = %q; want empty", fp)
	}
}

func TestSSHCertificateAuthority_MintEphemeralCert_HappyPath(t *testing.T) {
	ca, caSigner := newTestCA(t, time.Minute)
	cert, signer, err := ca.MintEphemeralCert("alice")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cert == nil || signer == nil {
		t.Fatal("mint returned nil cert/signer")
	}
	if cert.CertType != ssh.UserCert {
		t.Fatalf("cert_type = %d; want UserCert", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "alice" {
		t.Fatalf("principals = %v; want [alice]", cert.ValidPrincipals)
	}
	// The certificate must be signed by the CA — the signature
	// public key must match the CA's public key.
	if string(cert.SignatureKey.Marshal()) != string(caSigner.PublicKey().Marshal()) {
		t.Fatal("cert signature key does not match CA public key")
	}
	// And the certificate must verify against a CheckHostKey-style
	// CertChecker that trusts the CA.
	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return string(auth.Marshal()) == string(caSigner.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Fatalf("CheckCert: %v", err)
	}
}

func TestSSHCertificateAuthority_MintEphemeralCert_EmptyUsernameRejected(t *testing.T) {
	ca, _ := newTestCA(t, time.Minute)
	if _, _, err := ca.MintEphemeralCert(""); err == nil {
		t.Fatal("expected error for empty username")
	}
}

func TestSSHCertificateAuthority_MintEphemeralCert_NilReceiverRejected(t *testing.T) {
	var ca *SSHCertificateAuthority
	if _, _, err := ca.MintEphemeralCert("alice"); err == nil {
		t.Fatal("expected error on nil receiver")
	}
}

func TestSSHCertificateAuthority_MintEphemeralCert_ValidityWindow(t *testing.T) {
	ca, _ := newTestCA(t, time.Minute)
	cert, _, err := ca.MintEphemeralCert("alice")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// ValidAfter is now-30s, ValidBefore is now+validity. Check
	// the (ValidBefore - ValidAfter) window is close to the
	// validity (allow ±5s for clock drift).
	window := int64(cert.ValidBefore) - int64(cert.ValidAfter)
	want := int64(time.Minute/time.Second) + 30
	if window < want-5 || window > want+5 {
		t.Fatalf("window = %ds; want ≈%ds", window, want)
	}
}

func TestLoadSSHCAFromPath_EmptyPathRejected(t *testing.T) {
	if _, err := LoadSSHCAFromPath("", time.Minute); err == nil {
		t.Fatal("expected error for empty path")
	}
}

func TestLoadSSHCAFromPath_MissingFileRejected(t *testing.T) {
	if _, err := LoadSSHCAFromPath("/nonexistent/path/to/ca/key", time.Minute); err == nil {
		t.Fatal("expected error for missing file")
	}
}
