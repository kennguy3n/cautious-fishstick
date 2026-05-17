package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
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

// caKeyPEM returns a fresh ed25519 private key marshalled to OpenSSH
// PEM form, suitable for feeding into LoadSSHCAFromPath.
func caKeyPEM(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal ca key: %v", err)
	}
	return pem.EncodeToMemory(block)
}

func TestLoadSSHCAFromPath_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, caKeyPEM(t), 0o600); err != nil {
		t.Fatalf("write ca key: %v", err)
	}
	ca, err := LoadSSHCAFromPath(path, time.Minute)
	if err != nil {
		t.Fatalf("LoadSSHCAFromPath(path): %v", err)
	}
	if ca.Fingerprint() == "" {
		t.Fatal("loaded CA fingerprint is empty")
	}
}

// TestLoadSSHCAFromPath_InlinePEM exercises the K8s-Secret-env path:
// when the value is the PEM key material itself (what
// `valueFrom: secretKeyRef` injects), LoadSSHCAFromPath must parse it
// directly instead of treating it as a filesystem path and failing
// with ENAMETOOLONG.
func TestLoadSSHCAFromPath_InlinePEM(t *testing.T) {
	inline := string(caKeyPEM(t))
	ca, err := LoadSSHCAFromPath(inline, time.Minute)
	if err != nil {
		t.Fatalf("LoadSSHCAFromPath(inline PEM): %v", err)
	}
	if ca.Fingerprint() == "" {
		t.Fatal("loaded CA fingerprint is empty")
	}
}

func TestLoadOrGenerateHostKey_EmptyGeneratesEphemeral(t *testing.T) {
	signer, err := LoadOrGenerateHostKey("")
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(\"\"): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestLoadOrGenerateHostKey_MissingFileGeneratesEphemeral(t *testing.T) {
	signer, err := LoadOrGenerateHostKey(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(missing): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer for missing file")
	}
}

func TestLoadOrGenerateHostKey_FilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "host.pem")
	if err := os.WriteFile(path, caKeyPEM(t), 0o600); err != nil {
		t.Fatalf("write host key: %v", err)
	}
	signer, err := LoadOrGenerateHostKey(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(path): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer for valid path")
	}
}

// TestLoadOrGenerateHostKey_InlinePEM exercises the K8s-Secret-env
// path: when the value is the PEM key material itself (what
// `valueFrom: secretKeyRef` injects), the loader must parse it
// directly instead of trying to os.ReadFile a multi-line PEM string
// as a filesystem path and crashing the binary at boot.
func TestLoadOrGenerateHostKey_InlinePEM(t *testing.T) {
	inline := string(caKeyPEM(t))
	signer, err := LoadOrGenerateHostKey(inline)
	if err != nil {
		t.Fatalf("LoadOrGenerateHostKey(inline PEM): %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer for inline PEM")
	}
}
