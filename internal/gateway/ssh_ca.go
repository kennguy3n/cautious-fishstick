package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHCertificateAuthority is the gateway's short-lived SSH cert
// issuer. It wraps a long-lived CA private key (mounted from disk)
// and, on each session, mints an ephemeral keypair, signs it as a
// user certificate, and returns the resulting (cert, signer) pair
// to the SSH listener.
//
// Target hosts must trust the CA's public key (deployed out-of-
// band) for the certificate to authenticate. When the target does
// not trust the CA, the gateway falls back to credential injection
// (see APISecretInjector).
type SSHCertificateAuthority struct {
	caSigner ssh.Signer
	validity time.Duration
}

// NewSSHCertificateAuthority wraps caSigner so it can mint user
// certs. caSigner must be the CA's ssh.Signer (typically loaded
// from a PEM file on disk); validity caps how long each issued
// cert is valid for (zero / negative falls back to 5 minutes).
func NewSSHCertificateAuthority(caSigner ssh.Signer, validity time.Duration) *SSHCertificateAuthority {
	if validity <= 0 {
		validity = 5 * time.Minute
	}
	return &SSHCertificateAuthority{caSigner: caSigner, validity: validity}
}

// LoadSSHCAFromPath loads a CA private key from a PEM file on disk
// and returns an SSHCertificateAuthority bound to it.
func LoadSSHCAFromPath(path string, validity time.Duration) (*SSHCertificateAuthority, error) {
	if path == "" {
		return nil, errors.New("gateway: ssh ca key path is empty")
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gateway: read ssh ca key %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("gateway: parse ssh ca key %s: %w", path, err)
	}
	return NewSSHCertificateAuthority(signer, validity), nil
}

// Fingerprint returns the SHA-256 fingerprint of the CA public key
// for boot-log advertisement. Operators copy this value into their
// target hosts' /etc/ssh/sshd_config TrustedUserCAKeys file.
func (a *SSHCertificateAuthority) Fingerprint() string {
	if a == nil || a.caSigner == nil {
		return ""
	}
	return ssh.FingerprintSHA256(a.caSigner.PublicKey())
}

// Validity returns the cert validity window configured on the CA.
func (a *SSHCertificateAuthority) Validity() time.Duration {
	if a == nil {
		return 0
	}
	return a.validity
}

// MintEphemeralCert generates a fresh ed25519 keypair, wraps the
// public half in a short-lived SSH user certificate signed by the
// CA, and returns the (certificate, ephemeral signer) pair. The
// caller wires the pair into ssh.NewCertSigner before adding it to
// the upstream ssh.ClientConfig's auth method list.
//
// The certificate's ValidPrincipals is set to {username}; KeyId is
// set to a short opaque identifier so the upstream sshd auth log
// captures *which* gateway-minted cert authorised the session.
// Critical options and extensions are left at the sshd defaults so
// the cert behaves like a plain interactive login.
func (a *SSHCertificateAuthority) MintEphemeralCert(username string) (*ssh.Certificate, ssh.Signer, error) {
	if a == nil || a.caSigner == nil {
		return nil, nil, errors.New("gateway: SSHCertificateAuthority is nil")
	}
	if username == "" {
		return nil, nil, errors.New("gateway: empty username for ssh cert")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: generate ephemeral ed25519: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: ephemeral signer: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("gateway: ephemeral ssh public key: %w", err)
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             sshPub,
		Serial:          uint64(now.UnixNano()),
		CertType:        ssh.UserCert,
		KeyId:           fmt.Sprintf("pam-gateway:%s:%d", username, now.UnixNano()),
		ValidPrincipals: []string{username},
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(a.validity).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-pty":              "",
				"permit-port-forwarding":  "",
				"permit-X11-forwarding":   "",
				"permit-agent-forwarding": "",
				"permit-user-rc":          "",
			},
		},
	}
	if err := cert.SignCert(rand.Reader, a.caSigner); err != nil {
		return nil, nil, fmt.Errorf("gateway: sign ssh cert: %w", err)
	}
	return cert, signer, nil
}
