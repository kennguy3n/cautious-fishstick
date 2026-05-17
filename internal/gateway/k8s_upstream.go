package gateway

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/goccy/go-yaml"
)

// K8sUpstream is the parsed form of a SecretInjector payload for a
// Kubernetes session. It carries everything K8sListener needs to
// open an authenticated WebSocket against the target cluster's
// API server: the canonical server URL, an optional PEM-encoded
// cluster CA, and a bearer token.
//
// The gateway never serialises this struct back to disk — every
// field is held in memory for the lifetime of a single exec
// session.
type K8sUpstream struct {
	// Server is the API server URL ("https://10.0.0.1:6443"). It
	// MUST be an https:// URL — k8s.io's WebSocket exec endpoint
	// runs over TLS in every supported cluster, and downgrading
	// to http would let a network attacker MITM the bearer token.
	Server string

	// CAPEM is the cluster CA in PEM form. Optional — when nil
	// and InsecureSkipVerify is false, the system trust store is
	// consulted instead.
	CAPEM []byte

	// Token is the bearer token written as `Authorization: Bearer
	// <token>` on the upstream request. Required.
	Token string

	// InsecureSkipVerify mirrors the kubeconfig flag of the same
	// name. Only honoured when CAPEM is nil. Useful for the dev
	// compose stack pointing at a kind cluster with a self-signed
	// CA the operator hasn't trusted.
	InsecureSkipVerify bool
}

// ParseK8sUpstream decodes a SecretInjector payload into a
// K8sUpstream. secretType selects the decoder:
//
//   - "k8s_token" — plaintext is a JSON document
//     `{"server": "...", "ca_data": "base64-pem", "token": "..."}`.
//     This is the minimal shape used when the asset record already
//     pins the API server URL and the secret store only holds the
//     short-lived service-account token. ca_data is optional;
//     insecure_skip_verify is honoured.
//   - "kubeconfig" — plaintext is a YAML kubeconfig. The current
//     context is followed to its cluster + user; the user must
//     carry a token (client-certificate auth is reserved for a
//     follow-up milestone).
//
// Any other secretType yields an error rather than a permissive
// fallback so an asset-config typo never silently routes a real
// session through unverified TLS.
func ParseK8sUpstream(secretType string, plaintext []byte) (*K8sUpstream, error) {
	switch strings.ToLower(strings.TrimSpace(secretType)) {
	case "k8s_token":
		return parseK8sTokenJSON(plaintext)
	case "kubeconfig":
		return parseKubeconfigYAML(plaintext)
	default:
		return nil, fmt.Errorf("gateway: unsupported k8s secret type %q", secretType)
	}
}

// k8sTokenSecret is the wire shape for secret_type=k8s_token.
type k8sTokenSecret struct {
	Server             string `json:"server"`
	CAData             string `json:"ca_data,omitempty"`
	Token              string `json:"token"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
}

func parseK8sTokenJSON(plaintext []byte) (*K8sUpstream, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("gateway: k8s_token payload is empty")
	}
	var s k8sTokenSecret
	if err := json.Unmarshal(plaintext, &s); err != nil {
		return nil, fmt.Errorf("gateway: decode k8s_token: %w", err)
	}
	if err := validateK8sServerURL(s.Server); err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.Token) == "" {
		return nil, errors.New("gateway: k8s_token missing 'token'")
	}
	out := &K8sUpstream{
		Server:             strings.TrimRight(s.Server, "/"),
		Token:              s.Token,
		InsecureSkipVerify: s.InsecureSkipVerify,
	}
	if s.CAData != "" {
		raw, err := base64.StdEncoding.DecodeString(s.CAData)
		if err != nil {
			return nil, fmt.Errorf("gateway: decode k8s_token ca_data: %w", err)
		}
		out.CAPEM = raw
	}
	return out, nil
}

// kubeconfig mirrors the subset of the kubeconfig YAML schema the
// gateway actually uses. Fields we don't read (auth-providers,
// exec plugins, preferences, extensions) are deliberately omitted
// so a typo in those sections doesn't break parsing of the bits we
// care about.
type kubeconfig struct {
	CurrentContext string              `yaml:"current-context"`
	Contexts       []kubeconfigContext `yaml:"contexts"`
	Clusters       []kubeconfigCluster `yaml:"clusters"`
	Users          []kubeconfigUser    `yaml:"users"`
}

type kubeconfigContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster   string `yaml:"cluster"`
		User      string `yaml:"user"`
		Namespace string `yaml:"namespace,omitempty"`
	} `yaml:"context"`
}

type kubeconfigCluster struct {
	Name    string `yaml:"name"`
	Cluster struct {
		Server                   string `yaml:"server"`
		CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
		InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
	} `yaml:"cluster"`
}

type kubeconfigUser struct {
	Name string `yaml:"name"`
	User struct {
		Token string `yaml:"token,omitempty"`
	} `yaml:"user"`
}

func parseKubeconfigYAML(plaintext []byte) (*K8sUpstream, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("gateway: kubeconfig payload is empty")
	}
	var kc kubeconfig
	if err := yaml.Unmarshal(plaintext, &kc); err != nil {
		return nil, fmt.Errorf("gateway: decode kubeconfig: %w", err)
	}
	if strings.TrimSpace(kc.CurrentContext) == "" {
		return nil, errors.New("gateway: kubeconfig missing current-context")
	}
	ctx := lookupContext(kc.Contexts, kc.CurrentContext)
	if ctx == nil {
		return nil, fmt.Errorf("gateway: kubeconfig current-context %q not found in contexts", kc.CurrentContext)
	}
	cluster := lookupCluster(kc.Clusters, ctx.Context.Cluster)
	if cluster == nil {
		return nil, fmt.Errorf("gateway: kubeconfig cluster %q not found", ctx.Context.Cluster)
	}
	user := lookupUser(kc.Users, ctx.Context.User)
	if user == nil {
		return nil, fmt.Errorf("gateway: kubeconfig user %q not found", ctx.Context.User)
	}
	if err := validateK8sServerURL(cluster.Cluster.Server); err != nil {
		return nil, err
	}
	if strings.TrimSpace(user.User.Token) == "" {
		// Phase 1 only supports token auth for kubeconfigs; client-
		// certificate auth would require also wiring the operator-
		// side TLS dialer to present the cert, which we defer.
		return nil, errors.New("gateway: kubeconfig user missing token; client-cert auth not supported in phase 1")
	}
	out := &K8sUpstream{
		Server:             strings.TrimRight(cluster.Cluster.Server, "/"),
		Token:              user.User.Token,
		InsecureSkipVerify: cluster.Cluster.InsecureSkipTLSVerify,
	}
	if cluster.Cluster.CertificateAuthorityData != "" {
		raw, err := base64.StdEncoding.DecodeString(cluster.Cluster.CertificateAuthorityData)
		if err != nil {
			return nil, fmt.Errorf("gateway: decode kubeconfig certificate-authority-data: %w", err)
		}
		out.CAPEM = raw
	}
	return out, nil
}

// validateK8sServerURL refuses obviously-broken cluster URLs so a
// later wss:// dial doesn't fail with a more confusing error.
func validateK8sServerURL(server string) error {
	if strings.TrimSpace(server) == "" {
		return errors.New("gateway: k8s server URL is empty")
	}
	u, err := url.Parse(server)
	if err != nil {
		return fmt.Errorf("gateway: parse k8s server URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("gateway: k8s server URL scheme %q must be https (http allowed only for tests)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("gateway: k8s server URL missing host")
	}
	return nil
}

func lookupContext(in []kubeconfigContext, name string) *kubeconfigContext {
	for i := range in {
		if in[i].Name == name {
			return &in[i]
		}
	}
	return nil
}

func lookupCluster(in []kubeconfigCluster, name string) *kubeconfigCluster {
	for i := range in {
		if in[i].Name == name {
			return &in[i]
		}
	}
	return nil
}

func lookupUser(in []kubeconfigUser, name string) *kubeconfigUser {
	for i := range in {
		if in[i].Name == name {
			return &in[i]
		}
	}
	return nil
}
