// Package generic_oidc implements the access.AccessConnector contract for a
// generic OIDC-compliant identity provider. The connector federates SSO via
// Keycloak; it does not sync identities or push grants.
//
// Phase 1 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (no-op — SSO-only)
//   - GetSSOMetadata (parsed from /.well-known/openid-configuration)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 1 stubs.
package generic_oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ErrNotImplemented is returned by Phase 1 stubbed methods.
var ErrNotImplemented = errors.New("generic_oidc: capability not implemented in Phase 1")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// GenericOIDCAccessConnector implements access.AccessConnector for a generic
// OIDC identity provider.
type GenericOIDCAccessConnector struct {
	httpClient func() httpDoer
}

// New returns a fresh connector instance.
func New() *GenericOIDCAccessConnector {
	return &GenericOIDCAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *GenericOIDCAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return err
	}
	if err := cfg.validate(); err != nil {
		return err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *GenericOIDCAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.fetchDiscovery(ctx, cfg); err != nil {
		return fmt.Errorf("generic_oidc: connect: %w", err)
	}
	return nil
}

// VerifyPermissions probes the discovery doc for the sso_federation
// capability. Other capabilities are not supported.
func (c *GenericOIDCAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, _, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sso_federation":
			if _, err := c.fetchDiscovery(ctx, cfg); err != nil {
				missing = append(missing, fmt.Sprintf("sso_federation (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (not supported by generic_oidc)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync (no-op) ----------

// CountIdentities returns 0 — OIDC connectors do not enumerate users.
func (c *GenericOIDCAccessConnector) CountIdentities(_ context.Context, _, _ map[string]interface{}) (int, error) {
	return 0, nil
}

// SyncIdentities is a no-op — federation does not enumerate users
// out-of-band; user records arrive through Keycloak SSO sessions.
func (c *GenericOIDCAccessConnector) SyncIdentities(
	_ context.Context,
	_, _ map[string]interface{},
	_ string,
	_ func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	return nil
}

// ---------- Phase 1 stubs ----------

func (c *GenericOIDCAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericOIDCAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *GenericOIDCAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata fetches the OIDC discovery doc and reflects the relevant
// fields back to Keycloak.
func (c *GenericOIDCAccessConnector) GetSSOMetadata(ctx context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	doc, err := c.fetchDiscovery(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:     "oidc",
		MetadataURL:  cfg.normalisedIssuer() + "/.well-known/openid-configuration",
		EntityID:     doc.Issuer,
		SSOLoginURL:  doc.AuthorizationEndpoint,
		SSOLogoutURL: doc.EndSessionEndpoint,
	}, nil
}

func (c *GenericOIDCAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":  ProviderName,
		"client_id": s.ClientID,
	}, nil
}

// ---------- Internal helpers ----------

func decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Config{}, Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

// oidcDiscoveryDocument is the minimum subset of the OIDC discovery doc this
// connector needs for federation.
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string `json:"jwks_uri,omitempty"`
	EndSessionEndpoint    string `json:"end_session_endpoint,omitempty"`
}

func (c *GenericOIDCAccessConnector) fetchDiscovery(ctx context.Context, cfg Config) (*oidcDiscoveryDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.normalisedIssuer()+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("generic_oidc: discovery status %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return nil, err
	}
	var doc oidcDiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("generic_oidc: parse discovery: %w", err)
	}
	if doc.Issuer == "" || doc.AuthorizationEndpoint == "" || doc.TokenEndpoint == "" {
		return nil, fmt.Errorf("generic_oidc: discovery doc missing required fields (issuer=%q, auth=%q, token=%q)",
			doc.Issuer, doc.AuthorizationEndpoint, doc.TokenEndpoint)
	}
	if !strings.EqualFold(strings.TrimRight(doc.Issuer, "/"), strings.TrimRight(cfg.IssuerURL, "/")) {
		// Mismatched issuer is suspicious but not fatal; some IdPs add
		// a region suffix to issuer. Just continue — Keycloak will
		// catch any actual mismatch at runtime.
		_ = doc
	}
	return &doc, nil
}

func (c *GenericOIDCAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*GenericOIDCAccessConnector)(nil)
)
