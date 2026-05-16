package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SSOFederationService configures a Keycloak Identity Provider broker
// from connector-supplied SSOMetadata, closing the Phase 1 exit
// criterion "First-class SSO federation via Keycloak for SAML / OIDC /
// Microsoft Entra ID / Google Workspace" (docs/architecture.md §Phase 1).
//
// The service is a thin orchestration layer over the Keycloak Admin
// REST API:
//
//   - POST   /admin/realms/{realm}/identity-providers/instances
//   - PUT    /admin/realms/{realm}/identity-providers/instances/{alias}
//   - DELETE /admin/realms/{realm}/identity-providers/instances/{alias}
//   - GET    /admin/realms/{realm}/identity-providers/instances/{alias}
//
// Per docs/architecture.md §2 the access-platform calls
// ConfigureBroker after AccessConnector.Connect + GetSSOMetadata, so
// the IdP is wired into Keycloak as part of the connector setup
// transaction. The service does NOT touch SAML signing keys / OIDC
// client secrets — those are managed by Keycloak itself and surfaced
// to the operator out-of-band.
//
// Tests inject a mock KeycloakClient so no live Keycloak instance is
// required.
type SSOFederationService struct {
	keycloak KeycloakClient
}

// NewSSOFederationService returns a service wired to the supplied
// KeycloakClient. A nil client is allowed for processes that disable
// SSO federation (the resulting service short-circuits with
// ErrSSOFederationDisabled).
func NewSSOFederationService(client KeycloakClient) *SSOFederationService {
	return &SSOFederationService{keycloak: client}
}

// ErrSSOFederationDisabled surfaces when ConfigureBroker is called on
// a service constructed without a KeycloakClient. Callers should
// treat this as a soft-fail (connector setup proceeds; SSO federation
// is reported as unconfigured to the admin UI).
var ErrSSOFederationDisabled = errors.New("sso_federation: keycloak client is not configured")

// ErrSSOFederationUnsupported surfaces when GetSSOMetadata returned
// (nil, nil) — i.e. the connector does not federate SSO. Callers
// MUST NOT treat this as an error; it is a normal control-flow signal.
var ErrSSOFederationUnsupported = errors.New("sso_federation: connector does not advertise SSO metadata")

// KeycloakIdentityProvider mirrors the Keycloak Admin REST API
// IdentityProviderRepresentation. Only the fields the service writes
// or reads are declared; the rest of the upstream representation
// passes through transparently via Config.
type KeycloakIdentityProvider struct {
	Alias                     string            `json:"alias"`
	DisplayName               string            `json:"displayName,omitempty"`
	ProviderID                string            `json:"providerId"`
	Enabled                   bool              `json:"enabled"`
	TrustEmail                bool              `json:"trustEmail,omitempty"`
	StoreToken                bool              `json:"storeToken,omitempty"`
	AddReadTokenRoleOnCreate  bool              `json:"addReadTokenRoleOnCreate,omitempty"`
	AuthenticateByDefault     bool              `json:"authenticateByDefault,omitempty"`
	LinkOnly                  bool              `json:"linkOnly,omitempty"`
	FirstBrokerLoginFlowAlias string            `json:"firstBrokerLoginFlowAlias,omitempty"`
	Config                    map[string]string `json:"config,omitempty"`
}

// KeycloakClient is the narrow contract SSOFederationService uses to
// call the Keycloak Admin REST API. The production implementation is
// HTTPKeycloakClient; tests inject a mock.
type KeycloakClient interface {
	GetIdentityProvider(ctx context.Context, realm, alias string) (*KeycloakIdentityProvider, error)
	CreateIdentityProvider(ctx context.Context, realm string, idp KeycloakIdentityProvider) error
	UpdateIdentityProvider(ctx context.Context, realm, alias string, idp KeycloakIdentityProvider) error
	DeleteIdentityProvider(ctx context.Context, realm, alias string) error
}

// ErrKeycloakIdPNotFound is returned by GetIdentityProvider when the
// supplied alias is not registered in the realm. ConfigureBroker uses
// errors.Is against this sentinel to decide between create and update.
var ErrKeycloakIdPNotFound = errors.New("keycloak: identity provider not found")

// KeycloakUserAdminClient is the optional capability used by the
// Phase 11 leaver kill switch to disable a Keycloak user and
// revoke their refresh tokens. Production HTTPKeycloakClient
// implements this interface; tests can opt in by providing a mock
// that also satisfies it.
type KeycloakUserAdminClient interface {
	UpdateUser(ctx context.Context, realm, userID string, patch map[string]interface{}) error
	LogoutUser(ctx context.Context, realm, userID string) error
}

// HTTPKeycloakClient is the production KeycloakClient. It calls the
// Keycloak Admin REST API with a bearer token.
type HTTPKeycloakClient struct {
	BaseURL    string                            // e.g. https://keycloak.corp.example
	Token      func(ctx context.Context) (string, error) // service-account bearer
	HTTPClient *http.Client                      // nil → http.DefaultClient
}

// NewHTTPKeycloakClient returns an HTTPKeycloakClient with a 30s HTTP
// timeout and the supplied token provider. base is the Keycloak root
// URL (no trailing slash).
func NewHTTPKeycloakClient(base string, token func(ctx context.Context) (string, error)) *HTTPKeycloakClient {
	return &HTTPKeycloakClient{
		BaseURL:    strings.TrimRight(base, "/"),
		Token:      token,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *HTTPKeycloakClient) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *HTTPKeycloakClient) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	if c.BaseURL == "" {
		return nil, errors.New("keycloak: base url is required")
	}
	if c.Token == nil {
		return nil, errors.New("keycloak: token provider is required")
	}
	tok, err := c.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("keycloak: fetch token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// GetIdentityProvider returns the registered IdP or ErrKeycloakIdPNotFound.
func (c *HTTPKeycloakClient) GetIdentityProvider(ctx context.Context, realm, alias string) (*KeycloakIdentityProvider, error) {
	req, err := c.newRequest(ctx, http.MethodGet,
		fmt.Sprintf("/admin/realms/%s/identity-providers/instances/%s",
			url.PathEscape(realm), url.PathEscape(alias)), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrKeycloakIdPNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, fmt.Errorf("keycloak: GET idp status %d: %s", resp.StatusCode, string(body))
	}
	var idp KeycloakIdentityProvider
	if err := json.NewDecoder(resp.Body).Decode(&idp); err != nil {
		return nil, fmt.Errorf("keycloak: decode idp: %w", err)
	}
	return &idp, nil
}

// CreateIdentityProvider POSTs a new IdP instance.
func (c *HTTPKeycloakClient) CreateIdentityProvider(ctx context.Context, realm string, idp KeycloakIdentityProvider) error {
	body, err := json.Marshal(idp)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPost,
		fmt.Sprintf("/admin/realms/%s/identity-providers/instances",
			url.PathEscape(realm)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	return c.doWriteRequest(req, "POST")
}

// UpdateIdentityProvider PUTs an existing IdP instance.
func (c *HTTPKeycloakClient) UpdateIdentityProvider(ctx context.Context, realm, alias string, idp KeycloakIdentityProvider) error {
	body, err := json.Marshal(idp)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPut,
		fmt.Sprintf("/admin/realms/%s/identity-providers/instances/%s",
			url.PathEscape(realm), url.PathEscape(alias)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	return c.doWriteRequest(req, "PUT")
}

// DeleteIdentityProvider removes an IdP instance.
func (c *HTTPKeycloakClient) DeleteIdentityProvider(ctx context.Context, realm, alias string) error {
	req, err := c.newRequest(ctx, http.MethodDelete,
		fmt.Sprintf("/admin/realms/%s/identity-providers/instances/%s",
			url.PathEscape(realm), url.PathEscape(alias)), nil)
	if err != nil {
		return err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil // already absent
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("keycloak: DELETE idp status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func (c *HTTPKeycloakClient) doWriteRequest(req *http.Request, verb string) error {
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("keycloak: %s idp status %d: %s", verb, resp.StatusCode, string(body))
	}
	return nil
}

// ConfigureBroker idempotently configures a Keycloak Identity Provider
// broker from the supplied connector metadata. realm is the Keycloak
// realm name (typically the workspace slug); alias is the stable IdP
// alias (typically the connector ID).
//
// Behaviour:
//
//   - metadata == nil  -> returns ErrSSOFederationUnsupported (no-op).
//   - service.keycloak == nil -> returns ErrSSOFederationDisabled.
//   - IdP already exists -> PUT  (update in place).
//   - IdP does not exist -> POST (create).
//
// Returns the (alias, providerID) pair so callers can persist the
// link between connector and IdP for the admin UI.
func (s *SSOFederationService) ConfigureBroker(
	ctx context.Context,
	realm, alias, displayName string,
	metadata *SSOMetadata,
) (string, string, error) {
	if s == nil || s.keycloak == nil {
		return "", "", ErrSSOFederationDisabled
	}
	if metadata == nil {
		return "", "", ErrSSOFederationUnsupported
	}
	realm = strings.TrimSpace(realm)
	alias = strings.TrimSpace(alias)
	if realm == "" {
		return "", "", errors.New("sso_federation: realm is required")
	}
	if alias == "" {
		return "", "", errors.New("sso_federation: alias is required")
	}

	idp, err := buildIdentityProvider(alias, displayName, metadata)
	if err != nil {
		return "", "", err
	}

	existing, err := s.keycloak.GetIdentityProvider(ctx, realm, alias)
	switch {
	case errors.Is(err, ErrKeycloakIdPNotFound):
		if err := s.keycloak.CreateIdentityProvider(ctx, realm, idp); err != nil {
			return "", "", fmt.Errorf("sso_federation: create %s: %w", alias, err)
		}
	case err != nil:
		return "", "", fmt.Errorf("sso_federation: lookup %s: %w", alias, err)
	default:
		if err := s.keycloak.UpdateIdentityProvider(ctx, realm, alias, mergeIdP(*existing, idp)); err != nil {
			return "", "", fmt.Errorf("sso_federation: update %s: %w", alias, err)
		}
	}
	return idp.Alias, idp.ProviderID, nil
}

// UpdateUser PUTs an arbitrary JSON patch onto a Keycloak user.
// The Phase 11 leaver kill switch uses this with {"enabled": false}
// to flip the user to disabled at the realm.
func (c *HTTPKeycloakClient) UpdateUser(ctx context.Context, realm, userID string, patch map[string]interface{}) error {
	body, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, http.MethodPut,
		fmt.Sprintf("/admin/realms/%s/users/%s",
			url.PathEscape(realm), url.PathEscape(userID)), bytes.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil // already gone — idempotent kill switch
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("keycloak: PUT user status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// LogoutUser POSTs to the Keycloak Admin logout endpoint which
// invalidates every active session and refresh token issued to the
// user.
func (c *HTTPKeycloakClient) LogoutUser(ctx context.Context, realm, userID string) error {
	req, err := c.newRequest(ctx, http.MethodPost,
		fmt.Sprintf("/admin/realms/%s/users/%s/logout",
			url.PathEscape(realm), url.PathEscape(userID)), nil)
	if err != nil {
		return err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("keycloak: POST user logout status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// DisableKeycloakUser flips a Keycloak user to enabled=false and
// invalidates every active session and refresh token. Returns
// ErrSSOFederationDisabled when the service was constructed
// without a KeycloakClient, ErrSSOFederationUnsupported when the
// configured KeycloakClient does not satisfy the user-admin
// capability. Both error sentinels are best-effort signals — the
// JML leaver flow logs them but continues to the next kill-switch
// layer.
func (s *SSOFederationService) DisableKeycloakUser(ctx context.Context, realm, userID string) error {
	if s == nil || s.keycloak == nil {
		return ErrSSOFederationDisabled
	}
	admin, ok := s.keycloak.(KeycloakUserAdminClient)
	if !ok {
		return ErrSSOFederationUnsupported
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(userID) == "" {
		return errors.New("sso_federation: realm and userID are required")
	}
	if err := admin.UpdateUser(ctx, realm, userID, map[string]interface{}{"enabled": false}); err != nil {
		return fmt.Errorf("sso_federation: disable %s: %w", userID, err)
	}
	if err := admin.LogoutUser(ctx, realm, userID); err != nil {
		return fmt.Errorf("sso_federation: logout %s: %w", userID, err)
	}
	return nil
}

// DeleteBroker removes the Keycloak IdP for the supplied alias. Safe
// to call against an absent alias (the underlying Keycloak DELETE
// returns 404, which we swallow).
func (s *SSOFederationService) DeleteBroker(ctx context.Context, realm, alias string) error {
	if s == nil || s.keycloak == nil {
		return ErrSSOFederationDisabled
	}
	if strings.TrimSpace(realm) == "" || strings.TrimSpace(alias) == "" {
		return errors.New("sso_federation: realm and alias are required")
	}
	return s.keycloak.DeleteIdentityProvider(ctx, realm, alias)
}

// buildIdentityProvider maps SSOMetadata into a Keycloak
// IdentityProviderRepresentation. SAML and OIDC have distinct
// keycloak `config` shapes; the helper handles both.
func buildIdentityProvider(alias, displayName string, m *SSOMetadata) (KeycloakIdentityProvider, error) {
	switch strings.ToLower(strings.TrimSpace(m.Protocol)) {
	case "saml":
		return buildSAMLProvider(alias, displayName, m), nil
	case "oidc":
		return buildOIDCProvider(alias, displayName, m), nil
	default:
		return KeycloakIdentityProvider{},
			fmt.Errorf("sso_federation: unsupported protocol %q (want saml | oidc)", m.Protocol)
	}
}

func buildSAMLProvider(alias, displayName string, m *SSOMetadata) KeycloakIdentityProvider {
	cfg := map[string]string{
		"singleSignOnServiceUrl": m.SSOLoginURL,
		"entityId":               m.EntityID,
		"nameIDPolicyFormat":     "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		"postBindingResponse":    "true",
		"postBindingAuthnRequest": "true",
		"validateSignature":      "true",
		"wantAuthnRequestsSigned": "false",
	}
	if m.MetadataURL != "" {
		cfg["idpEntityId"] = m.EntityID
		// Keycloak accepts a metadata URL for auto-import of certs.
		cfg["metadataDescriptorUrl"] = m.MetadataURL
	}
	if m.SSOLogoutURL != "" {
		cfg["singleLogoutServiceUrl"] = m.SSOLogoutURL
	}
	if len(m.SigningCertificates) > 0 {
		cfg["signingCertificate"] = m.SigningCertificates[0]
	}
	return KeycloakIdentityProvider{
		Alias:                     alias,
		DisplayName:               displayName,
		ProviderID:                "saml",
		Enabled:                   true,
		TrustEmail:                true,
		FirstBrokerLoginFlowAlias: "first broker login",
		Config:                    cfg,
	}
}

func buildOIDCProvider(alias, displayName string, m *SSOMetadata) KeycloakIdentityProvider {
	cfg := map[string]string{
		"issuer":               m.EntityID,
		"useJwksUrl":           "true",
	}
	if m.MetadataURL != "" {
		cfg["metadataUrl"] = m.MetadataURL
	}
	if m.SSOLoginURL != "" {
		cfg["authorizationUrl"] = m.SSOLoginURL
	}
	if m.SSOLogoutURL != "" {
		cfg["logoutUrl"] = m.SSOLogoutURL
	}
	return KeycloakIdentityProvider{
		Alias:                     alias,
		DisplayName:               displayName,
		ProviderID:                "oidc",
		Enabled:                   true,
		TrustEmail:                true,
		FirstBrokerLoginFlowAlias: "first broker login",
		Config:                    cfg,
	}
}

// mergeIdP preserves operator-tweaked fields on an existing IdP while
// taking the freshly-supplied connector metadata as the source of
// truth for the SSO endpoints / certificates.
func mergeIdP(existing, fresh KeycloakIdentityProvider) KeycloakIdentityProvider {
	out := fresh
	if existing.Config != nil {
		merged := make(map[string]string, len(existing.Config)+len(fresh.Config))
		for k, v := range existing.Config {
			merged[k] = v
		}
		for k, v := range fresh.Config {
			merged[k] = v
		}
		out.Config = merged
	}
	if existing.FirstBrokerLoginFlowAlias != "" {
		out.FirstBrokerLoginFlowAlias = existing.FirstBrokerLoginFlowAlias
	}
	return out
}
