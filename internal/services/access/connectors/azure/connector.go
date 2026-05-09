// Package azure implements the access.AccessConnector contract for Azure
// RBAC over Microsoft Graph. The connector authenticates against Entra ID
// with the same client-credentials flow as the microsoft connector but is
// scoped to a single subscription's directory users.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/microsoft"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName   = "azure"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
)

var ErrNotImplemented = errors.New("azure: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TenantID       string `json:"tenant_id"`
	SubscriptionID string `json:"subscription_id"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AzureAccessConnector struct {
	httpClient    func(ctx context.Context, cfg Config, secrets Secrets) httpDoer
	urlOverride   string
	tokenOverride func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
}

func New() *AzureAccessConnector { return &AzureAccessConnector{} }
func init()                      { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("azure: config is nil")
	}
	var cfg Config
	if v, ok := raw["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := raw["subscription_id"].(string); ok {
		cfg.SubscriptionID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("azure: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["client_id"].(string); ok {
		s.ClientID = v
	}
	if v, ok := raw["client_secret"].(string); ok {
		s.ClientSecret = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.TenantID) == "" {
		return errors.New("azure: tenant_id is required")
	}
	if strings.TrimSpace(c.SubscriptionID) == "" {
		return errors.New("azure: subscription_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("azure: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("azure: client_secret is required")
	}
	return nil
}

func (c *AzureAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AzureAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *AzureAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func newClientCredentialsConfig(cfg Config, secrets Secrets) *clientcredentials.Config {
	return &clientcredentials.Config{
		ClientID:     secrets.ClientID,
		ClientSecret: secrets.ClientSecret,
		TokenURL:     microsoft.AzureADEndpoint(cfg.TenantID).TokenURL,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}
}

func (c *AzureAccessConnector) graphClient(ctx context.Context, cfg Config, secrets Secrets) httpDoer {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{ctx: ctx, cfg: cfg, secrets: secrets, token: c.tokenOverride, inner: &http.Client{Timeout: 30 * time.Second}}
	}
	return newClientCredentialsConfig(cfg, secrets).Client(ctx)
}

type bearerTransportClient struct {
	ctx     context.Context
	cfg     Config
	secrets Secrets
	token   func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
	inner   *http.Client
}

func (b *bearerTransportClient) Do(req *http.Request) (*http.Response, error) {
	tok, err := b.token(b.ctx, b.cfg, b.secrets)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return b.inner.Do(req)
}

func (c *AzureAccessConnector) doJSON(client httpDoer, ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("ConsistencyLevel", "eventual")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azure: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("azure: %s %s: status %d: %s", method, path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *AzureAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	if _, err := c.doJSON(client, ctx, http.MethodGet, "/users?$top=1"); err != nil {
		return fmt.Errorf("azure: connect probe: %w", err)
	}
	return nil
}

func (c *AzureAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type azureUsersResponse struct {
	NextLink string      `json:"@odata.nextLink,omitempty"`
	Count    int         `json:"@odata.count,omitempty"`
	Value    []azureUser `json:"value"`
}

type azureUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
	AccountEnabled    bool   `json:"accountEnabled"`
}

func (c *AzureAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	client := c.graphClient(ctx, cfg, secrets)
	body, err := c.doJSON(client, ctx, http.MethodGet, "/users/$count")
	if err != nil {
		return 0, err
	}
	// /users/$count returns a plain integer.
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(body)), "%d", &n); err != nil {
		return 0, fmt.Errorf("azure: parse count: %w", err)
	}
	return n, nil
}

func (c *AzureAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	path := "/users?$select=id,displayName,userPrincipalName,mail,accountEnabled&$top=200"
	if checkpoint != "" {
		path = checkpoint
	}
	for {
		body, err := c.doJSON(client, ctx, http.MethodGet, path)
		if err != nil {
			return err
		}
		var resp azureUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("azure: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Value))
		for _, u := range resp.Value {
			email := u.Mail
			if email == "" {
				email = u.UserPrincipalName
			}
			status := "active"
			if !u.AccountEnabled {
				status = "disabled"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: u.DisplayName,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		if resp.NextLink != "" {
			next = strings.TrimPrefix(resp.NextLink, c.baseURL())
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		path = next
	}
}

func (c *AzureAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *AzureAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *AzureAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *AzureAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

// GetCredentialsMetadata returns the client-secret expiry advertised by
// the application's credentials in app registration. When the override
// path is missing, the response includes only non-sensitive metadata.
func (c *AzureAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":         ProviderName,
		"tenant_id":        cfg.TenantID,
		"subscription_id":  cfg.SubscriptionID,
		"auth_type":        "client_credentials",
		"client_id_short":  shortToken(secrets.ClientID),
	}
	client := c.graphClient(ctx, cfg, secrets)
	// Escape per OData (double single quotes) and URL-encode the literal
	// before embedding into $filter, so a non-UUID client_id containing
	// quotes or other special characters cannot break out of the filter.
	escapedClientID := strings.ReplaceAll(secrets.ClientID, "'", "''")
	filter := url.QueryEscape("appId eq '" + escapedClientID + "'")
	body, err := c.doJSON(client, ctx, http.MethodGet, "/applications?$filter="+filter+"&$select=passwordCredentials")
	if err != nil {
		return out, nil
	}
	var resp struct {
		Value []struct {
			PasswordCredentials []struct {
				EndDateTime string `json:"endDateTime"`
				DisplayName string `json:"displayName"`
			} `json:"passwordCredentials"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return out, nil
	}
	if len(resp.Value) > 0 && len(resp.Value[0].PasswordCredentials) > 0 {
		creds := resp.Value[0].PasswordCredentials
		earliest := ""
		for _, c := range creds {
			if c.EndDateTime != "" && (earliest == "" || c.EndDateTime < earliest) {
				earliest = c.EndDateTime
			}
		}
		if earliest != "" {
			out["client_secret_expires_at"] = earliest
		}
	}
	return out, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*AzureAccessConnector)(nil)
