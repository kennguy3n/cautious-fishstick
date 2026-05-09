// Package msteams implements the access.AccessConnector contract for the
// Microsoft Teams membership API (Microsoft Graph /teams/{id}/members).
//
// MS Teams reuses the same client-credentials OAuth2 flow that the
// Microsoft Entra ID connector uses, but scoped to a single team and
// surfacing the team's federation metadata as Entra ID SAML.
package msteams

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"golang.org/x/oauth2/microsoft"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName   = "ms_teams"
	defaultBaseURL = "https://graph.microsoft.com/v1.0"
)

var ErrNotImplemented = errors.New("ms_teams: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	TenantID string `json:"tenant_id"`
	TeamID   string `json:"team_id"`
}

type Secrets struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type MSTeamsAccessConnector struct {
	httpClient    func(ctx context.Context, cfg Config, secrets Secrets) httpDoer
	urlOverride   string
	tokenOverride func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
}

func New() *MSTeamsAccessConnector { return &MSTeamsAccessConnector{} }
func init()                        { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("ms_teams: config is nil")
	}
	var cfg Config
	if v, ok := raw["tenant_id"].(string); ok {
		cfg.TenantID = v
	}
	if v, ok := raw["team_id"].(string); ok {
		cfg.TeamID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("ms_teams: secrets is nil")
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
		return errors.New("ms_teams: tenant_id is required")
	}
	if strings.TrimSpace(c.TeamID) == "" {
		return errors.New("ms_teams: team_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ClientID) == "" {
		return errors.New("ms_teams: client_id is required")
	}
	if strings.TrimSpace(s.ClientSecret) == "" {
		return errors.New("ms_teams: client_secret is required")
	}
	return nil
}

func (c *MSTeamsAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *MSTeamsAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *MSTeamsAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *MSTeamsAccessConnector) graphClient(ctx context.Context, cfg Config, secrets Secrets) httpDoer {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{
			ctx:     ctx,
			cfg:     cfg,
			secrets: secrets,
			token:   c.tokenOverride,
			inner:   &http.Client{Timeout: 30 * time.Second},
		}
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

func (c *MSTeamsAccessConnector) doJSON(client httpDoer, ctx context.Context, method, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ms_teams: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ms_teams: %s %s: status %d: %s", method, path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *MSTeamsAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client := c.graphClient(ctx, cfg, secrets)
	if _, err := c.doJSON(client, ctx, http.MethodGet, "/teams/"+cfg.TeamID); err != nil {
		return fmt.Errorf("ms_teams: connect probe: %w", err)
	}
	return nil
}

func (c *MSTeamsAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type teamMembersResponse struct {
	NextLink string       `json:"@odata.nextLink,omitempty"`
	Count    int          `json:"@odata.count,omitempty"`
	Value    []teamMember `json:"value"`
}

type teamMember struct {
	ID          string   `json:"id"`
	UserID      string   `json:"userId"`
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
}

func (c *MSTeamsAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *MSTeamsAccessConnector) SyncIdentities(
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
	path := "/teams/" + cfg.TeamID + "/members"
	if checkpoint != "" {
		// Allow callers to resume from a relative path (without host).
		path = checkpoint
	}
	for {
		body, err := c.doJSON(client, ctx, http.MethodGet, path)
		if err != nil {
			return err
		}
		var resp teamMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("ms_teams: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Value))
		for _, m := range resp.Value {
			ext := m.UserID
			if ext == "" {
				ext = m.ID
			}
			display := m.DisplayName
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  ext,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
				RawData:     map[string]interface{}{"roles": m.Roles},
			})
		}
		next := ""
		if resp.NextLink != "" {
			// Trim the absolute Graph host so we can re-append it later.
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

func (c *MSTeamsAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *MSTeamsAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *MSTeamsAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// GetSSOMetadata returns the Entra ID federation metadata URL for the
// configured tenant — Teams authenticates against the same Entra surface.
func (c *MSTeamsAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: fmt.Sprintf("https://login.microsoftonline.com/%s/federationmetadata/2007-06/federationmetadata.xml", cfg.TenantID),
		EntityID:    fmt.Sprintf("https://sts.windows.net/%s/", cfg.TenantID),
		SSOLoginURL: fmt.Sprintf("https://login.microsoftonline.com/%s/saml2", cfg.TenantID),
	}, nil
}

func (c *MSTeamsAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":            ProviderName,
		"tenant_id":           cfg.TenantID,
		"team_id":             cfg.TeamID,
		"auth_type":           "client_credentials",
		"client_id_short":     shortToken(secrets.ClientID),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*MSTeamsAccessConnector)(nil)
