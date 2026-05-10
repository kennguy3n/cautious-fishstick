// Package jira implements the access.AccessConnector contract for the
// Atlassian Jira Cloud users API.
package jira

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName     = "jira"
	defaultGatewayBase = "https://api.atlassian.com"
	pageSize         = 100
)

var ErrNotImplemented = errors.New("jira: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	CloudID string `json:"cloud_id"`
	SiteURL string `json:"site_url"`
}

type Secrets struct {
	APIToken string `json:"api_token"`
	Email    string `json:"email"`
}

type JiraAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *JiraAccessConnector { return &JiraAccessConnector{} }
func init()                     { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("jira: config is nil")
	}
	var cfg Config
	if v, ok := raw["cloud_id"].(string); ok {
		cfg.CloudID = v
	}
	if v, ok := raw["site_url"].(string); ok {
		cfg.SiteURL = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("jira: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	if v, ok := raw["email"].(string); ok {
		s.Email = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.CloudID) == "" {
		return errors.New("jira: cloud_id is required")
	}
	site := strings.TrimSpace(c.SiteURL)
	if site == "" {
		return errors.New("jira: site_url is required")
	}
	if !strings.HasPrefix(site, "http://") && !strings.HasPrefix(site, "https://") {
		return errors.New("jira: site_url must include scheme")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("jira: api_token is required")
	}
	if strings.TrimSpace(s.Email) == "" {
		return errors.New("jira: email is required")
	}
	return nil
}

func (c *JiraAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *JiraAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return strings.TrimRight(defaultGatewayBase, "/") + "/ex/jira/" + cfg.CloudID
}

func (c *JiraAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func basicAuthHeader(email, token string) string {
	creds := strings.TrimSpace(email) + ":" + strings.TrimSpace(token)
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}

func (c *JiraAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", basicAuthHeader(secrets.Email, secrets.APIToken))
	return req, nil
}

func (c *JiraAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("jira: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("jira: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *JiraAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *JiraAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/rest/api/3/myself"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("jira: connect probe: %w", err)
	}
	return nil
}

func (c *JiraAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type jiraUser struct {
	AccountID    string `json:"accountId"`
	AccountType  string `json:"accountType"`
	DisplayName  string `json:"displayName"`
	EmailAddress string `json:"emailAddress,omitempty"`
	Active       bool   `json:"active"`
}

func (c *JiraAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *JiraAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startAt := 0
	if checkpoint != "" {
		fmt.Sscanf(checkpoint, "%d", &startAt)
		if startAt < 0 {
			startAt = 0
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/rest/api/3/users/search?startAt=%d&maxResults=%d", base, startAt, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var users []jiraUser
		if err := json.Unmarshal(body, &users); err != nil {
			return fmt.Errorf("jira: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(users))
		for _, u := range users {
			idType := access.IdentityTypeUser
			if strings.EqualFold(u.AccountType, "app") {
				idType = access.IdentityTypeServiceAccount
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			display := u.DisplayName
			if display == "" {
				display = u.EmailAddress
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.AccountID,
				Type:        idType,
				DisplayName: display,
				Email:       u.EmailAddress,
				Status:      status,
			})
		}
		next := ""
		if len(users) >= pageSize {
			next = fmt.Sprintf("%d", startAt+len(users))
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		startAt += len(users)
	}
}

func (c *JiraAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *JiraAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *JiraAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// GetSSOMetadata returns the Atlassian Access SAML metadata URL for the
// configured site. Atlassian Access publishes SAML metadata at
// `{site_url}/admin/saml/metadata` once SSO is enabled.
func (c *JiraAccessConnector) GetSSOMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, _, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	site := strings.TrimRight(cfg.SiteURL, "/")
	return &access.SSOMetadata{
		Protocol:    "saml",
		MetadataURL: site + "/admin/saml/metadata",
		EntityID:    site,
	}, nil
}

func (c *JiraAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"cloud_id":    cfg.CloudID,
		"site_url":    cfg.SiteURL,
		"email":       secrets.Email,
		"auth_type":   "basic",
		"token_short": shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*JiraAccessConnector)(nil)
