// Package trello implements the access.AccessConnector contract for the
// Trello organization members API.
package trello

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

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName   = "trello"
	defaultBaseURL = "https://api.trello.com/1"
)

var ErrNotImplemented = errors.New("trello: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrganizationID string `json:"organization_id"`
}

type Secrets struct {
	APIKey   string `json:"api_key"`
	APIToken string `json:"api_token"`
}

type TrelloAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *TrelloAccessConnector { return &TrelloAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("trello: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_id"].(string); ok {
		cfg.OrganizationID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("trello: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrganizationID) == "" {
		return errors.New("trello: organization_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIKey) == "" {
		return errors.New("trello: api_key is required")
	}
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("trello: api_token is required")
	}
	return nil
}

func (c *TrelloAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *TrelloAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *TrelloAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *TrelloAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string, extra url.Values) (*http.Request, error) {
	u := c.baseURL() + path
	q := url.Values{}
	if extra != nil {
		for k, vs := range extra {
			for _, v := range vs {
				q.Add(k, v)
			}
		}
	}
	q.Set("key", strings.TrimSpace(secrets.APIKey))
	q.Set("token", strings.TrimSpace(secrets.APIToken))
	if strings.Contains(u, "?") {
		u += "&" + q.Encode()
	} else {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *TrelloAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		// Trello requires api_key/api_token to be sent as URL query parameters
		// (no header-auth equivalent for personal tokens), so we strip the URL
		// component from any *url.Error before wrapping to keep credentials
		// out of the error chain (and therefore out of caller log lines).
		return nil, fmt.Errorf("trello: %s %s: %w", req.Method, req.URL.Path, sanitizeURLError(err))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("trello: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *TrelloAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *TrelloAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/organizations/"+cfg.OrganizationID, nil)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("trello: connect probe: %w", err)
	}
	return nil
}

func (c *TrelloAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type trelloMember struct {
	ID       string `json:"id"`
	FullName string `json:"fullName"`
	Username string `json:"username"`
	Type     string `json:"memberType,omitempty"`
}

func (c *TrelloAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

// Trello returns the full members list in one call (no pagination on this endpoint),
// but we still loop to honour the contract / be future-proof if Trello ever adds it.
func (c *TrelloAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/organizations/"+cfg.OrganizationID+"/members",
		url.Values{"fields": {"fullName,username"}})
	if err != nil {
		return err
	}
	body, err := c.do(req)
	if err != nil {
		return err
	}
	var members []trelloMember
	if err := json.Unmarshal(body, &members); err != nil {
		return fmt.Errorf("trello: decode members: %w", err)
	}
	identities := make([]*access.Identity, 0, len(members))
	for _, m := range members {
		display := m.FullName
		if display == "" {
			display = m.Username
		}
		identities = append(identities, &access.Identity{
			ExternalID:  m.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       "",
			Status:      "active",
		})
	}
	return handler(identities, "")
}

func (c *TrelloAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *TrelloAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *TrelloAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *TrelloAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *TrelloAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"organization_id": cfg.OrganizationID,
		"auth_type":       "api_key+token",
		"key_short":       shortToken(secrets.APIKey),
		"token_short":     shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

// sanitizeURLError unwraps *url.Error and re-wraps with only the operation
// ("Get", "Post", ...) and the underlying error, dropping the URL field —
// which would otherwise embed the api_key/api_token query parameters in any
// log line that prints the returned error.
func sanitizeURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return fmt.Errorf("%s: %w", urlErr.Op, urlErr.Err)
	}
	return err
}

var _ access.AccessConnector = (*TrelloAccessConnector)(nil)
