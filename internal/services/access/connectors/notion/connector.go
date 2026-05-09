// Package notion implements the access.AccessConnector contract for the
// Notion v1 users API.
package notion

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

const (
	ProviderName     = "notion"
	defaultBaseURL   = "https://api.notion.com"
	notionAPIVersion = "2022-06-28"
)

var ErrNotImplemented = errors.New("notion: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct{}

type Secrets struct {
	APIToken string `json:"api_token"`
}

type NotionAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *NotionAccessConnector { return &NotionAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("notion: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	return s, nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.APIToken) == "" {
		return errors.New("notion: api_token is required")
	}
	return nil
}

func (c *NotionAccessConnector) Validate(_ context.Context, _, secretsRaw map[string]interface{}) error {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return err
	}
	return s.validate()
}

func (c *NotionAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *NotionAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *NotionAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Notion-Version", notionAPIVersion)
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	return req, nil
}

func (c *NotionAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("notion: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("notion: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *NotionAccessConnector) decodeBoth(secretsRaw map[string]interface{}) (Secrets, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return Secrets{}, err
	}
	if err := s.validate(); err != nil {
		return Secrets{}, err
	}
	return s, nil
}

func (c *NotionAccessConnector) Connect(ctx context.Context, _, secretsRaw map[string]interface{}) error {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodGet, "/v1/users?page_size=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("notion: connect probe: %w", err)
	}
	return nil
}

func (c *NotionAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type notionUsersResponse struct {
	Results    []notionUser `json:"results"`
	NextCursor *string      `json:"next_cursor"`
	HasMore    bool         `json:"has_more"`
}

type notionUser struct {
	Object    string `json:"object"`
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Person    struct {
		Email string `json:"email,omitempty"`
	} `json:"person"`
	Bot struct {
		Owner struct {
			Type string `json:"type"`
		} `json:"owner"`
	} `json:"bot"`
}

func (c *NotionAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *NotionAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return err
	}
	cursor := checkpoint
	for {
		path := "/v1/users?page_size=100"
		if cursor != "" {
			path += "&start_cursor=" + cursor
		}
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp notionUsersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("notion: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Results))
		for _, u := range resp.Results {
			idType := access.IdentityTypeUser
			if u.Type == "bot" {
				idType = access.IdentityTypeServiceAccount
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID,
				Type:        idType,
				DisplayName: u.Name,
				Email:       u.Person.Email,
				Status:      "active",
			})
		}
		next := ""
		if resp.HasMore && resp.NextCursor != nil {
			next = *resp.NextCursor
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if !resp.HasMore || resp.NextCursor == nil {
			return nil
		}
		cursor = next
	}
}

func (c *NotionAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *NotionAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *NotionAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *NotionAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *NotionAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	secrets, err := c.decodeBoth(secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":     ProviderName,
		"auth_type":    "internal_integration_token",
		"api_version":  notionAPIVersion,
		"token_short":  shortToken(secrets.APIToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*NotionAccessConnector)(nil)
