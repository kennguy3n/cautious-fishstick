// Package egnyte implements the access.AccessConnector contract for the
// Egnyte SCIM-compatible users API (/pubapi/v2/users).
//
// Egnyte exposes /pubapi/v1/userinfo for the *current* authenticated user
// and /pubapi/v2/users for the full user directory; the latter is the
// canonical pull source for ZTNA Teams. /pubapi/v1/userinfo is used as
// a cheap Connect probe so we exercise the credentials without fetching
// the full directory.
package egnyte

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
	ProviderName = "egnyte"
	pageSize     = 100
)

var ErrNotImplemented = errors.New("egnyte: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Domain string `json:"domain"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type EgnyteAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *EgnyteAccessConnector { return &EgnyteAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("egnyte: config is nil")
	}
	var cfg Config
	if v, ok := raw["domain"].(string); ok {
		cfg.Domain = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("egnyte: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	domain := strings.TrimSpace(c.Domain)
	if domain == "" {
		return errors.New("egnyte: domain is required")
	}
	if !isDNSLabel(domain) {
		return errors.New("egnyte: domain must be a single DNS label (letters, digits, hyphen)")
	}
	return nil
}

func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return s[0] != '-' && s[len(s)-1] != '-'
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("egnyte: access_token is required")
	}
	return nil
}

func (c *EgnyteAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *EgnyteAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return fmt.Sprintf("https://%s.egnyte.com", strings.TrimSpace(cfg.Domain))
}

func (c *EgnyteAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *EgnyteAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *EgnyteAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("egnyte: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("egnyte: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *EgnyteAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *EgnyteAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL(cfg) + "/pubapi/v1/userinfo"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("egnyte: connect probe: %w", err)
	}
	return nil
}

func (c *EgnyteAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type egnyteUser struct {
	ID         json.Number `json:"id"`
	UserName   string      `json:"userName"`
	ExternalID string      `json:"externalId"`
	Active     bool        `json:"active"`
	Name       struct {
		GivenName  string `json:"givenName"`
		FamilyName string `json:"familyName"`
	} `json:"name"`
	Emails []struct {
		Value   string `json:"value"`
		Primary bool   `json:"primary"`
	} `json:"emails"`
}

type egnyteListResponse struct {
	TotalResults int          `json:"totalResults"`
	ItemsPerPage int          `json:"itemsPerPage"`
	StartIndex   int          `json:"startIndex"`
	Resources    []egnyteUser `json:"resources"`
}

func (c *EgnyteAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *EgnyteAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 1
	if checkpoint != "" {
		fmt.Sscanf(checkpoint, "%d", &offset)
		if offset < 1 {
			offset = 1
		}
	}
	base := c.baseURL(cfg)
	for {
		path := fmt.Sprintf("%s/pubapi/v2/users?startIndex=%d&count=%d", base, offset, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp egnyteListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("egnyte: decode users: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.Resources))
		for _, u := range resp.Resources {
			email := ""
			for _, e := range u.Emails {
				if e.Primary || email == "" {
					email = e.Value
				}
			}
			display := strings.TrimSpace(u.Name.GivenName + " " + u.Name.FamilyName)
			if display == "" {
				display = u.UserName
			}
			if display == "" {
				display = email
			}
			status := "active"
			if !u.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  u.ID.String(),
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       email,
				Status:      status,
			})
		}
		next := ""
		if offset+len(resp.Resources) <= resp.TotalResults && len(resp.Resources) > 0 {
			next = fmt.Sprintf("%d", offset+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		offset += pageSize
	}
}

func (c *EgnyteAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *EgnyteAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *EgnyteAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *EgnyteAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *EgnyteAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*EgnyteAccessConnector)(nil)
