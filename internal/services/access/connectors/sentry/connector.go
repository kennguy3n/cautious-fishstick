// Package sentry implements the access.AccessConnector contract for the
// Sentry organization members API.
package sentry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName   = "sentry"
	defaultBaseURL = "https://sentry.io"
)

var ErrNotImplemented = errors.New("sentry: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	OrganizationSlug string `json:"organization_slug"`
}

type Secrets struct {
	AuthToken string `json:"auth_token"`
}

type SentryAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *SentryAccessConnector { return &SentryAccessConnector{} }
func init()                       { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("sentry: config is nil")
	}
	var cfg Config
	if v, ok := raw["organization_slug"].(string); ok {
		cfg.OrganizationSlug = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("sentry: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["auth_token"].(string); ok {
		s.AuthToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.OrganizationSlug) == "" {
		return errors.New("sentry: organization_slug is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AuthToken) == "" {
		return errors.New("sentry: auth_token is required")
	}
	return nil
}

func (c *SentryAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *SentryAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *SentryAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *SentryAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AuthToken))
	return req, nil
}

func (c *SentryAccessConnector) doRaw(req *http.Request) (*http.Response, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("sentry: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp, body, fmt.Errorf("sentry: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return resp, body, nil
}

func (c *SentryAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *SentryAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.baseURL() + "/api/0/organizations/" + cfg.OrganizationSlug + "/"
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, _, err := c.doRaw(req); err != nil {
		return fmt.Errorf("sentry: connect probe: %w", err)
	}
	return nil
}

func (c *SentryAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type sentryMember struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// Sentry uses RFC 5988 Link headers with `results="true"` / `cursor="..."` markers:
// `<URL>; rel="next"; results="true"; cursor="100:0:0"`.
var sentryLinkPattern = regexp.MustCompile(`<([^>]+)>;\s*rel="next";[^,]*results="(true|false)"`)

func parseSentryNext(linkHeader string) string {
	m := sentryLinkPattern.FindStringSubmatch(linkHeader)
	if len(m) < 3 {
		return ""
	}
	if m[2] != "true" {
		return ""
	}
	return m[1]
}

func (c *SentryAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *SentryAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	nextURL := checkpoint
	if nextURL == "" {
		nextURL = c.baseURL() + "/api/0/organizations/" + cfg.OrganizationSlug + "/members/"
	}
	for {
		req, err := c.newRequest(ctx, secrets, http.MethodGet, nextURL)
		if err != nil {
			return err
		}
		resp, body, err := c.doRaw(req)
		if err != nil {
			return err
		}
		var members []sentryMember
		if err := json.Unmarshal(body, &members); err != nil {
			return fmt.Errorf("sentry: decode members: %w", err)
		}
		identities := make([]*access.Identity, 0, len(members))
		for _, m := range members {
			display := m.Name
			if display == "" {
				display = m.Email
			}
			identities = append(identities, &access.Identity{
				ExternalID:  m.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       m.Email,
				Status:      "active",
			})
		}
		next := parseSentryNext(resp.Header.Get("Link"))
		if next != "" && c.urlOverride != "" {
			next = strings.Replace(next, defaultBaseURL, strings.TrimRight(c.urlOverride, "/"), 1)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		nextURL = next
	}
}

func (c *SentryAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *SentryAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *SentryAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *SentryAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *SentryAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":          ProviderName,
		"organization_slug": cfg.OrganizationSlug,
		"auth_type":         "auth_token",
		"token_short":       shortToken(secrets.AuthToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*SentryAccessConnector)(nil)
