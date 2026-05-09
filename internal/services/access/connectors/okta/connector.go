// Package okta implements the access.AccessConnector contract for Okta.
//
// Phase 0 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /api/v1/users with Link header)
//   - SyncIdentitiesDelta (System Log polling; expired token → ErrDeltaTokenExpired)
//   - GetSSOMetadata (Okta OIDC discovery URL)
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 0 stubs.
package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ErrNotImplemented is returned by Phase 0 stubbed methods.
var ErrNotImplemented = errors.New("okta: capability not implemented in Phase 0")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OktaAccessConnector implements access.AccessConnector and
// access.IdentityDeltaSyncer.
type OktaAccessConnector struct {
	httpClient    func() httpDoer
	urlOverride   string // optional base URL override (e.g. http://127.0.0.1:port) for tests
}

// New returns a fresh connector instance.
func New() *OktaAccessConnector {
	return &OktaAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *OktaAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *OktaAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/org", nil)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("okta: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes /api/v1/users?limit=1. If the API token has the
// required scope the call returns 200; anything else surfaces as a missing
// capability rather than an error.
func (c *OktaAccessConnector) VerifyPermissions(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	capabilities []string,
) ([]string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, cap := range capabilities {
		switch cap {
		case "sync_identity":
			req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/users?limit=1", nil)
			if err != nil {
				return nil, err
			}
			if _, err := c.do(req); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities reads the X-Total-Count header if Okta returns it. Most
// Okta orgs do not, so the connector returns -1 to signal unknown.
func (c *OktaAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/api/v1/users?limit=1", nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return 0, fmt.Errorf("okta: count probe status %d: %s", resp.StatusCode, string(body))
	}
	if total := resp.Header.Get("X-Total-Count"); total != "" {
		if n, err := strconv.Atoi(total); err == nil {
			return n, nil
		}
	}
	return -1, nil
}

// SyncIdentities pages through /api/v1/users using the RFC-5988 Link header
// rel="next" pagination Okta uses.
func (c *OktaAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}

	// Resolve the start URL: full URL from checkpoint or the canonical
	// /api/v1/users path on the configured Okta domain.
	startURL := checkpoint
	if startURL == "" {
		startURL = c.absURL(cfg, "/api/v1/users?limit=200")
	}

	for next := startURL; next != ""; {
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return fmt.Errorf("okta: users page status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return err
		}

		var users []oktaUser
		if err := json.Unmarshal(body, &users); err != nil {
			return fmt.Errorf("okta: decode users: %w", err)
		}
		batch := mapOktaUsers(users)
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(batch, nextLink); err != nil {
			return err
		}
		next = nextLink
	}
	return nil
}

// SyncIdentitiesDelta polls Okta's /api/v1/logs system-log endpoint for
// USER_CREATED / USER_UPDATED / USER_DEACTIVATED events since the last
// deltaLink. An expired or rejected since token surfaces as
// access.ErrDeltaTokenExpired.
func (c *OktaAccessConnector) SyncIdentitiesDelta(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	deltaLink string,
	handler func(batch []*access.Identity, removedExternalIDs []string, nextLink string) error,
) (string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return "", err
	}

	startURL := deltaLink
	if startURL == "" {
		// Default to "from now" on first run.
		since := time.Now().UTC().Add(-1 * time.Hour).Format(time.RFC3339)
		startURL = c.absURL(cfg, "/api/v1/logs?since="+url.QueryEscape(since))
	}

	var finalDeltaLink string
	for next := startURL; next != ""; {
		reqURL := next
		if c.urlOverride != "" {
			reqURL = c.rewriteForTest(reqURL)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
		req.Header.Set("Accept", "application/json")

		resp, err := c.doRaw(req)
		if err != nil {
			return "", err
		}

		switch resp.StatusCode {
		case http.StatusOK:
			// fallthrough below
		case http.StatusGone, http.StatusBadRequest:
			// Okta returns 400 with E0000031 when the since cursor is
			// out of retention; we treat both 410 and 400 as expired.
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			if isExpiredCursorBody(body) {
				return "", access.ErrDeltaTokenExpired
			}
			if resp.StatusCode == http.StatusGone {
				return "", access.ErrDeltaTokenExpired
			}
			return "", fmt.Errorf("okta: logs status %d: %s", resp.StatusCode, string(body))
		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			_ = resp.Body.Close()
			return "", fmt.Errorf("okta: logs status %d: %s", resp.StatusCode, string(body))
		}

		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return "", err
		}
		var events []oktaLogEvent
		if err := json.Unmarshal(body, &events); err != nil {
			return "", fmt.Errorf("okta: decode logs: %w", err)
		}
		batch, removed := mapOktaLogEvents(events)
		nextLink := parseNextLink(resp.Header.Get("Link"))
		if err := handler(batch, removed, nextLink); err != nil {
			return "", err
		}
		// On the last page, Okta returns the final since cursor in the
		// rel="self" Link header; we reuse the request URL as the
		// finalDeltaLink for simplicity in Phase 0.
		if nextLink == "" {
			finalDeltaLink = reqURL
		}
		next = nextLink
	}
	return finalDeltaLink, nil
}

// ---------- Phase 0 stubs ----------

func (c *OktaAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *OktaAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *OktaAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

func (c *OktaAccessConnector) GetSSOMetadata(_ context.Context, configRaw, _ map[string]interface{}) (*access.SSOMetadata, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	domain := cfg.normalisedDomain()
	return &access.SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: fmt.Sprintf("https://%s/.well-known/openid-configuration", domain),
		EntityID:    fmt.Sprintf("https://%s", domain),
		SSOLoginURL: fmt.Sprintf("https://%s/oauth2/v1/authorize", domain),
	}, nil
}

func (c *OktaAccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderName,
		"note":     "API token expiry is not exposed by the Okta API; populate via renewal cron",
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

func (c *OktaAccessConnector) absURL(cfg Config, path string) string {
	if c.urlOverride != "" {
		return c.urlOverride + path
	}
	return "https://" + cfg.normalisedDomain() + path
}

// rewriteForTest replaces the absolute Okta URL in a Link-header next link
// with the test-server base URL, so paginated test fixtures still resolve.
func (c *OktaAccessConnector) rewriteForTest(rawURL string) string {
	if c.urlOverride == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	override, err := url.Parse(c.urlOverride)
	if err != nil {
		return rawURL
	}
	u.Scheme = override.Scheme
	u.Host = override.Host
	return u.String()
}

func (c *OktaAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, path string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.absURL(cfg, path), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "SSWS "+strings.TrimPrefix(secrets.APIToken, "SSWS "))
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *OktaAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("okta: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *OktaAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// linkNextRE matches the rel="next" entry in an RFC-5988 Link header.
var linkNextRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

func parseNextLink(linkHeader string) string {
	if linkHeader == "" {
		return ""
	}
	m := linkNextRE.FindStringSubmatch(linkHeader)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

func isExpiredCursorBody(body []byte) bool {
	return strings.Contains(string(body), "E0000031") ||
		strings.Contains(string(body), "expired") ||
		strings.Contains(string(body), "out of retention")
}

func mapOktaUsers(users []oktaUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName),
			Email:       firstNonEmpty(u.Profile.Email, u.Profile.Login),
			Status:      strings.ToLower(u.Status),
		})
	}
	return out
}

func mapOktaLogEvents(events []oktaLogEvent) ([]*access.Identity, []string) {
	identities := make([]*access.Identity, 0, len(events))
	var removed []string
	for _, e := range events {
		var userID, userEmail string
		for _, t := range e.Target {
			if strings.EqualFold(t.Type, "User") {
				userID = t.ID
				userEmail = t.AlternateID
				break
			}
		}
		if userID == "" {
			continue
		}
		switch e.EventType {
		case "user.lifecycle.delete.completed", "user.lifecycle.deactivate":
			removed = append(removed, userID)
		default:
			identities = append(identities, &access.Identity{
				ExternalID: userID,
				Type:       access.IdentityTypeUser,
				Email:      userEmail,
				Status:     "active",
			})
		}
	}
	return identities, removed
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// ---------- Okta DTOs ----------

type oktaUser struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Profile struct {
		Login     string `json:"login"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	} `json:"profile"`
}

type oktaLogEvent struct {
	EventType string         `json:"eventType"`
	Published string         `json:"published"`
	Target    []oktaLogActor `json:"target"`
}

type oktaLogActor struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	AlternateID string `json:"alternateId"`
	DisplayName string `json:"displayName"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector     = (*OktaAccessConnector)(nil)
	_ access.IdentityDeltaSyncer = (*OktaAccessConnector)(nil)
)
