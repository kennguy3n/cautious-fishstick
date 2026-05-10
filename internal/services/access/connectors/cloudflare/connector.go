// Package cloudflare implements the access.AccessConnector contract for
// Cloudflare's account-members API.
//
// Phase 7 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /accounts/{id}/members)
//   - GetCredentialsMetadata (token metadata via /user/tokens/verify)
//   - GetSSOMetadata returns nil — Cloudflare itself federates via Access,
//     not via a generic IdP surface.
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 7 stubs.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bytes"

	"net/url"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ProviderName is the registry key for the Cloudflare connector.
const ProviderName = "cloudflare"

// ErrNotImplemented is returned by Phase 7 stubbed methods.
var ErrNotImplemented = errors.New("cloudflare: capability not implemented")

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Config is the operator-visible config.
type Config struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email,omitempty"`
}

// Secrets carries either an API token (preferred) or a legacy global API
// key paired with the account email.
type Secrets struct {
	APIToken string `json:"api_token,omitempty"`
	APIKey   string `json:"api_key,omitempty"`
}

// CloudflareAccessConnector implements access.AccessConnector.
type CloudflareAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New constructs a fresh connector instance.
func New() *CloudflareAccessConnector { return &CloudflareAccessConnector{} }

func init() { access.RegisterAccessConnector(ProviderName, New()) }

// ---------- Decode / Validate ----------

// DecodeConfig pulls a typed Config out of the operator-supplied payload.
func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("cloudflare: config is nil")
	}
	var cfg Config
	if v, ok := raw["account_id"].(string); ok {
		cfg.AccountID = v
	}
	if v, ok := raw["email"].(string); ok {
		cfg.Email = v
	}
	return cfg, nil
}

// DecodeSecrets pulls a typed Secrets out of the decrypted payload.
func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("cloudflare: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["api_token"].(string); ok {
		s.APIToken = v
	}
	if v, ok := raw["api_key"].(string); ok {
		s.APIKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.AccountID) == "" {
		return errors.New("cloudflare: account_id is required")
	}
	return nil
}

func (s Secrets) validate(cfg Config) error {
	if strings.TrimSpace(s.APIToken) == "" && strings.TrimSpace(s.APIKey) == "" {
		return errors.New("cloudflare: api_token or api_key is required")
	}
	if strings.TrimSpace(s.APIToken) == "" && strings.TrimSpace(cfg.Email) == "" {
		return errors.New("cloudflare: email is required when authenticating with api_key")
	}
	return nil
}

func (c *CloudflareAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	_ = cfg
	_ = secrets
	return nil
}

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
	if err := s.validate(cfg); err != nil {
		return Config{}, Secrets{}, err
	}
	return cfg, s, nil
}

// ---------- HTTP plumbing ----------

func (c *CloudflareAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *CloudflareAccessConnector) newRequest(ctx context.Context, secrets Secrets, cfg Config, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(secrets.APIToken) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	} else {
		req.Header.Set("X-Auth-Email", cfg.Email)
		req.Header.Set("X-Auth-Key", strings.TrimSpace(secrets.APIKey))
	}
	return req, nil
}

func (c *CloudflareAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("cloudflare: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *CloudflareAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// ---------- Connect / VerifyPermissions ----------

func (c *CloudflareAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("cloudflare: connect probe: %w", err)
	}
	return nil
}

func (c *CloudflareAccessConnector) VerifyPermissions(
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
			req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
			if err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
				continue
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

type cfMembersResponse struct {
	Result     []cfMember `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Success bool                `json:"success"`
	Errors  []map[string]any    `json:"errors"`
}

type cfMember struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	User   struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"first_name"`
		LastName  string `json:"last_name"`
	} `json:"user"`
}

func (c *CloudflareAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/accounts/"+cfg.AccountID+"/members?per_page=1")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var resp cfMembersResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return 0, fmt.Errorf("cloudflare: decode members: %w", err)
	}
	return resp.ResultInfo.TotalCount, nil
}

func (c *CloudflareAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	const perPage = 50
	page := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			page = n
		}
	}
	for {
		path := fmt.Sprintf("/accounts/%s/members?per_page=%d&page=%d", cfg.AccountID, perPage, page)
		req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp cfMembersResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("cloudflare: decode members: %w", err)
		}
		batch := mapMembers(resp.Result)
		nextCheckpoint := ""
		if resp.ResultInfo.TotalPages > page {
			nextCheckpoint = strconv.Itoa(page + 1)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		page++
	}
}

func mapMembers(in []cfMember) []*access.Identity {
	out := make([]*access.Identity, 0, len(in))
	for _, m := range in {
		display := strings.TrimSpace(m.User.FirstName + " " + m.User.LastName)
		if display == "" {
			display = m.User.Email
		}
		status := "active"
		if m.Status != "" && m.Status != "accepted" {
			status = m.Status
		}
		out = append(out, &access.Identity{
			ExternalID:  m.User.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: display,
			Email:       m.User.Email,
			Status:      status,
		})
	}
	return out
}

// ---------- Stubs ----------

func (c *CloudflareAccessConnector) ProvisionAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("cloudflare: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{"email": grant.UserExternalID, "roles": []string{grant.ResourceExternalID}})
	urlStr := fmt.Sprintf("%s/accounts/%s/members", c.baseURL(), url.PathEscape(cfg.AccountID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, urlStr, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: provision: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	if strings.Contains(string(respBody), "already a member") {
		return nil
	}
	return fmt.Errorf("cloudflare: provision status %d: %s", resp.StatusCode, string(respBody))
}

func (c *CloudflareAccessConnector) RevokeAccess(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant,
) error {
	if grant.UserExternalID == "" || grant.ResourceExternalID == "" {
		return errors.New("cloudflare: grant.UserExternalID and grant.ResourceExternalID are required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	urlStr := fmt.Sprintf("%s/accounts/%s/members/%s", c.baseURL(), url.PathEscape(cfg.AccountID), url.PathEscape(grant.UserExternalID))
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, urlStr, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.APIToken))
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: revoke: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("cloudflare: revoke status %d: %s", resp.StatusCode, string(respBody))
}

func (c *CloudflareAccessConnector) ListEntitlements(
	ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string,
) ([]access.Entitlement, error) {
	if userExternalID == "" {
		return nil, errors.New("cloudflare: user external id is required")
	}
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	urlStr := fmt.Sprintf("%s/accounts/%s/members/%s", c.baseURL(), url.PathEscape(cfg.AccountID), url.PathEscape(userExternalID))
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "")
	if err != nil {
		return nil, err
	}
	req.URL, _ = url.Parse(urlStr)
	body, err := c.do(req)
	if err != nil {
		return nil, nil
	}
	var resp struct {
		Result struct {
			Roles []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"roles"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return nil, nil
	}
	var out []access.Entitlement
	for _, r := range resp.Result.Roles {
		out = append(out, access.Entitlement{
			ResourceExternalID: r.ID,
			Role:               r.Name,
			Source:             "direct",
		})
	}
	return out, nil
}

func (c *CloudflareAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

// GetCredentialsMetadata returns token verification metadata from
// /user/tokens/verify when an API token is supplied; for legacy global
// API keys it returns just the email + auth_type.
func (c *CloudflareAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":   ProviderName,
		"account_id": cfg.AccountID,
	}
	if strings.TrimSpace(secrets.APIToken) == "" {
		out["auth_type"] = "api_key"
		out["email"] = cfg.Email
		return out, nil
	}
	out["auth_type"] = "api_token"
	req, err := c.newRequest(ctx, secrets, cfg, http.MethodGet, "/user/tokens/verify")
	if err != nil {
		return out, nil
	}
	body, err := c.do(req)
	if err != nil {
		return out, nil
	}
	var resp struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresOn string `json:"expires_on,omitempty"`
		} `json:"result"`
	}
	if err := json.Unmarshal(body, &resp); err == nil {
		out["token_id"] = resp.Result.ID
		out["status"] = resp.Result.Status
		if resp.Result.ExpiresOn != "" {
			out["expires_on"] = resp.Result.ExpiresOn
		}
	}
	return out, nil
}

// Compile-time interface assertion.
var _ access.AccessConnector = (*CloudflareAccessConnector)(nil)
