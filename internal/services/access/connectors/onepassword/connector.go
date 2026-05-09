// Package onepassword implements the access.AccessConnector contract for
// 1Password via its SCIM v2.0 bridge.
//
// Phase 1 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated /scim/v2/Users)
//   - GetSSOMetadata returns nil — 1Password is a vault, not an SSO provider
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 1 stubs.
package onepassword

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

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ErrNotImplemented is returned by Phase 1 stubbed methods.
var ErrNotImplemented = errors.New("onepassword: capability not implemented in Phase 1")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// OnePasswordAccessConnector implements access.AccessConnector for 1Password.
type OnePasswordAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New returns a fresh connector instance.
func New() *OnePasswordAccessConnector {
	return &OnePasswordAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *OnePasswordAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *OnePasswordAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("onepassword: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes the SCIM Users endpoint for the sync_identity
// capability. Other capabilities are reported missing-with-no-probe.
func (c *OnePasswordAccessConnector) VerifyPermissions(
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
			req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
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

// CountIdentities reads the SCIM ListResponse totalResults field.
func (c *OnePasswordAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, "/scim/v2/Users?count=1")
	if err != nil {
		return 0, err
	}
	body, err := c.do(req)
	if err != nil {
		return 0, err
	}
	var lr scimListResponse
	if err := json.Unmarshal(body, &lr); err != nil {
		return 0, fmt.Errorf("onepassword: decode list response: %w", err)
	}
	return lr.TotalResults, nil
}

// SyncIdentities pages through /scim/v2/Users using SCIM startIndex/count
// pagination (1-based). The checkpoint is the next startIndex encoded as a
// decimal string; an empty checkpoint starts at 1.
func (c *OnePasswordAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	startIndex := 1
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			startIndex = n
		}
	}
	const count = 100
	for {
		path := fmt.Sprintf("/scim/v2/Users?count=%d&startIndex=%d", count, startIndex)
		req, err := c.newRequest(ctx, cfg, secrets, http.MethodGet, path)
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var lr scimListResponse
		if err := json.Unmarshal(body, &lr); err != nil {
			return fmt.Errorf("onepassword: decode list response: %w", err)
		}
		batch := mapSCIMUsers(lr.Resources)
		nextCheckpoint := ""
		consumed := startIndex + len(lr.Resources) - 1
		if lr.TotalResults > 0 && consumed < lr.TotalResults {
			nextCheckpoint = strconv.Itoa(consumed + 1)
		} else if len(lr.Resources) == count && lr.TotalResults == 0 {
			// Some SCIM bridges omit totalResults — keep paging while
			// pages stay full.
			nextCheckpoint = strconv.Itoa(startIndex + count)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		startIndex, _ = strconv.Atoi(nextCheckpoint)
	}
}

// ---------- Phase 1 stubs ----------

func (c *OnePasswordAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *OnePasswordAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *OnePasswordAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata returns nil — 1Password is a vault, not an SSO provider.
func (c *OnePasswordAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *OnePasswordAccessConnector) GetCredentialsMetadata(_ context.Context, _, _ map[string]interface{}) (map[string]interface{}, error) {
	return map[string]interface{}{
		"provider": ProviderName,
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

func (c *OnePasswordAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return cfg.normalisedAccountURL()
}

func (c *OnePasswordAccessConnector) newRequest(ctx context.Context, cfg Config, secrets Secrets, method, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL(cfg)+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secrets.bearerToken())
	req.Header.Set("Accept", "application/scim+json")
	return req, nil
}

func (c *OnePasswordAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("onepassword: %s status %d: %s", req.URL.Path, resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}

func (c *OnePasswordAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func mapSCIMUsers(users []scimUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if !u.Active {
			status = "disabled"
		}
		email := u.UserName
		for _, e := range u.Emails {
			if e.Primary || email == "" || !strings.Contains(email, "@") {
				email = e.Value
				if e.Primary {
					break
				}
			}
		}
		out = append(out, &access.Identity{
			ExternalID:  u.ID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.DisplayName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- SCIM DTOs ----------

type scimListResponse struct {
	Schemas      []string   `json:"schemas"`
	TotalResults int        `json:"totalResults"`
	StartIndex   int        `json:"startIndex"`
	ItemsPerPage int        `json:"itemsPerPage"`
	Resources    []scimUser `json:"Resources"`
}

type scimUser struct {
	ID          string      `json:"id"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*OnePasswordAccessConnector)(nil)
)
