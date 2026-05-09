// Package lastpass implements the access.AccessConnector contract for
// LastPass Enterprise via its enterpriseapi.php JSON endpoint.
//
// Phase 1 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities, SyncIdentities (paginated cmd=getuserdata)
//   - GetSSOMetadata returns nil — LastPass is a vault, not an SSO provider
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 1 stubs.
package lastpass

import (
	"bytes"
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
var ErrNotImplemented = errors.New("lastpass: capability not implemented in Phase 1")

// defaultEndpoint is the LastPass Enterprise JSON API URL. Tests override it
// via urlOverride.
const defaultEndpoint = "https://lastpass.com/enterpriseapi.php"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// LastPassAccessConnector implements access.AccessConnector for LastPass
// Enterprise.
type LastPassAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

// New returns a fresh connector instance.
func New() *LastPassAccessConnector {
	return &LastPassAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *LastPassAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *LastPassAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
	if _, err := c.postJSON(ctx, body); err != nil {
		return fmt.Errorf("lastpass: connect probe: %w", err)
	}
	return nil
}

// VerifyPermissions probes cmd=getuserdata for the sync_identity capability.
func (c *LastPassAccessConnector) VerifyPermissions(
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
			body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
			if _, err := c.postJSON(ctx, body); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities calls cmd=getuserdata with pagesize=1 and reads the total
// from the response.
func (c *LastPassAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{"pagesize": 1})
	respBody, err := c.postJSON(ctx, body)
	if err != nil {
		return 0, err
	}
	var resp lastpassUserDataResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return 0, fmt.Errorf("lastpass: decode getuserdata: %w", err)
	}
	return resp.Total, nil
}

// SyncIdentities pages through cmd=getuserdata using pageoffset/pagesize.
// The checkpoint is the next pageoffset encoded as a decimal string; an
// empty checkpoint starts at 0.
func (c *LastPassAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	const pageSize = 100
	pageOffset := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil && n > 0 {
			pageOffset = n
		}
	}
	for {
		body := buildPayload(cfg, secrets, "getuserdata", map[string]interface{}{
			"pagesize":   pageSize,
			"pageoffset": pageOffset,
		})
		respBody, err := c.postJSON(ctx, body)
		if err != nil {
			return err
		}
		var resp lastpassUserDataResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("lastpass: decode getuserdata: %w", err)
		}
		batch := mapLastPassUsers(resp.Users)
		nextCheckpoint := ""
		consumed := pageOffset + len(resp.Users)
		if (resp.Total > 0 && consumed < resp.Total) ||
			(resp.Total == 0 && len(resp.Users) == pageSize) {
			nextCheckpoint = strconv.Itoa(consumed)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		pageOffset = consumed
	}
}

// ---------- Phase 1 stubs ----------

func (c *LastPassAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *LastPassAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *LastPassAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata returns nil — LastPass is a password vault, not an SSO
// provider. SSO federation through LastPass goes via Keycloak's SAML
// connector instead.
func (c *LastPassAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *LastPassAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, _ map[string]interface{}) (map[string]interface{}, error) {
	cfg, err := DecodeConfig(configRaw)
	if err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":       ProviderName,
		"account_number": cfg.AccountNumber,
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

func (c *LastPassAccessConnector) endpoint() string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return defaultEndpoint
}

func buildPayload(cfg Config, secrets Secrets, cmd string, data map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"cid":      cfg.AccountNumber,
		"provhash": secrets.ProvisioningHash,
		"cmd":      cmd,
		"data":     data,
	}
}

func (c *LastPassAccessConnector) postJSON(ctx context.Context, body map[string]interface{}) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("lastpass: status %d: %s", resp.StatusCode, string(respBody))
	}
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	// LastPass returns 200 even on error; we sniff for the "status":"FAIL"
	// convention. Keeping this loose because the project documents
	// inconsistencies.
	if strings.Contains(string(respBody), `"status":"FAIL"`) {
		return nil, fmt.Errorf("lastpass: api FAIL: %s", string(respBody))
	}
	return respBody, nil
}

func (c *LastPassAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func mapLastPassUsers(users []lastpassUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := "active"
		if u.Disabled {
			status = "disabled"
		}
		email := u.Username
		if u.Email != "" {
			email = u.Email
		}
		externalID := u.UserID
		if externalID == "" {
			externalID = u.Username
		}
		out = append(out, &access.Identity{
			ExternalID:  externalID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.FullName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- LastPass DTOs ----------

type lastpassUserDataResponse struct {
	Total int            `json:"total"`
	Users []lastpassUser `json:"Users"`
}

type lastpassUser struct {
	UserID   string `json:"user_id,omitempty"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	FullName string `json:"fullname"`
	Disabled bool   `json:"disabled"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*LastPassAccessConnector)(nil)
)
