// Package duo implements the access.AccessConnector contract for the Duo
// Security Admin API.
//
// Phase 1 scope:
//
//   - Validate (pure-local), Connect, VerifyPermissions
//   - CountIdentities (admin/v1/info/summary)
//   - SyncIdentities (paginated /admin/v1/users)
//   - GetSSOMetadata returns nil — Duo is MFA, not SSO
//   - GetCredentialsMetadata
//   - ProvisionAccess / RevokeAccess / ListEntitlements: Phase 1 stubs.
package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// ErrNotImplemented is returned by Phase 1 stubbed methods.
var ErrNotImplemented = errors.New("duo_security: capability not implemented in Phase 1")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// DuoAccessConnector implements access.AccessConnector for Duo Security.
type DuoAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
	// nowFn lets tests pin the request Date header for stable signature
	// snapshots; production paths leave it nil and use time.Now.
	nowFn func() time.Time
}

// New returns a fresh connector instance.
func New() *DuoAccessConnector {
	return &DuoAccessConnector{}
}

// ---------- Validate / Connect / VerifyPermissions ----------

func (c *DuoAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *DuoAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	if _, err := c.fetchSummary(ctx, cfg, secrets); err != nil {
		return fmt.Errorf("duo_security: connect: %w", err)
	}
	return nil
}

// VerifyPermissions probes /admin/v1/info/summary for sync_identity.
func (c *DuoAccessConnector) VerifyPermissions(
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
			if _, err := c.fetchSummary(ctx, cfg, secrets); err != nil {
				missing = append(missing, fmt.Sprintf("sync_identity (%v)", err))
			}
		default:
			missing = append(missing, fmt.Sprintf("%s (no probe defined)", cap))
		}
	}
	return missing, nil
}

// ---------- Identity sync ----------

// CountIdentities returns the user_count exposed by /admin/v1/info/summary.
func (c *DuoAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	summary, err := c.fetchSummary(ctx, cfg, secrets)
	if err != nil {
		return 0, err
	}
	return summary.UserCount, nil
}

// SyncIdentities pages through /admin/v1/users using offset/limit pagination.
// The checkpoint is the next offset encoded as a decimal string.
func (c *DuoAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	offset := 0
	if checkpoint != "" {
		if n, err := strconv.Atoi(checkpoint); err == nil {
			offset = n
		}
	}
	const limit = 300
	for {
		params := map[string]string{
			"limit":  strconv.Itoa(limit),
			"offset": strconv.Itoa(offset),
		}
		var resp duoUsersResponse
		if err := c.signedJSON(ctx, cfg, secrets, http.MethodGet, "/admin/v1/users", params, &resp); err != nil {
			return err
		}
		batch := mapDuoUsers(resp.Response)
		nextCheckpoint := ""
		if resp.Metadata != nil && resp.Metadata.NextOffset != nil {
			nextCheckpoint = strconv.Itoa(*resp.Metadata.NextOffset)
		}
		if err := handler(batch, nextCheckpoint); err != nil {
			return err
		}
		if nextCheckpoint == "" {
			return nil
		}
		offset = *resp.Metadata.NextOffset
	}
}

// ---------- Phase 1 stubs ----------

func (c *DuoAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *DuoAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}

func (c *DuoAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}

// ---------- Metadata ----------

// GetSSOMetadata always returns (nil, nil) because Duo is an MFA provider —
// federation is brokered by upstream IdPs, not by Duo itself.
func (c *DuoAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *DuoAccessConnector) GetCredentialsMetadata(_ context.Context, _, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	s, err := DecodeSecrets(secretsRaw)
	if err != nil {
		return nil, err
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":        ProviderName,
		"integration_key": s.IntegrationKey,
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

func (c *DuoAccessConnector) baseURL(cfg Config) string {
	if c.urlOverride != "" {
		return c.urlOverride
	}
	return "https://" + cfg.normalisedHost()
}

func (c *DuoAccessConnector) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now().UTC()
}

// signDuoRequest builds the Duo Admin API HMAC-SHA1 signature per
// https://duo.com/docs/adminapi#authentication. The signed string is:
//
//	date\n
//	METHOD\n
//	HOST\n   (lower-case, no port)
//	path\n
//	canonical-params (RFC 3986 encoded, sorted by key)
//
// The HMAC is keyed with secret_key and rendered as lower-case hex. The
// final Authorization header is "Basic base64(ikey:signature)".
func signDuoRequest(method, host, path string, params map[string]string, ikey, skey, date string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(url.QueryEscape(k))
		canonical.WriteByte('=')
		canonical.WriteString(url.QueryEscape(params[k]))
	}
	stringToSign := strings.Join([]string{
		date,
		strings.ToUpper(method),
		strings.ToLower(host),
		path,
		canonical.String(),
	}, "\n")

	mac := hmac.New(sha1.New, []byte(skey))
	mac.Write([]byte(stringToSign))
	sig := hex.EncodeToString(mac.Sum(nil))

	auth := ikey + ":" + sig
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

func (c *DuoAccessConnector) signedJSON(
	ctx context.Context,
	cfg Config,
	secrets Secrets,
	method, path string,
	params map[string]string,
	out interface{},
) error {
	if params == nil {
		params = map[string]string{}
	}
	host := cfg.normalisedHost()
	date := c.now().Format(time.RFC1123Z)

	authHeader := signDuoRequest(method, host, path, params, secrets.IntegrationKey, secrets.SecretKey, date)

	reqURL := c.baseURL(cfg) + path
	if method == http.MethodGet && len(params) > 0 {
		v := url.Values{}
		for k, val := range params {
			v.Set(k, val)
		}
		reqURL = reqURL + "?" + v.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Date", date)
	req.Header.Set("Accept", "application/json")

	resp, err := c.doRaw(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("duo_security: %s status %d: %s", path, resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("duo_security: decode %s: %w", path, err)
		}
	}
	return nil
}

func (c *DuoAccessConnector) doRaw(req *http.Request) (*http.Response, error) {
	if c.httpClient != nil {
		return c.httpClient().Do(req)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

func (c *DuoAccessConnector) fetchSummary(ctx context.Context, cfg Config, secrets Secrets) (*duoSummary, error) {
	var resp duoSummaryResponse
	if err := c.signedJSON(ctx, cfg, secrets, http.MethodGet, "/admin/v1/info/summary", nil, &resp); err != nil {
		return nil, err
	}
	if resp.Stat != "" && resp.Stat != "OK" {
		return nil, fmt.Errorf("duo_security: summary stat=%q", resp.Stat)
	}
	return &resp.Response, nil
}

func mapDuoUsers(users []duoUser) []*access.Identity {
	out := make([]*access.Identity, 0, len(users))
	for _, u := range users {
		status := strings.ToLower(u.Status)
		if status == "" {
			status = "active"
		}
		email := u.Email
		if email == "" {
			email = u.Username
		}
		out = append(out, &access.Identity{
			ExternalID:  u.UserID,
			Type:        access.IdentityTypeUser,
			DisplayName: u.RealName,
			Email:       email,
			Status:      status,
		})
	}
	return out
}

// ---------- Duo DTOs ----------

type duoUsersResponse struct {
	Stat     string        `json:"stat"`
	Response []duoUser     `json:"response"`
	Metadata *duoMetadata  `json:"metadata,omitempty"`
}

type duoMetadata struct {
	NextOffset   *int `json:"next_offset,omitempty"`
	TotalObjects int  `json:"total_objects,omitempty"`
}

type duoUser struct {
	UserID   string `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	RealName string `json:"realname"`
	Status   string `json:"status"`
}

type duoSummaryResponse struct {
	Stat     string     `json:"stat"`
	Response duoSummary `json:"response"`
}

type duoSummary struct {
	UserCount        int `json:"user_count"`
	IntegrationCount int `json:"integration_count,omitempty"`
}

// ---------- compile-time interface assertions ----------

var (
	_ access.AccessConnector = (*DuoAccessConnector)(nil)
)
