package ga4

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

// Phase 10 advanced-capability mapping for Google Analytics 4 Admin API
// /v1beta/accounts/{account}/userLinks:
//
//   - ProvisionAccess  -> POST   /v1beta/accounts/{account}/userLinks           (create userLink)
//   - RevokeAccess     -> DELETE /v1beta/accounts/{account}/userLinks/{userId}  (delete userLink)
//   - ListEntitlements -> GET    /v1beta/accounts/{account}/userLinks/{userId}  (current directRoles)
//
// AccessGrant maps:
//   - grant.UserExternalID     -> GA4 userLink id or email
//   - grant.ResourceExternalID -> direct role
//     ("predefinedRoles/admin" | "predefinedRoles/editor" | "predefinedRoles/analyst" | "predefinedRoles/viewer")
//
// Idempotent on (UserExternalID, ResourceExternalID) per PROPOSAL §2.1.

func ga4ValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("ga4: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("ga4: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *GA4AccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("ga4: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *GA4AccessConnector) userLinksURL(cfg Config) string {
	return c.baseURL() + c.userLinksPath(cfg)
}

func (c *GA4AccessConnector) userLinkURL(cfg Config, userID string) string {
	return c.userLinksURL(cfg) + "/" + url.PathEscape(strings.TrimSpace(userID))
}

func (c *GA4AccessConnector) newJSONRequest(ctx context.Context, secrets Secrets, method, fullURL string, body []byte) (*http.Request, error) {
	var rdr io.Reader
	if len(body) > 0 {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, fullURL, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	return req, nil
}

func (c *GA4AccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ga4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"emailAddress": strings.TrimSpace(grant.UserExternalID),
		"directRoles":  []string{strings.TrimSpace(grant.ResourceExternalID)},
	})
	req, err := c.newJSONRequest(ctx, secrets, http.MethodPost, c.userLinksURL(cfg), payload)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentProvisionStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("ga4: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ga4: provision status %d: %s", status, string(body))
	}
}

func (c *GA4AccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := ga4ValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userLinkURL(cfg, grant.UserExternalID), nil)
	if err != nil {
		return err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return err
	}
	switch {
	case status >= 200 && status < 300:
		return nil
	case access.IsIdempotentRevokeStatus(status, body):
		return nil
	case access.IsTransientStatus(status):
		return fmt.Errorf("ga4: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("ga4: revoke status %d: %s", status, string(body))
	}
}

func (c *GA4AccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("ga4: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodGet, c.userLinkURL(cfg, user), nil)
	if err != nil {
		return nil, err
	}
	status, body, err := c.doRaw(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("ga4: list entitlements status %d: %s", status, string(body))
	}
	var resp struct {
		Name         string   `json:"name"`
		EmailAddress string   `json:"emailAddress"`
		DirectRoles  []string `json:"directRoles"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("ga4: decode entitlements: %w", err)
	}
	out := make([]access.Entitlement, 0, len(resp.DirectRoles))
	for _, role := range resp.DirectRoles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: role,
			Role:               role,
			Source:             "direct",
		})
	}
	return out, nil
}
