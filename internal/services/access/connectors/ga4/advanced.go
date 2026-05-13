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
// /v1beta/accounts/{account}/userLinks.
//
// GA4 identifies user links via the auto-generated resource name
// `accounts/{account}/userLinks/{userLinkId}` and exposes no per-email
// lookup endpoint, so the connector canonicalises AccessGrant.UserExternalID
// on the user's email address — the same value that the
// `accounts.userLinks.create` payload accepts as `emailAddress` and that
// SyncIdentities surfaces as Identity.ExternalID. RevokeAccess and
// ListEntitlements paginate /userLinks and filter client-side to resolve
// email → resource name before issuing the per-resource DELETE / GET. A
// full resource name (`accounts/{account}/userLinks/{userLinkId}`) is also
// accepted in case the caller already has it from SyncIdentities.RawData.
//
//   - ProvisionAccess  -> POST   /v1beta/accounts/{account}/userLinks
//   - RevokeAccess     -> list+filter, then DELETE /v1beta/{name}
//   - ListEntitlements -> list+filter, then expose directRoles from the match
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

// userLinkResourceURL builds the absolute URL for an individual userLink
// addressed by its full GA4 resource name (e.g.
// "accounts/123/userLinks/abc"). Per the GA4 Admin v1beta REST contract the
// slashes inside `{name=accounts/*/userLinks/*}` are part of the path and
// must NOT be percent-encoded.
func (c *GA4AccessConnector) userLinkResourceURL(name string) string {
	return c.baseURL() + "/v1beta/" + strings.TrimSpace(name)
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

// findUserLinkByExternalID paginates /userLinks and returns the resource
// name plus the current directRoles for the entry whose emailAddress
// matches userExternalID case-insensitively, or whose full `name` matches
// exactly. Returns ("", nil, nil) when no match is found so RevokeAccess
// can treat repeated revokes as idempotent and ListEntitlements can return
// an empty slice without raising an error.
func (c *GA4AccessConnector) findUserLinkByExternalID(
	ctx context.Context, secrets Secrets, cfg Config, userExternalID string,
) (string, []string, error) {
	want := strings.TrimSpace(userExternalID)
	if want == "" {
		return "", nil, errors.New("ga4: user external id is required")
	}
	base := c.baseURL()
	path := c.userLinksPath(cfg)
	token := ""
	for {
		q := url.Values{"pageSize": []string{fmt.Sprintf("%d", pageSize)}}
		if token != "" {
			q.Set("pageToken", token)
		}
		fullURL := base + path + "?" + q.Encode()
		req, err := c.newRequest(ctx, secrets, http.MethodGet, fullURL)
		if err != nil {
			return "", nil, err
		}
		body, err := c.do(req)
		if err != nil {
			return "", nil, err
		}
		var resp ga4ListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", nil, fmt.Errorf("ga4: decode userLinks: %w", err)
		}
		for _, u := range resp.UserLinks {
			email := strings.TrimSpace(u.EmailAddress)
			name := strings.TrimSpace(u.Name)
			if strings.EqualFold(email, want) || name == want {
				return name, u.DirectRoles, nil
			}
		}
		if strings.TrimSpace(resp.NextPageToken) == "" {
			return "", nil, nil
		}
		token = resp.NextPageToken
	}
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
	name, _, err := c.findUserLinkByExternalID(ctx, secrets, cfg, grant.UserExternalID)
	if err != nil {
		return err
	}
	if name == "" {
		// Already absent — idempotent revoke per PROPOSAL §2.1.
		return nil
	}
	req, err := c.newJSONRequest(ctx, secrets, http.MethodDelete, c.userLinkResourceURL(name), nil)
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
	_, roles, err := c.findUserLinkByExternalID(ctx, secrets, cfg, user)
	if err != nil {
		return nil, err
	}
	out := make([]access.Entitlement, 0, len(roles))
	for _, role := range roles {
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
