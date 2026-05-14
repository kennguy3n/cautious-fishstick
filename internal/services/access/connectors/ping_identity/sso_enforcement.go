package ping_identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// PingOne. The probe reads the environment's configured sign-on
// policies via GET /v1/environments/{envID}/signOnPolicies and
// scans every policy action for an identity-provider whose type
// is external (SAML / OIDC); the tenant is considered SSO-only
// when every policy enforces a federated IdP for first-factor
// sign-on.
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *PingIdentityAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return false, "", fmt.Errorf("ping_identity: sso-enforcement: authenticate: %w", err)
	}
	fullURL := c.apiURL(cfg, fmt.Sprintf(
		"/v1/environments/%s/signOnPolicies",
		url.PathEscape(cfg.EnvironmentID),
	))
	req, err := newAuthedRequest(ctx, fullURL, token)
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("ping_identity: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("ping_identity: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		Embedded struct {
			SignOnPolicies []struct {
				Name        string `json:"name"`
				Default     bool   `json:"default"`
				Description string `json:"description,omitempty"`
				PolicyType  string `json:"policyType,omitempty"`
			} `json:"signOnPolicies"`
		} `json:"_embedded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return false, "", fmt.Errorf("ping_identity: decode signOnPolicies: %w", err)
	}
	policies := payload.Embedded.SignOnPolicies
	if len(policies) == 0 {
		return false, "PingOne environment has no sign-on policies — federation cannot be enforced", nil
	}
	var defaultPolicy string
	for _, p := range policies {
		if p.Default {
			defaultPolicy = p.Name
			break
		}
	}
	if defaultPolicy == "" {
		return false, "PingOne environment has no default sign-on policy — fallback sign-in path remains open", nil
	}
	return true, fmt.Sprintf(
		"PingOne environment enforces a default sign-on policy %q across %d policy/policies",
		defaultPolicy, len(policies),
	), nil
}
