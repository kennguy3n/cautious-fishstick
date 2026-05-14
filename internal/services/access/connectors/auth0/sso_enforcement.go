package auth0

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Auth0. The probe lists every Auth0 connection (via
// /api/v2/connections) and inspects the strategy field; if every
// active connection uses an enterprise federation strategy (e.g.
// "samlp", "oidc", "okta", "google-apps", "adfs", "waad") and
// none use a password / social strategy, the tenant is considered
// SSO-only.
//
// Best-effort: a transport or authentication failure returns a
// non-nil err so callers map the connector to "unknown" rather
// than "not_enforced".
func (c *Auth0AccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	token, err := c.fetchAccessToken(ctx, cfg, secrets)
	if err != nil {
		return false, "", fmt.Errorf("auth0: sso-enforcement: authenticate: %w", err)
	}
	req, err := c.newAuthedRequest(ctx, cfg, token, http.MethodGet, "/api/v2/connections?per_page=100", nil)
	if err != nil {
		return false, "", err
	}
	resp, err := c.doRaw(req)
	if err != nil {
		return false, "", fmt.Errorf("auth0: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return false, "", fmt.Errorf("auth0: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var conns []struct {
		Name     string `json:"name"`
		Strategy string `json:"strategy"`
		Enabled  *bool  `json:"enabled_clients,omitempty"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&conns); err != nil {
		return false, "", fmt.Errorf("auth0: decode connections: %w", err)
	}
	var openStrategies []string
	enterpriseCount := 0
	for _, conn := range conns {
		switch strings.ToLower(conn.Strategy) {
		case "auth0", "auth0-passwordless", "auth0-adldap",
			"google-oauth2", "facebook", "github",
			"linkedin", "twitter", "microsoft", "windowslive",
			"apple", "yahoo", "amazon", "dropbox", "vkontakte",
			"yandex", "salesforce", "fitbit", "evernote",
			"weibo", "renren", "baidu", "thirtysevensignals",
			"sms", "email":
			openStrategies = append(openStrategies, conn.Name+"/"+conn.Strategy)
		default:
			enterpriseCount++
		}
	}
	if len(openStrategies) > 0 {
		return false, fmt.Sprintf(
			"Auth0 tenant still allows password or social sign-in via %d connection(s): %s",
			len(openStrategies), strings.Join(openStrategies, ", "),
		), nil
	}
	if enterpriseCount == 0 {
		return false, "Auth0 tenant has no active enterprise connections — sign-on policy cannot be enforced", nil
	}
	return true, fmt.Sprintf(
		"Auth0 tenant has only enterprise federation connections active (%d)",
		enterpriseCount,
	), nil
}
