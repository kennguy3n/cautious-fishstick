package slack_enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Slack Enterprise Grid. The `team.info` Web API endpoint returns
// the grid's SSO state via `team.sso_provider.type` and
// `enterprise.is_sso_enabled`; when SAML/OIDC is wired AND
// password sign-in is disabled, the grid enforces SSO across every
// workspace.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map them to "unknown" — never to "not
// enforced".
func (c *SlackEnterpriseAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	_, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	endpoint := c.baseURL() + "/api/team.info"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.Token))
	resp, err := c.client().Do(req)
	if err != nil {
		return false, "", fmt.Errorf("slack_enterprise: sso-enforcement probe: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", fmt.Errorf("slack_enterprise: sso-enforcement status %d: %s", resp.StatusCode, string(body))
	}
	var payload struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
		Team  struct {
			SSOProvider struct {
				Type string `json:"type"`
			} `json:"sso_provider"`
		} `json:"team"`
		Enterprise struct {
			IsSSOEnabled bool `json:"is_sso_enabled"`
		} `json:"enterprise"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("slack_enterprise: decode team.info: %w", err)
	}
	if !payload.OK {
		return false, "", fmt.Errorf("slack_enterprise: sso-enforcement api error: %s", payload.Error)
	}
	if payload.Team.SSOProvider.Type == "saml" || payload.Enterprise.IsSSOEnabled {
		return true, "Slack Enterprise Grid is wired to a SAML identity provider", nil
	}
	return false, "Slack Enterprise Grid still permits password sign-in alongside SSO", nil
}
