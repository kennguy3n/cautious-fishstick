package zoom

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CheckSSOEnforcement implements access.SSOEnforcementChecker for
// Zoom. The account-settings API exposes the "security" object
// at /accounts/{accountId}/settings?option=security, which
// includes a "sign_in_methods" array. When the account has SSO
// configured AND password sign-in is disabled, the array contains
// only the "sso" entry and the connector reports enforced=true.
//
// Best-effort: transport / authorisation failures surface as a
// non-nil err so callers map the result to "unknown" instead of
// silently treating the account as compliant.
func (c *ZoomAccessConnector) CheckSSOEnforcement(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (bool, string, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return false, "", err
	}
	tok, err := c.accessToken(ctx, cfg, secrets)
	if err != nil {
		return false, "", fmt.Errorf("zoom: sso-enforcement token: %w", err)
	}
	path := "/accounts/" + cfg.AccountID + "/settings?option=security"
	req, err := c.newRequest(ctx, tok, http.MethodGet, path)
	if err != nil {
		return false, "", err
	}
	body, err := c.do(req)
	if err != nil {
		return false, "", fmt.Errorf("zoom: sso-enforcement probe: %w", err)
	}
	var payload struct {
		LoginTypes []string `json:"login_types"`
		SignIn     struct {
			Methods []string `json:"methods"`
		} `json:"sign_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false, "", fmt.Errorf("zoom: decode security settings: %w", err)
	}

	// Older accounts surface the list under "login_types"; newer
	// accounts under "sign_in.methods". Walk both and let either
	// satisfy the enforcement contract.
	methods := append([]string{}, payload.LoginTypes...)
	methods = append(methods, payload.SignIn.Methods...)
	if len(methods) == 0 {
		return false, "Zoom account did not surface a sign-in method list", nil
	}
	hasSSO := false
	hasPassword := false
	for _, m := range methods {
		switch m {
		case "sso", "saml":
			hasSSO = true
		case "password", "email":
			hasPassword = true
		}
	}
	if hasSSO && !hasPassword {
		return true, "Zoom account requires single sign-on for every interactive login", nil
	}
	return false, "Zoom account allows password login alongside SSO", nil
}
