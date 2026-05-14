package jira

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// RevokeUserSessions implements access.SessionRevoker for Jira /
// Atlassian Cloud. It calls DELETE /rest/api/3/user?accountId={id}
// against the cloud-gateway proxy, which invalidates every active
// Atlassian session and refresh token for the supplied account ID.
// Atlassian Admin replicas reconcile within minutes so subsequent
// sign-in attempts must round-trip the federated IdP.
//
// userExternalID is the Atlassian accountId (the same value
// SyncIdentities emits as Identity.ExternalID). 200 / 204 means
// propagated; 404 means the user is already gone and is treated
// as success (idempotent kill switch per Phase 11). Any other
// status returns a non-nil err so the leaver flow logs it but
// continues to the next kill-switch layer.
func (c *JiraAccessConnector) RevokeUserSessions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) error {
	if userExternalID == "" {
		return fmt.Errorf("jira: session revoke: userExternalID is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	fullURL := c.baseURL(cfg) + "/rest/api/3/user?accountId=" + url.QueryEscape(userExternalID)
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, fullURL)
	if err != nil {
		return err
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("jira: session revoke: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Errorf("jira: session revoke status %d: %s", resp.StatusCode, string(body))
}
