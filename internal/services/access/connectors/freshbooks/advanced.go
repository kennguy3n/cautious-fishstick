package freshbooks

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

// Phase 10 advanced-capability mapping for FreshBooks:
//
//   - ProvisionAccess  -> PUT    /accounting/account/{id}/users/staffs/{staff_id}
//   - RevokeAccess     -> DELETE /accounting/account/{id}/users/staffs/{staff_id}
//   - ListEntitlements -> GET    /accounting/account/{id}/users/staffs
//
// AccessGrant maps:
//   - grant.UserExternalID     -> FreshBooks staff_id
//   - grant.ResourceExternalID -> FreshBooks role id (or "managed_user")
//
// Bearer auth via FreshBooksAccessConnector.newRequest.

func freshbooksValidateGrant(g access.AccessGrant) error {
	if strings.TrimSpace(g.UserExternalID) == "" {
		return errors.New("freshbooks: grant.UserExternalID is required")
	}
	if strings.TrimSpace(g.ResourceExternalID) == "" {
		return errors.New("freshbooks: grant.ResourceExternalID is required")
	}
	return nil
}

func (c *FreshBooksAccessConnector) doRaw(req *http.Request) (int, []byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("freshbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, body, nil
}

func (c *FreshBooksAccessConnector) staffURL(cfg Config, staffID string) string {
	return fmt.Sprintf("%s/accounting/account/%s/users/staffs/%s",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.AccountID)),
		url.PathEscape(strings.TrimSpace(staffID)))
}

func (c *FreshBooksAccessConnector) ProvisionAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := freshbooksValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodPut, c.staffURL(cfg, grant.UserExternalID))
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
		return fmt.Errorf("freshbooks: provision transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("freshbooks: provision status %d: %s", status, string(body))
	}
}

func (c *FreshBooksAccessConnector) RevokeAccess(ctx context.Context, configRaw, secretsRaw map[string]interface{}, grant access.AccessGrant) error {
	if err := freshbooksValidateGrant(grant); err != nil {
		return err
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	req, err := c.newRequest(ctx, secrets, http.MethodDelete, c.staffURL(cfg, grant.UserExternalID))
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
		return fmt.Errorf("freshbooks: revoke transient status %d: %s", status, string(body))
	default:
		return fmt.Errorf("freshbooks: revoke status %d: %s", status, string(body))
	}
}

func (c *FreshBooksAccessConnector) ListEntitlements(ctx context.Context, configRaw, secretsRaw map[string]interface{}, userExternalID string) ([]access.Entitlement, error) {
	user := strings.TrimSpace(userExternalID)
	if user == "" {
		return nil, errors.New("freshbooks: user external id is required")
	}
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/accounting/account/%s/users/staffs",
		c.baseURL(),
		url.PathEscape(strings.TrimSpace(cfg.AccountID)))
	req, err := c.newRequest(ctx, secrets, http.MethodGet, endpoint)
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
		return nil, fmt.Errorf("freshbooks: list staffs status %d: %s", status, string(body))
	}
	var envelope struct {
		Response struct {
			Result struct {
				Staffs []struct {
					ID   interface{} `json:"id"`
					Name string      `json:"role"`
				} `json:"staffs"`
			} `json:"result"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("freshbooks: decode staffs: %w", err)
	}
	out := make([]access.Entitlement, 0, len(envelope.Response.Result.Staffs))
	for _, s := range envelope.Response.Result.Staffs {
		id := strings.TrimSpace(fmt.Sprintf("%v", s.ID))
		if id == "" || id != user {
			continue
		}
		out = append(out, access.Entitlement{
			ResourceExternalID: id,
			Role:               strings.TrimSpace(s.Name),
			Source:             "direct",
		})
	}
	return out, nil
}
