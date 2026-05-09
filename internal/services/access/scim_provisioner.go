package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SCIMResourceType enumerates the SCIM v2.0 resource kinds the
// generic provisioner client knows how to push. The base SCIM spec
// (RFC 7643) defines /Users and /Groups; downstream providers may
// add custom resource types but the generic client deliberately
// limits itself to the two RFC-mandated kinds.
type SCIMResourceType string

const (
	// SCIMResourceUser is the SCIM /Users endpoint.
	SCIMResourceUser SCIMResourceType = "Users"
	// SCIMResourceGroup is the SCIM /Groups endpoint.
	SCIMResourceGroup SCIMResourceType = "Groups"
)

// DefaultSCIMTimeout is the per-request timeout used when the
// connector config leaves base_url_timeout unset. Tuned slightly
// larger than the typical SaaS SCIM endpoint p99 (≈3s) so transient
// slowness doesn't churn the JML retry loop.
const DefaultSCIMTimeout = 10 * time.Second

// scimProvisionerConfigKey is the canonical config key for the
// SCIM v2.0 base URL. Exposed as a string so connector docs can
// reference it directly.
const scimProvisionerConfigKey = "scim_base_url"

// scimProvisionerSecretKey is the canonical secret key for the
// SCIM v2.0 bearer token (or any literal Authorization header
// value).
const scimProvisionerSecretKey = "scim_auth_header"

// scimProvisionerTimeoutKey is the optional config key for the
// per-request SCIM timeout. The value MUST be a Go time.Duration
// string (e.g. "5s", "1m30s").
const scimProvisionerTimeoutKey = "scim_timeout"

// SCIMClient is the generic SCIM v2.0 client connectors compose to
// satisfy the SCIMProvisioner optional interface. It implements the
// SCIMProvisioner interface from optional_interfaces.go directly —
// connectors with a SCIM v2.0 backend can embed *SCIMClient and
// inherit the three method signatures.
//
// The client owns no per-request state; a single instance can be
// shared across goroutines and across connectors.
type SCIMClient struct {
	// httpClient is overridable so tests can swap in an
	// httptest.Server's Client(). Defaults to http.DefaultClient
	// in NewSCIMClient.
	httpClient *http.Client
}

// NewSCIMClient returns a client backed by http.DefaultClient. Tests
// override the http client via WithHTTPClient.
func NewSCIMClient() *SCIMClient {
	return &SCIMClient{httpClient: http.DefaultClient}
}

// WithHTTPClient replaces the underlying *http.Client. Returns the
// client so callers can chain. Intended for tests + production
// deployments that need a custom transport (e.g. mTLS, custom
// timeouts).
func (c *SCIMClient) WithHTTPClient(h *http.Client) *SCIMClient {
	if h != nil {
		c.httpClient = h
	}
	return c
}

// Sentinel errors returned by SCIMClient. Wrapped with fmt.Errorf so
// callers can errors.Is them without depending on message formats.
var (
	// ErrSCIMRemoteConflict signals the SCIM endpoint returned 409
	// Conflict — the resource already exists upstream. JML callers
	// MAY treat this as a successful no-op idempotent push (per
	// PROPOSAL §5.4 connectors must be idempotent on
	// (UserExternalID, ResourceExternalID)).
	ErrSCIMRemoteConflict = errors.New("scim: remote returned 409 Conflict")

	// ErrSCIMRemoteNotFound signals the SCIM endpoint returned 404
	// Not Found. For DeleteSCIMResource this is treated as a
	// successful no-op idempotent delete; for Push this is a
	// configuration bug and surfaces to the operator.
	ErrSCIMRemoteNotFound = errors.New("scim: remote returned 404 Not Found")

	// ErrSCIMRemoteUnauthorized signals 401 / 403 — the auth
	// header is invalid or the token lacks SCIM scopes. The
	// connector layer should surface this as a validation error
	// during connector verify-permissions.
	ErrSCIMRemoteUnauthorized = errors.New("scim: remote returned 401/403 Unauthorized")

	// ErrSCIMRemoteServer signals a 5xx from the SCIM endpoint;
	// callers retry with exponential backoff.
	ErrSCIMRemoteServer = errors.New("scim: remote returned 5xx")

	// ErrSCIMConfigInvalid signals the config blob is missing
	// scim_base_url or has a malformed URL. Surfaces during
	// connector validation.
	ErrSCIMConfigInvalid = errors.New("scim: config invalid")
)

// PushSCIMUser POSTs the supplied SCIMUser to {scim_base_url}/Users.
// 409 Conflict surfaces as ErrSCIMRemoteConflict; callers MAY treat
// this as success because the SCIM contract requires idempotency on
// the (externalId, userName) tuple.
func (c *SCIMClient) PushSCIMUser(ctx context.Context, config, secrets map[string]interface{}, user SCIMUser) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	body := scimUserPayload{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ExternalID:  user.ExternalID,
		UserName:    user.UserName,
		DisplayName: user.DisplayName,
		Active:      user.Active,
	}
	if user.Email != "" {
		body.Emails = []scimEmail{{Value: user.Email, Primary: true}}
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("scim: marshal user: %w", err)
	}
	if _, err := c.do(ctx, rcfg, http.MethodPost, string(SCIMResourceUser), payload); err != nil {
		return err
	}
	return nil
}

// PushSCIMGroup POSTs the supplied SCIMGroup to {scim_base_url}/Groups.
func (c *SCIMClient) PushSCIMGroup(ctx context.Context, config, secrets map[string]interface{}, group SCIMGroup) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	members := make([]scimGroupMember, 0, len(group.MemberIDs))
	for _, id := range group.MemberIDs {
		members = append(members, scimGroupMember{Value: id})
	}
	body := scimGroupPayload{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		ExternalID:  group.ExternalID,
		DisplayName: group.DisplayName,
		Members:     members,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("scim: marshal group: %w", err)
	}
	if _, err := c.do(ctx, rcfg, http.MethodPost, string(SCIMResourceGroup), payload); err != nil {
		return err
	}
	return nil
}

// DeleteSCIMResource DELETEs {scim_base_url}/{resourceType}/{externalID}.
// 404 from the remote is treated as success (idempotent delete);
// every other non-2xx surfaces as the matching sentinel error.
//
// resourceType MUST be "Users" or "Groups" (case-sensitive, per
// RFC 7644 §3.4.1) — the SCIM spec defines no other resources.
func (c *SCIMClient) DeleteSCIMResource(ctx context.Context, config, secrets map[string]interface{}, resourceType, externalID string) error {
	rcfg, err := readSCIMConfig(config, secrets)
	if err != nil {
		return err
	}
	if externalID == "" {
		return fmt.Errorf("%w: external_id is required for DELETE", ErrSCIMConfigInvalid)
	}
	rt := SCIMResourceType(resourceType)
	if rt != SCIMResourceUser && rt != SCIMResourceGroup {
		return fmt.Errorf("%w: unknown resource type %q", ErrSCIMConfigInvalid, resourceType)
	}
	path := string(rt) + "/" + url.PathEscape(externalID)
	_, err = c.do(ctx, rcfg, http.MethodDelete, path, nil)
	if errors.Is(err, ErrSCIMRemoteNotFound) {
		// SCIM DELETE is idempotent — a 404 means the resource is
		// already gone, which is a successful end state from the
		// caller's perspective.
		return nil
	}
	return err
}

// resolvedSCIMConfig is the parsed view of the (config, secrets)
// maps the client receives. Constructed once per request by
// readSCIMConfig.
type resolvedSCIMConfig struct {
	BaseURL    string
	AuthHeader string
	Timeout    time.Duration
}

// readSCIMConfig parses the (config, secrets) maps into a
// resolvedSCIMConfig and validates required fields. Returns
// ErrSCIMConfigInvalid wrapping the specific reason when validation
// fails so callers can errors.Is against the sentinel.
func readSCIMConfig(config, secrets map[string]interface{}) (resolvedSCIMConfig, error) {
	out := resolvedSCIMConfig{Timeout: DefaultSCIMTimeout}

	rawURL, ok := config[scimProvisionerConfigKey].(string)
	if !ok || strings.TrimSpace(rawURL) == "" {
		return out, fmt.Errorf("%w: %s is required", ErrSCIMConfigInvalid, scimProvisionerConfigKey)
	}
	if _, err := url.Parse(rawURL); err != nil {
		return out, fmt.Errorf("%w: %s unparseable: %v", ErrSCIMConfigInvalid, scimProvisionerConfigKey, err)
	}
	out.BaseURL = rawURL

	if header, ok := secrets[scimProvisionerSecretKey].(string); ok {
		out.AuthHeader = header
	}

	if rawTimeout, ok := config[scimProvisionerTimeoutKey].(string); ok && rawTimeout != "" {
		d, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return out, fmt.Errorf("%w: %s unparseable: %v", ErrSCIMConfigInvalid, scimProvisionerTimeoutKey, err)
		}
		out.Timeout = d
	}

	return out, nil
}

// do issues the HTTP request, applies the auth header, dispatches
// status-code → sentinel mapping, and returns the response body
// for callers that want to parse it. Empty payload is allowed for
// DELETE.
func (c *SCIMClient) do(ctx context.Context, cfg resolvedSCIMConfig, method, path string, payload []byte) ([]byte, error) {
	rctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	endpoint, err := joinSCIMURL(cfg.BaseURL, path)
	if err != nil {
		return nil, err
	}
	var bodyReader io.Reader
	if len(payload) > 0 {
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(rctx, method, endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("scim: build %s %s: %w", method, endpoint, err)
	}
	req.Header.Set("Accept", "application/scim+json")
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if cfg.AuthHeader != "" {
		req.Header.Set("Authorization", cfg.AuthHeader)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scim: %s %s: %w", method, endpoint, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return respBody, nil
	case resp.StatusCode == http.StatusConflict:
		return respBody, fmt.Errorf("%w: %s", ErrSCIMRemoteConflict, truncate(string(respBody), 256))
	case resp.StatusCode == http.StatusNotFound:
		return respBody, fmt.Errorf("%w: %s %s", ErrSCIMRemoteNotFound, method, endpoint)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return respBody, fmt.Errorf("%w: %d", ErrSCIMRemoteUnauthorized, resp.StatusCode)
	case resp.StatusCode >= 500:
		return respBody, fmt.Errorf("%w: %d", ErrSCIMRemoteServer, resp.StatusCode)
	default:
		return respBody, fmt.Errorf("scim: %s %s returned %d: %s", method, endpoint, resp.StatusCode, truncate(string(respBody), 256))
	}
}

// joinSCIMURL appends path to base, handling missing/duplicate
// trailing slashes. Returns the absolute URL string.
func joinSCIMURL(base, path string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSCIMConfigInvalid, err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	return u.String(), nil
}

// truncate caps s at n runes. Used for error messages so a chatty
// SCIM provider does not blow up the audit log.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// scimUserPayload is the wire shape PushSCIMUser sends. The struct
// is package-private; callers see only the SCIMUser DTO.
type scimUserPayload struct {
	Schemas     []string    `json:"schemas"`
	ExternalID  string      `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	DisplayName string      `json:"displayName,omitempty"`
	Active      bool        `json:"active"`
	Emails      []scimEmail `json:"emails,omitempty"`
}

// scimEmail mirrors the SCIM Email multi-valued attribute.
type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

// scimGroupPayload is the wire shape PushSCIMGroup sends.
type scimGroupPayload struct {
	Schemas     []string          `json:"schemas"`
	ExternalID  string            `json:"externalId,omitempty"`
	DisplayName string            `json:"displayName"`
	Members     []scimGroupMember `json:"members,omitempty"`
}

// scimGroupMember mirrors one entry in the SCIM Group.members list.
type scimGroupMember struct {
	Value string `json:"value"`
}

// Verify SCIMClient satisfies the SCIMProvisioner contract from
// optional_interfaces.go at build time. The unused declaration is
// the canonical Go pattern for compile-time interface assertions.
var _ SCIMProvisioner = (*SCIMClient)(nil)
