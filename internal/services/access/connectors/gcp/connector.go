// Package gcp implements the access.AccessConnector contract for Google
// Cloud IAM via the cloudresourcemanager.projects.getIamPolicy endpoint.
//
// Members of the project IAM policy are flattened into a list of
// access.Identity records (user / serviceAccount / group). The connector
// authenticates via a service-account JSON key with domain-wide
// delegation disabled — no user impersonation is needed because IAM
// queries are performed against the service account's own permissions.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2/google"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName        = "gcp"
	defaultBaseURL      = "https://cloudresourcemanager.googleapis.com"
	cloudPlatformScope  = "https://www.googleapis.com/auth/cloud-platform.read-only"
)

var ErrNotImplemented = errors.New("gcp: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	ProjectID string `json:"project_id"`
}

type Secrets struct {
	ServiceAccountJSON string `json:"service_account_json"`
}

type GCPAccessConnector struct {
	httpClient    func(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error)
	urlOverride   string
	tokenOverride func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
}

func New() *GCPAccessConnector { return &GCPAccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("gcp: config is nil")
	}
	var cfg Config
	if v, ok := raw["project_id"].(string); ok {
		cfg.ProjectID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("gcp: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["service_account_json"].(string); ok {
		s.ServiceAccountJSON = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.ProjectID) == "" {
		return errors.New("gcp: project_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.ServiceAccountJSON) == "" {
		return errors.New("gcp: service_account_json is required")
	}
	if !strings.Contains(s.ServiceAccountJSON, "private_key") {
		return errors.New("gcp: service_account_json appears malformed (no private_key)")
	}
	return nil
}

func (c *GCPAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *GCPAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return defaultBaseURL
}

func (c *GCPAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *GCPAccessConnector) cloudResourceClient(ctx context.Context, cfg Config, secrets Secrets) (httpDoer, error) {
	if c.httpClient != nil {
		return c.httpClient(ctx, cfg, secrets)
	}
	if c.tokenOverride != nil {
		return &bearerTransportClient{ctx: ctx, cfg: cfg, secrets: secrets, token: c.tokenOverride, inner: &http.Client{Timeout: 30 * time.Second}}, nil
	}
	jwtConfig, err := google.JWTConfigFromJSON([]byte(secrets.ServiceAccountJSON), cloudPlatformScope)
	if err != nil {
		return nil, fmt.Errorf("gcp: parse service account: %w", err)
	}
	return jwtConfig.Client(ctx), nil
}

type bearerTransportClient struct {
	ctx     context.Context
	cfg     Config
	secrets Secrets
	token   func(ctx context.Context, cfg Config, secrets Secrets) (string, error)
	inner   *http.Client
}

func (b *bearerTransportClient) Do(req *http.Request) (*http.Response, error) {
	tok, err := b.token(b.ctx, b.cfg, b.secrets)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	return b.inner.Do(req)
}

func (c *GCPAccessConnector) doJSON(client httpDoer, ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = strings.NewReader(string(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL()+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	resBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gcp: %s %s: status %d: %s", method, path, resp.StatusCode, string(resBody))
	}
	return resBody, nil
}

func (c *GCPAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	if _, err := c.doJSON(client, ctx, http.MethodGet, "/v1/projects/"+cfg.ProjectID, nil); err != nil {
		return fmt.Errorf("gcp: connect probe: %w", err)
	}
	return nil
}

func (c *GCPAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type iamPolicyResponse struct {
	Bindings []iamBinding `json:"bindings"`
}

type iamBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func (c *GCPAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *GCPAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	_ string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	client, err := c.cloudResourceClient(ctx, cfg, secrets)
	if err != nil {
		return err
	}
	body, err := c.doJSON(client, ctx, http.MethodPost, "/v1/projects/"+cfg.ProjectID+":getIamPolicy", []byte(`{}`))
	if err != nil {
		return err
	}
	var policy iamPolicyResponse
	if err := json.Unmarshal(body, &policy); err != nil {
		return fmt.Errorf("gcp: decode policy: %w", err)
	}
	// Members are scoped under bindings. Dedup across bindings, collapse
	// roles per principal.
	type aggregated struct {
		identity *access.Identity
		roles    []string
	}
	dedup := make(map[string]*aggregated)
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			rec, ok := dedup[m]
			if !ok {
				rec = &aggregated{identity: principalToIdentity(m)}
				dedup[m] = rec
			}
			rec.roles = append(rec.roles, b.Role)
		}
	}
	identities := make([]*access.Identity, 0, len(dedup))
	for _, rec := range dedup {
		if rec.identity == nil {
			continue
		}
		rec.identity.RawData = map[string]interface{}{"roles": rec.roles}
		identities = append(identities, rec.identity)
	}
	return handler(identities, "")
}

func principalToIdentity(member string) *access.Identity {
	idx := strings.Index(member, ":")
	if idx <= 0 {
		return nil
	}
	prefix := member[:idx]
	value := member[idx+1:]
	switch prefix {
	case "user":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeUser,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "serviceAccount":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeServiceAccount,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "group":
		return &access.Identity{
			ExternalID:  value,
			Type:        access.IdentityTypeGroup,
			DisplayName: value,
			Email:       value,
			Status:      "active",
		}
	case "domain", "allUsers", "allAuthenticatedUsers":
		// Skip wildcards — they aren't real principals.
		return nil
	}
	return nil
}

func (c *GCPAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *GCPAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *GCPAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *GCPAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

// GetCredentialsMetadata extracts the service account email + key id from
// the JSON credentials. We never echo the private key.
func (c *GCPAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":   ProviderName,
		"project_id": cfg.ProjectID,
		"auth_type":  "service_account_json",
	}
	var meta struct {
		ClientEmail string `json:"client_email"`
		PrivateKeyID string `json:"private_key_id"`
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
	}
	if err := json.Unmarshal([]byte(secrets.ServiceAccountJSON), &meta); err == nil {
		if meta.ClientEmail != "" {
			out["client_email"] = meta.ClientEmail
		}
		if meta.PrivateKeyID != "" {
			out["private_key_id"] = meta.PrivateKeyID
		}
		if meta.Type != "" {
			out["service_account_type"] = meta.Type
		}
		if meta.ProjectID != "" {
			out["service_account_project_id"] = meta.ProjectID
		}
	}
	return out, nil
}

var _ access.AccessConnector = (*GCPAccessConnector)(nil)
