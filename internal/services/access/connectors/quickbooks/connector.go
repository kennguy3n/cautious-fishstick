// Package quickbooks implements the access.AccessConnector contract for the
// QuickBooks Online Employees query API.
package quickbooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/cautious-fishstick/internal/services/access"
)

const (
	ProviderName = "quickbooks"
	pageSize     = 100
)

var ErrNotImplemented = errors.New("quickbooks: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	RealmID string `json:"realm_id"`
}

type Secrets struct {
	AccessToken string `json:"access_token"`
}

type QuickBooksAccessConnector struct {
	httpClient  func() httpDoer
	urlOverride string
}

func New() *QuickBooksAccessConnector { return &QuickBooksAccessConnector{} }
func init()                           { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("quickbooks: config is nil")
	}
	var cfg Config
	if v, ok := raw["realm_id"].(string); ok {
		cfg.RealmID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("quickbooks: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["access_token"].(string); ok {
		s.AccessToken = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.RealmID) == "" {
		return errors.New("quickbooks: realm_id is required")
	}
	return nil
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessToken) == "" {
		return errors.New("quickbooks: access_token is required")
	}
	return nil
}

func (c *QuickBooksAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *QuickBooksAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/")
	}
	return "https://quickbooks.api.intuit.com"
}

func (c *QuickBooksAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *QuickBooksAccessConnector) newRequest(ctx context.Context, secrets Secrets, method, fullURL string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(secrets.AccessToken))
	return req, nil
}

func (c *QuickBooksAccessConnector) do(req *http.Request) ([]byte, error) {
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("quickbooks: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("quickbooks: %s %s: status %d: %s", req.Method, req.URL.Path, resp.StatusCode, string(body))
	}
	return body, nil
}

func (c *QuickBooksAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *QuickBooksAccessConnector) queryURL(cfg Config, query string) string {
	q := url.Values{}
	q.Set("query", query)
	q.Set("minorversion", "65")
	return fmt.Sprintf("%s/v3/company/%s/query?%s", c.baseURL(), cfg.RealmID, q.Encode())
}

func (c *QuickBooksAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	probe := c.queryURL(cfg, "SELECT COUNT(*) FROM Employee")
	req, err := c.newRequest(ctx, secrets, http.MethodGet, probe)
	if err != nil {
		return err
	}
	if _, err := c.do(req); err != nil {
		return fmt.Errorf("quickbooks: connect probe: %w", err)
	}
	return nil
}

func (c *QuickBooksAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type qbEmployee struct {
	ID           string `json:"Id"`
	GivenName    string `json:"GivenName"`
	FamilyName   string `json:"FamilyName"`
	DisplayName  string `json:"DisplayName"`
	Active       bool   `json:"Active"`
	PrimaryEmail struct {
		Address string `json:"Address"`
	} `json:"PrimaryEmailAddr"`
}

type qbQueryResponse struct {
	QueryResponse struct {
		Employee      []qbEmployee `json:"Employee"`
		StartPosition int          `json:"startPosition"`
		MaxResults    int          `json:"maxResults"`
		TotalCount    int          `json:"totalCount"`
	} `json:"QueryResponse"`
}

func (c *QuickBooksAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	count := 0
	err := c.SyncIdentities(ctx, configRaw, secretsRaw, "", func(b []*access.Identity, _ string) error {
		count += len(b)
		return nil
	})
	return count, err
}

func (c *QuickBooksAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	start := 1
	if checkpoint != "" {
		fmt.Sscanf(checkpoint, "%d", &start)
		if start < 1 {
			start = 1
		}
	}
	for {
		query := fmt.Sprintf("SELECT * FROM Employee STARTPOSITION %d MAXRESULTS %d", start, pageSize)
		req, err := c.newRequest(ctx, secrets, http.MethodGet, c.queryURL(cfg, query))
		if err != nil {
			return err
		}
		body, err := c.do(req)
		if err != nil {
			return err
		}
		var resp qbQueryResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("quickbooks: decode query: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.QueryResponse.Employee))
		for _, e := range resp.QueryResponse.Employee {
			display := e.DisplayName
			if display == "" {
				display = strings.TrimSpace(e.GivenName + " " + e.FamilyName)
			}
			status := "active"
			if !e.Active {
				status = "inactive"
			}
			identities = append(identities, &access.Identity{
				ExternalID:  e.ID,
				Type:        access.IdentityTypeUser,
				DisplayName: display,
				Email:       e.PrimaryEmail.Address,
				Status:      status,
			})
		}
		next := ""
		if len(resp.QueryResponse.Employee) >= pageSize {
			next = fmt.Sprintf("%d", start+pageSize)
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		start += pageSize
	}
}

func (c *QuickBooksAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *QuickBooksAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *QuickBooksAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *QuickBooksAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

func (c *QuickBooksAccessConnector) GetCredentialsMetadata(_ context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"provider":    ProviderName,
		"realm_id":    cfg.RealmID,
		"auth_type":   "oauth2",
		"token_short": shortToken(secrets.AccessToken),
	}, nil
}

func shortToken(t string) string {
	t = strings.TrimSpace(t)
	if len(t) <= 8 {
		return t
	}
	return t[:4] + "..." + t[len(t)-4:]
}

var _ access.AccessConnector = (*QuickBooksAccessConnector)(nil)
