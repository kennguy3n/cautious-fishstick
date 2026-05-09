// Package aws implements the access.AccessConnector contract for AWS IAM.
//
// The IAM API is a query-style service: every operation is a POST to
// https://iam.amazonaws.com/ with Action=… in the form body. We use a
// minimal, hand-rolled SigV4 signer (sigv4.go) so we don't pull in the
// full aws-sdk-go-v2 module just for three APIs.
package aws

import (
	"context"
	"encoding/xml"
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
	ProviderName = "aws"
	// IAM is a global service that lives in us-east-1.
	defaultBaseURL = "https://iam.amazonaws.com/"
	defaultRegion  = "us-east-1"
	iamAPIVersion  = "2010-05-08"
)

var ErrNotImplemented = errors.New("aws: capability not implemented in Phase 7")

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Config struct {
	Region       string `json:"aws_region"`
	AccountID    string `json:"aws_account_id"`
}

type Secrets struct {
	AccessKeyID     string `json:"aws_access_key_id"`
	SecretAccessKey string `json:"aws_secret_access_key"`
}

type AWSAccessConnector struct {
	httpClient   func() httpDoer
	urlOverride  string
	timeOverride func() time.Time
}

func New() *AWSAccessConnector { return &AWSAccessConnector{} }
func init()                    { access.RegisterAccessConnector(ProviderName, New()) }

func DecodeConfig(raw map[string]interface{}) (Config, error) {
	if raw == nil {
		return Config{}, errors.New("aws: config is nil")
	}
	var cfg Config
	if v, ok := raw["aws_region"].(string); ok {
		cfg.Region = v
	}
	if v, ok := raw["aws_account_id"].(string); ok {
		cfg.AccountID = v
	}
	return cfg, nil
}

func DecodeSecrets(raw map[string]interface{}) (Secrets, error) {
	if raw == nil {
		return Secrets{}, errors.New("aws: secrets is nil")
	}
	var s Secrets
	if v, ok := raw["aws_access_key_id"].(string); ok {
		s.AccessKeyID = v
	}
	if v, ok := raw["aws_secret_access_key"].(string); ok {
		s.SecretAccessKey = v
	}
	return s, nil
}

func (c Config) validate() error {
	if strings.TrimSpace(c.Region) == "" {
		return errors.New("aws: aws_region is required")
	}
	if !looksLikeAWSRegion(c.Region) {
		return errors.New("aws: aws_region does not look like a valid AWS region (expected e.g. us-east-1)")
	}
	if strings.TrimSpace(c.AccountID) != "" && len(c.AccountID) != 12 {
		return errors.New("aws: aws_account_id must be a 12-digit account ID when set")
	}
	return nil
}

func looksLikeAWSRegion(region string) bool {
	parts := strings.Split(region, "-")
	if len(parts) < 3 {
		return false
	}
	// Reject obviously bogus values; the actual list of regions changes
	// over time, so we only enforce a syntactic shape: a 2–6 letter
	// lowercase geo-prefix, then at least two more dash-separated segments.
	prefix := parts[0]
	if len(prefix) < 2 || len(prefix) > 6 {
		return false
	}
	for _, ch := range prefix {
		if ch < 'a' || ch > 'z' {
			return false
		}
	}
	return true
}

func (s Secrets) validate() error {
	if strings.TrimSpace(s.AccessKeyID) == "" {
		return errors.New("aws: aws_access_key_id is required")
	}
	if strings.TrimSpace(s.SecretAccessKey) == "" {
		return errors.New("aws: aws_secret_access_key is required")
	}
	return nil
}

func (c *AWSAccessConnector) Validate(_ context.Context, configRaw, secretsRaw map[string]interface{}) error {
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

func (c *AWSAccessConnector) baseURL() string {
	if c.urlOverride != "" {
		return strings.TrimRight(c.urlOverride, "/") + "/"
	}
	return defaultBaseURL
}

func (c *AWSAccessConnector) client() httpDoer {
	if c.httpClient != nil {
		return c.httpClient()
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (c *AWSAccessConnector) now() time.Time {
	if c.timeOverride != nil {
		return c.timeOverride()
	}
	return time.Now()
}

func (c *AWSAccessConnector) decodeBoth(configRaw, secretsRaw map[string]interface{}) (Config, Secrets, error) {
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

func (c *AWSAccessConnector) callIAM(ctx context.Context, cfg Config, secrets Secrets, params url.Values) ([]byte, error) {
	if params.Get("Version") == "" {
		params.Set("Version", iamAPIVersion)
	}
	body := params.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL(), strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/xml")
	if err := signRequestSigV4(req, secrets.AccessKeyID, secrets.SecretAccessKey, defaultRegion, "iam", c.now()); err != nil {
		return nil, fmt.Errorf("aws: sign: %w", err)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws: %s: %w", params.Get("Action"), err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("aws: %s: status %d: %s", params.Get("Action"), resp.StatusCode, string(respBody))
	}
	return respBody, nil
}

func (c *AWSAccessConnector) Connect(ctx context.Context, configRaw, secretsRaw map[string]interface{}) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	params := url.Values{}
	params.Set("Action", "GetAccountSummary")
	if _, err := c.callIAM(ctx, cfg, secrets, params); err != nil {
		return fmt.Errorf("aws: connect probe: %w", err)
	}
	return nil
}

func (c *AWSAccessConnector) VerifyPermissions(ctx context.Context, configRaw, secretsRaw map[string]interface{}, capabilities []string) ([]string, error) {
	if err := c.Connect(ctx, configRaw, secretsRaw); err != nil {
		var missing []string
		for _, cap := range capabilities {
			missing = append(missing, fmt.Sprintf("%s (%v)", cap, err))
		}
		return missing, nil
	}
	return nil, nil
}

type getAccountSummaryResult struct {
	XMLName               xml.Name `xml:"GetAccountSummaryResponse"`
	GetAccountSummaryResult struct {
		SummaryMap struct {
			Entries []struct {
				Key   string `xml:"key"`
				Value int    `xml:"value"`
			} `xml:"entry"`
		} `xml:"SummaryMap"`
	} `xml:"GetAccountSummaryResult"`
}

func (c *AWSAccessConnector) CountIdentities(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (int, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return 0, err
	}
	params := url.Values{}
	params.Set("Action", "GetAccountSummary")
	body, err := c.callIAM(ctx, cfg, secrets, params)
	if err != nil {
		return 0, err
	}
	var result getAccountSummaryResult
	if err := xml.Unmarshal(body, &result); err != nil {
		return 0, fmt.Errorf("aws: decode GetAccountSummary: %w", err)
	}
	for _, e := range result.GetAccountSummaryResult.SummaryMap.Entries {
		if e.Key == "Users" {
			return e.Value, nil
		}
	}
	return 0, nil
}

type listUsersResponse struct {
	XMLName         xml.Name `xml:"ListUsersResponse"`
	ListUsersResult struct {
		IsTruncated bool   `xml:"IsTruncated"`
		Marker      string `xml:"Marker"`
		Users       []struct {
			UserName   string `xml:"UserName"`
			UserID     string `xml:"UserId"`
			Arn        string `xml:"Arn"`
			Path       string `xml:"Path"`
			CreateDate string `xml:"CreateDate"`
		} `xml:"Users>member"`
	} `xml:"ListUsersResult"`
}

func (c *AWSAccessConnector) SyncIdentities(
	ctx context.Context,
	configRaw, secretsRaw map[string]interface{},
	checkpoint string,
	handler func(batch []*access.Identity, nextCheckpoint string) error,
) error {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return err
	}
	marker := checkpoint
	for {
		params := url.Values{}
		params.Set("Action", "ListUsers")
		params.Set("MaxItems", "100")
		if marker != "" {
			params.Set("Marker", marker)
		}
		body, err := c.callIAM(ctx, cfg, secrets, params)
		if err != nil {
			return err
		}
		var resp listUsersResponse
		if err := xml.Unmarshal(body, &resp); err != nil {
			return fmt.Errorf("aws: decode ListUsers: %w", err)
		}
		identities := make([]*access.Identity, 0, len(resp.ListUsersResult.Users))
		for _, u := range resp.ListUsersResult.Users {
			identities = append(identities, &access.Identity{
				ExternalID:  u.UserID,
				Type:        access.IdentityTypeUser,
				DisplayName: u.UserName,
				Email:       "",
				Status:      "active",
				RawData:     map[string]interface{}{"arn": u.Arn, "path": u.Path, "create_date": u.CreateDate},
			})
		}
		next := ""
		if resp.ListUsersResult.IsTruncated {
			next = resp.ListUsersResult.Marker
		}
		if err := handler(identities, next); err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		marker = next
	}
}

func (c *AWSAccessConnector) ProvisionAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *AWSAccessConnector) RevokeAccess(_ context.Context, _, _ map[string]interface{}, _ access.AccessGrant) error {
	return ErrNotImplemented
}
func (c *AWSAccessConnector) ListEntitlements(_ context.Context, _, _ map[string]interface{}, _ string) ([]access.Entitlement, error) {
	return nil, ErrNotImplemented
}
func (c *AWSAccessConnector) GetSSOMetadata(_ context.Context, _, _ map[string]interface{}) (*access.SSOMetadata, error) {
	return nil, nil
}

type listAccessKeysResponse struct {
	XMLName              xml.Name `xml:"ListAccessKeysResponse"`
	ListAccessKeysResult struct {
		AccessKeyMetadata []struct {
			AccessKeyID string `xml:"AccessKeyId"`
			Status      string `xml:"Status"`
			CreateDate  string `xml:"CreateDate"`
			UserName    string `xml:"UserName"`
		} `xml:"AccessKeyMetadata>member"`
	} `xml:"ListAccessKeysResult"`
}

// GetCredentialsMetadata returns the access-key age + status by calling
// iam:ListAccessKeys for the caller's identity. The connector never
// echoes the secret access key.
func (c *AWSAccessConnector) GetCredentialsMetadata(ctx context.Context, configRaw, secretsRaw map[string]interface{}) (map[string]interface{}, error) {
	cfg, secrets, err := c.decodeBoth(configRaw, secretsRaw)
	if err != nil {
		return nil, err
	}
	out := map[string]interface{}{
		"provider":         ProviderName,
		"region":           cfg.Region,
		"account_id":       cfg.AccountID,
		"access_key_id":    secrets.AccessKeyID,
	}
	params := url.Values{}
	params.Set("Action", "ListAccessKeys")
	body, err := c.callIAM(ctx, cfg, secrets, params)
	if err != nil {
		return out, nil
	}
	var resp listAccessKeysResponse
	if err := xml.Unmarshal(body, &resp); err != nil {
		return out, nil
	}
	for _, k := range resp.ListAccessKeysResult.AccessKeyMetadata {
		if k.AccessKeyID == secrets.AccessKeyID {
			out["access_key_status"] = k.Status
			out["access_key_created_at"] = k.CreateDate
			out["iam_user_name"] = k.UserName
			break
		}
	}
	return out, nil
}

var _ access.AccessConnector = (*AWSAccessConnector)(nil)
