package access

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
)

// mockKeycloakClient records every call so individual tests can
// assert on the create / update payload.
type mockKeycloakClient struct {
	existing map[string]KeycloakIdentityProvider
	created  []KeycloakIdentityProvider
	updated  []KeycloakIdentityProvider
	deleted  []string

	getErr    error
	createErr error
}

func newMockKeycloak() *mockKeycloakClient {
	return &mockKeycloakClient{existing: map[string]KeycloakIdentityProvider{}}
}

func (m *mockKeycloakClient) GetIdentityProvider(_ context.Context, _, alias string) (*KeycloakIdentityProvider, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if idp, ok := m.existing[alias]; ok {
		return &idp, nil
	}
	return nil, ErrKeycloakIdPNotFound
}

func (m *mockKeycloakClient) CreateIdentityProvider(_ context.Context, _ string, idp KeycloakIdentityProvider) error {
	if m.createErr != nil {
		return m.createErr
	}
	m.created = append(m.created, idp)
	m.existing[idp.Alias] = idp
	return nil
}

func (m *mockKeycloakClient) UpdateIdentityProvider(_ context.Context, _, alias string, idp KeycloakIdentityProvider) error {
	m.updated = append(m.updated, idp)
	m.existing[alias] = idp
	return nil
}

func (m *mockKeycloakClient) DeleteIdentityProvider(_ context.Context, _, alias string) error {
	m.deleted = append(m.deleted, alias)
	delete(m.existing, alias)
	return nil
}

// --- Task 12 service basics ---

func TestSSOFederation_DisabledWhenClientNil(t *testing.T) {
	svc := NewSSOFederationService(nil)
	_, _, err := svc.ConfigureBroker(context.Background(), "r", "a", "Alias", &SSOMetadata{Protocol: "oidc"})
	if !errors.Is(err, ErrSSOFederationDisabled) {
		t.Fatalf("want ErrSSOFederationDisabled; got %v", err)
	}
}

func TestSSOFederation_UnsupportedWhenMetadataNil(t *testing.T) {
	svc := NewSSOFederationService(newMockKeycloak())
	_, _, err := svc.ConfigureBroker(context.Background(), "r", "a", "Alias", nil)
	if !errors.Is(err, ErrSSOFederationUnsupported) {
		t.Fatalf("want ErrSSOFederationUnsupported; got %v", err)
	}
}

func TestSSOFederation_RejectsUnknownProtocol(t *testing.T) {
	svc := NewSSOFederationService(newMockKeycloak())
	_, _, err := svc.ConfigureBroker(context.Background(), "r", "a", "Alias", &SSOMetadata{Protocol: "kerberos"})
	if err == nil {
		t.Fatal("expected error for unsupported protocol")
	}
}

func TestSSOFederation_RejectsEmptyRealmOrAlias(t *testing.T) {
	svc := NewSSOFederationService(newMockKeycloak())
	if _, _, err := svc.ConfigureBroker(context.Background(), "", "a", "Alias", &SSOMetadata{Protocol: "oidc"}); err == nil {
		t.Error("expected error for empty realm")
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "r", "", "Alias", &SSOMetadata{Protocol: "oidc"}); err == nil {
		t.Error("expected error for empty alias")
	}
}

func TestSSOFederation_CreateThenUpdate(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://idp.example/.well-known/openid-configuration",
		EntityID:    "https://idp.example",
		SSOLoginURL: "https://idp.example/auth",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "acme", "Acme", meta); err != nil {
		t.Fatalf("first ConfigureBroker: %v", err)
	}
	if len(mc.created) != 1 || mc.created[0].Alias != "acme" || mc.created[0].ProviderID != "oidc" {
		t.Fatalf("first call created = %#v", mc.created)
	}
	// Re-run -> update.
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "acme", "Acme", meta); err != nil {
		t.Fatalf("second ConfigureBroker: %v", err)
	}
	if len(mc.updated) != 1 || mc.updated[0].Alias != "acme" {
		t.Fatalf("second call updated = %#v", mc.updated)
	}
}

func TestSSOFederation_DeleteBroker(t *testing.T) {
	mc := newMockKeycloak()
	mc.existing["acme"] = KeycloakIdentityProvider{Alias: "acme"}
	svc := NewSSOFederationService(mc)
	if err := svc.DeleteBroker(context.Background(), "shieldnet", "acme"); err != nil {
		t.Fatalf("DeleteBroker: %v", err)
	}
	if !reflect.DeepEqual(mc.deleted, []string{"acme"}) {
		t.Fatalf("deleted = %v", mc.deleted)
	}
}

func TestSSOFederation_PropagatesCreateError(t *testing.T) {
	mc := newMockKeycloak()
	mc.createErr = errors.New("conflict")
	svc := NewSSOFederationService(mc)
	_, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "acme", "Acme", &SSOMetadata{Protocol: "oidc"})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

// --- Task 13 wiring: Microsoft Entra ID + Google Workspace ---

func TestSSOFederation_MicrosoftEntraOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://login.microsoftonline.com/tenant-1234/v2.0/.well-known/openid-configuration",
		EntityID:    "https://login.microsoftonline.com/tenant-1234/v2.0",
		SSOLoginURL: "https://login.microsoftonline.com/tenant-1234/oauth2/v2.0/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ms-conn-1", "Microsoft", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q; want oidc", got.ProviderID)
	}
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
	if got.Config["authorizationUrl"] != meta.SSOLoginURL {
		t.Errorf("authorizationUrl = %q", got.Config["authorizationUrl"])
	}
	if got.Config["issuer"] != meta.EntityID {
		t.Errorf("issuer = %q", got.Config["issuer"])
	}
}

func TestSSOFederation_GoogleWorkspaceOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://accounts.google.com/.well-known/openid-configuration",
		EntityID:    "https://accounts.google.com",
		SSOLoginURL: "https://accounts.google.com/o/oauth2/v2/auth",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "google-conn-1", "Google Workspace", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
	if !got.Enabled || !got.TrustEmail {
		t.Errorf("flags = enabled=%v trustEmail=%v", got.Enabled, got.TrustEmail)
	}
}

// --- Task 14 wiring: Generic SAML + Generic OIDC ---

func TestSSOFederation_GenericSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:            "saml",
		MetadataURL:         "https://idp.corp.example/saml/metadata",
		EntityID:            "https://idp.corp.example",
		SSOLoginURL:         "https://idp.corp.example/saml/sso",
		SSOLogoutURL:        "https://idp.corp.example/saml/slo",
		SigningCertificates: []string{"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----"},
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "generic-saml-1", "Corp IdP", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["singleSignOnServiceUrl"] != meta.SSOLoginURL {
		t.Errorf("singleSignOnServiceUrl = %q", got.Config["singleSignOnServiceUrl"])
	}
	if got.Config["singleLogoutServiceUrl"] != meta.SSOLogoutURL {
		t.Errorf("singleLogoutServiceUrl = %q", got.Config["singleLogoutServiceUrl"])
	}
	if !contains(got.Config["signingCertificate"], "ABC") {
		t.Errorf("signingCertificate = %q", got.Config["signingCertificate"])
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
}

func TestSSOFederation_GenericOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://idp.corp.example/.well-known/openid-configuration",
		EntityID:    "https://idp.corp.example",
		SSOLoginURL: "https://idp.corp.example/oauth2/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "generic-oidc-1", "Corp OIDC", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["issuer"] != meta.EntityID {
		t.Errorf("issuer = %q", got.Config["issuer"])
	}
}

// --- Task 15 wiring: Okta + Ping Identity ---

func TestSSOFederation_OktaOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://corp.okta.com/.well-known/openid-configuration",
		EntityID:    "https://corp.okta.com",
		SSOLoginURL: "https://corp.okta.com/oauth2/default/v1/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "okta-1", "Okta", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.Config["authorizationUrl"] != meta.SSOLoginURL {
		t.Errorf("authorizationUrl = %q", got.Config["authorizationUrl"])
	}
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
}

func TestSSOFederation_PingIdentityOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://auth.pingone.com/env-id/.well-known/openid-configuration",
		EntityID:    "https://auth.pingone.com/env-id",
		SSOLoginURL: "https://auth.pingone.com/env-id/as/authorization",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ping-1", "Ping Identity", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.Config["issuer"] != meta.EntityID {
		t.Errorf("issuer = %q", got.Config["issuer"])
	}
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
}

// --- Phase 10 wiring: SAML connectors (Task 11) ---

func TestSSOFederation_BambooHRSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.bamboohr.com/saml/metadata",
		EntityID:    "https://acme.bamboohr.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "bamboo-1", "BambooHR", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
}

func TestSSOFederation_WorkdaySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://wd5-impl-services1.workday.com/acme1/saml2/metadata",
		EntityID:    "https://wd5-impl-services1.workday.com/acme1",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "workday-1", "Workday", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_ZendeskSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.zendesk.com/access/saml/metadata",
		EntityID:    "https://acme.zendesk.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zendesk-1", "Zendesk", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
}

func TestSSOFederation_DropboxBusinessSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.dropbox.com/saml_login/metadata",
		EntityID:    "https://www.dropbox.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "dropbox-1", "Dropbox Business", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

func TestSSOFederation_SalesforceSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.my.salesforce.com/identity/saml/metadata",
		EntityID:    "https://acme.my.salesforce.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sf-1", "Salesforce", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_GitHubSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://github.com/organizations/acme/saml/metadata",
		EntityID:    "https://github.com/organizations/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gh-1", "GitHub", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
}

// --- Phase 10 wiring: OIDC / Atlassian / Entra connectors (Task 12) ---

func TestSSOFederation_Auth0OIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://uney.us.auth0.com/.well-known/openid-configuration",
		EntityID:    "https://uney.us.auth0.com/",
		SSOLoginURL: "https://uney.us.auth0.com/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "auth0-1", "Auth0", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["issuer"] != meta.EntityID {
		t.Errorf("issuer = %q", got.Config["issuer"])
	}
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
}

func TestSSOFederation_GitLabGroupSAML(t *testing.T) {
	// GitLab returns SAML group metadata.
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://gitlab.com/groups/12345/-/saml/metadata",
		EntityID:    "https://gitlab.com/groups/12345",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gitlab-1", "GitLab", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

func TestSSOFederation_JiraAtlassianSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.atlassian.net/admin/saml/metadata",
		EntityID:    "https://acme.atlassian.net",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "jira-1", "Jira", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

func TestSSOFederation_SlackEnterpriseSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.slack.com/sso/saml/metadata",
		EntityID:    "https://slack.com/E0123ABCD",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "slack-1", "Slack Enterprise", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

func TestSSOFederation_MSTeamsEntraSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.microsoftonline.com/tenant-1234/federationmetadata/2007-06/federationmetadata.xml",
		EntityID:    "https://sts.windows.net/tenant-1234/",
		SSOLoginURL: "https://login.microsoftonline.com/tenant-1234/saml2",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "msteams-1", "Microsoft Teams", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["singleSignOnServiceUrl"] != meta.SSOLoginURL {
		t.Errorf("singleSignOnServiceUrl = %q", got.Config["singleSignOnServiceUrl"])
	}
}

// --- Phase 10 wiring batch 4: SSO federation for 5 more connectors ---

func TestSSOFederation_CloudflareAccessSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.cloudflareaccess.com/cdn-cgi/access/saml-metadata",
		EntityID:    "https://acme.cloudflareaccess.com",
		SSOLoginURL: "https://acme.cloudflareaccess.com/cdn-cgi/access/sso",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "cloudflare-1", "Cloudflare Access", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
}

func TestSSOFederation_RipplingSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.rippling.com/api/platform/saml/idp_metadata/abc123",
		EntityID:    "https://app.rippling.com/saml/abc123",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "rippling-1", "Rippling", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_ForgeRockOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://idm.corp.example/.well-known/openid-configuration",
		EntityID:    "https://idm.corp.example",
		SSOLoginURL: "https://idm.corp.example/oauth2/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "forgerock-1", "ForgeRock", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["metadataUrl"] != meta.MetadataURL {
		t.Errorf("metadataUrl = %q", got.Config["metadataUrl"])
	}
}

func TestSSOFederation_KeeperSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://keepersecurity.com/api/rest/sso/saml/metadata/abc123",
		EntityID:    "https://keepersecurity.com/sso/abc123",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "keeper-1", "Keeper Enterprise", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

func TestSSOFederation_OpenAIEnterpriseSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://platform.openai.com/api/saml/metadata/org-abc",
		EntityID:    "https://platform.openai.com/org-abc",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "openai-1", "OpenAI Enterprise", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
}

// Zoom intentionally has no native SSO metadata; verifies the
// service returns ErrSSOFederationUnsupported for nil metadata so
// callers can downgrade gracefully without recording a configuration
// failure.
func TestSSOFederation_ZoomUnsupported(t *testing.T) {
	svc := NewSSOFederationService(newMockKeycloak())
	_, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zoom-1", "Zoom", nil)
	if !errors.Is(err, ErrSSOFederationUnsupported) {
		t.Fatalf("err = %v; want ErrSSOFederationUnsupported", err)
	}
}

// TestHTTPKeycloakClient_EscapesURLPathSegments asserts that
// realm/alias values containing reserved characters are percent-encoded
// before being interpolated into the Admin REST path so they cannot
// alter the targeted endpoint. Without escaping a value like
// "tenant-a/../tenant-b" would silently address a different realm's
// resources.
func TestHTTPKeycloakClient_EscapesURLPathSegments(t *testing.T) {
	var (
		mu    sync.Mutex
		paths []string
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"alias":"x","providerId":"oidc","enabled":true}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	client := NewHTTPKeycloakClient(server.URL, func(_ context.Context) (string, error) {
		return "test-token", nil
	})

	const (
		nastyRealm = "tenant a/../tenant-b"
		nastyAlias = "okta?x=1#frag"
	)
	idp := KeycloakIdentityProvider{Alias: nastyAlias, ProviderID: "oidc", Enabled: true}

	if _, err := client.GetIdentityProvider(context.Background(), nastyRealm, nastyAlias); err != nil {
		t.Fatalf("GetIdentityProvider: %v", err)
	}
	if err := client.CreateIdentityProvider(context.Background(), nastyRealm, idp); err != nil {
		t.Fatalf("CreateIdentityProvider: %v", err)
	}
	if err := client.UpdateIdentityProvider(context.Background(), nastyRealm, nastyAlias, idp); err != nil {
		t.Fatalf("UpdateIdentityProvider: %v", err)
	}
	if err := client.DeleteIdentityProvider(context.Background(), nastyRealm, nastyAlias); err != nil {
		t.Fatalf("DeleteIdentityProvider: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 4 {
		t.Fatalf("expected 4 requests; got %d (%v)", len(paths), paths)
	}

	const (
		// url.PathEscape encodes "/" as %2F, " " as %20, "?" as %3F,
		// "#" as %23, ".." as ".." (dots are allowed but the surrounding
		// "/" is escaped, defusing path traversal).
		wantEscapedRealm = "tenant%20a%2F..%2Ftenant-b"
		wantEscapedAlias = "okta%3Fx=1%23frag"
	)
	wantInstancesBase := "/admin/realms/" + wantEscapedRealm + "/identity-providers/instances"
	wantAliasPath := wantInstancesBase + "/" + wantEscapedAlias

	if paths[0] != wantAliasPath {
		t.Errorf("GET path = %q; want %q", paths[0], wantAliasPath)
	}
	if paths[1] != wantInstancesBase {
		t.Errorf("POST path = %q; want %q", paths[1], wantInstancesBase)
	}
	if paths[2] != wantAliasPath {
		t.Errorf("PUT path = %q; want %q", paths[2], wantAliasPath)
	}
	if paths[3] != wantAliasPath {
		t.Errorf("DELETE path = %q; want %q", paths[3], wantAliasPath)
	}
	// Defense-in-depth: ensure no raw "/" leaked into the realm slot.
	for i, p := range paths {
		if contains(p[len("/admin/realms/"):], "/tenant-b") {
			t.Errorf("path[%d] = %q contains un-escaped traversal", i, p)
		}
	}
}

// contains is a substring helper that avoids pulling in `strings` for
// just one use.
func contains(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
