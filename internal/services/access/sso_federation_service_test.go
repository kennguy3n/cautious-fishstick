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

// --- Phase 10 SSO federation batch 4: AWS / Azure / GCP wiring ---

func TestSSOFederation_AWSIAMSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://portal.sso.us-east-1.amazonaws.com/saml/metadata/MDEyMzQ1Njc4OTAyNDU2NzAxMjM",
		EntityID:    "https://portal.sso.us-east-1.amazonaws.com/saml/metadata/MDEyMzQ1Njc4OTAyNDU2NzAxMjM",
		SSOLoginURL: "https://d-1234567890.awsapps.com/start",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "aws-1", "AWS IAM Identity Center", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
	if got.Config["singleSignOnServiceUrl"] != meta.SSOLoginURL {
		t.Errorf("singleSignOnServiceUrl = %q", got.Config["singleSignOnServiceUrl"])
	}
}

func TestSSOFederation_AzureEntraOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0/.well-known/openid-configuration",
		EntityID:    "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
		SSOLoginURL: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "azure-1", "Azure Entra ID", meta); err != nil {
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

func TestSSOFederation_AzureEntraSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:     "saml",
		MetadataURL:  "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/federationmetadata/2007-06/federationmetadata.xml",
		EntityID:     "https://sts.windows.net/11111111-2222-3333-4444-555555555555/",
		SSOLoginURL:  "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2",
		SSOLogoutURL: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2/logout",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "azure-saml-1", "Azure Entra ID (SAML)", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q", got.ProviderID)
	}
	if got.Config["singleLogoutServiceUrl"] != meta.SSOLogoutURL {
		t.Errorf("singleLogoutServiceUrl = %q", got.Config["singleLogoutServiceUrl"])
	}
}

func TestSSOFederation_GCPWorkforcePoolOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://iam.googleapis.com/locations/global/workforcePools/shieldnet-pool/.well-known/openid-configuration",
		EntityID:    "https://iam.googleapis.com/locations/global/workforcePools/shieldnet-pool",
		SSOLoginURL: "https://auth.cloud.google/signin/locations/global/workforcePools/shieldnet-pool",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gcp-1", "GCP Workforce Pool", meta); err != nil {
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

// --- Phase 10 wiring: SSO federation batch 5 (Tasks 17-18) ---

// TestSSOFederation_Phase10Batch5 wires the five operator-supplied
// SSO metadata pairs (SAP Concur, Coupa, LinkedIn Learning, Udemy
// Business — SAML; RingCentral — OIDC) end-to-end through
// SSOFederationService.ConfigureBroker.
func TestSSOFederation_SAPConcurSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://us.api.concursolutions.com/saml2/metadata",
		EntityID:    "https://us.api.concursolutions.com",
		SSOLoginURL: "https://us.api.concursolutions.com/saml2/sso",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "concur-1", "SAP Concur", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["metadataDescriptorUrl"] != meta.MetadataURL {
		t.Errorf("metadataDescriptorUrl = %q", got.Config["metadataDescriptorUrl"])
	}
	if got.Config["singleSignOnServiceUrl"] != meta.SSOLoginURL {
		t.Errorf("singleSignOnServiceUrl = %q", got.Config["singleSignOnServiceUrl"])
	}
}

func TestSSOFederation_CoupaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.coupahost.com/saml/metadata",
		EntityID:    "https://acme.coupahost.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "coupa-1", "Coupa", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_LinkedInLearningSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.linkedin.com/learning/admin/sso/saml-metadata",
		EntityID:    "urn:linkedin.com:learning:acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "linkedin-learning-1", "LinkedIn Learning", meta); err != nil {
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

func TestSSOFederation_UdemyBusinessSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.udemy.com/organization/saml/metadata",
		EntityID:    "https://acme.udemy.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "udemy-1", "Udemy Business", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_RingCentralOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://platform.ringcentral.com/.well-known/openid-configuration",
		EntityID:    "https://platform.ringcentral.com",
		SSOLoginURL: "https://platform.ringcentral.com/restapi/oauth/authorize",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ringcentral-1", "RingCentral", meta); err != nil {
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
}

// TestSSOMetadataFromConfig_HelperBehaviour exercises the shared
// helper at the connector seam: blank metadata URL → nil; populated
// URL → SSOMetadata threaded through Keycloak.
func TestSSOMetadataFromConfig_BlankReturnsNil(t *testing.T) {
	if got := SSOMetadataFromConfig(nil, "saml"); got != nil {
		t.Errorf("nil config: got %v", got)
	}
	if got := SSOMetadataFromConfig(map[string]interface{}{"sso_metadata_url": ""}, "saml"); got != nil {
		t.Errorf("blank URL: got %v", got)
	}
}

func TestSSOMetadataFromConfig_PopulatesFields(t *testing.T) {
	cfg := map[string]interface{}{
		"sso_metadata_url": "https://idp.example.com/saml/metadata",
		"sso_entity_id":    "https://idp.example.com",
		"sso_login_url":    "https://idp.example.com/saml/sso",
		"sso_logout_url":   "https://idp.example.com/saml/slo",
	}
	got := SSOMetadataFromConfig(cfg, "saml")
	if got == nil {
		t.Fatalf("expected SSOMetadata, got nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q", got.Protocol)
	}
	if got.MetadataURL != cfg["sso_metadata_url"].(string) {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != cfg["sso_entity_id"].(string) {
		t.Errorf("EntityID = %q", got.EntityID)
	}
	if got.SSOLoginURL != cfg["sso_login_url"].(string) {
		t.Errorf("SSOLoginURL = %q", got.SSOLoginURL)
	}
	if got.SSOLogoutURL != cfg["sso_logout_url"].(string) {
		t.Errorf("SSOLogoutURL = %q", got.SSOLogoutURL)
	}
}

// TestSSOFederation_Batch6 (Phase 10 SSO batch 6) verifies the
// end-to-end broker flow for the 5 newly-wired connectors:
// HubSpot, Notion, Box, PagerDuty, Sentry. Each connector federates
// SSO via SAML 2.0 through the SSOMetadataFromConfig helper.
func TestSSOFederation_HubSpotSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.hubapi.com/sso/saml/metadata",
		EntityID:    "https://app.hubspot.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "hubspot-1", "HubSpot", meta); err != nil {
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

func TestSSOFederation_NotionSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.notion.so/api/v3/saml/metadata",
		EntityID:    "https://www.notion.so/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "notion-1", "Notion", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_BoxSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.box.com/2.0/sso/saml/metadata",
		EntityID:    "https://app.box.com/saml",
		SSOLoginURL: "https://app.box.com/saml/login",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "box-1", "Box", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["singleSignOnServiceUrl"] != meta.SSOLoginURL {
		t.Errorf("singleSignOnServiceUrl = %q", got.Config["singleSignOnServiceUrl"])
	}
}

func TestSSOFederation_PagerDutySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.pagerduty.com/sso/saml/metadata",
		EntityID:    "https://acme.pagerduty.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "pagerduty-1", "PagerDuty", meta); err != nil {
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

func TestSSOFederation_SentrySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://sentry.io/api/0/organizations/acme/auth-provider/saml/metadata/",
		EntityID:    "https://sentry.io/organizations/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sentry-1", "Sentry", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
	if got.Config["entityId"] != meta.EntityID {
		t.Errorf("entityId = %q", got.Config["entityId"])
	}
}

func TestSSOFederation_JFrogSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.jfrog.io/access/api/v1/saml/metadata",
		EntityID:    "https://acme.jfrog.io",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "jfrog-1", "JFrog", meta); err != nil {
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

func TestSSOFederation_LaunchDarklySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.launchdarkly.com/trust/sso/metadata.xml",
		EntityID:    "https://app.launchdarkly.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ld-1", "LaunchDarkly", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NewRelicSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.newrelic.com/login/saml2-acme/metadata",
		EntityID:    "https://login.newrelic.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "newrelic-1", "New Relic", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SplunkCloudSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.splunkcloud.com/saml/metadata",
		EntityID:    "https://acme.splunkcloud.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "splunk-1", "Splunk Cloud", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SumoLogicSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://service.sumologic.com/saml/metadata",
		EntityID:    "https://service.sumologic.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sumo-1", "Sumo Logic", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DatadogSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.datadoghq.com/account/saml/metadata.xml",
		EntityID:    "https://app.datadoghq.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "datadog-1", "Datadog", meta); err != nil {
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

func TestSSOFederation_FreshdeskSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.freshdesk.com/api/saml/metadata",
		EntityID:    "https://acme.freshdesk.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "freshdesk-1", "Freshdesk", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_FrontSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.frontapp.com/api/1/companies/acme/saml/metadata",
		EntityID:    "https://app.frontapp.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "front-1", "Front", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_AsanaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.asana.com/-/saml/metadata/acme",
		EntityID:    "https://app.asana.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "asana-1", "Asana", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MondaySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.monday.com/saml/metadata",
		EntityID:    "https://acme.monday.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "monday-1", "Monday.com", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_FigmaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.figma.com/api/sso/saml/metadata/acme",
		EntityID:    "https://www.figma.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "figma-1", "Figma", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MiroSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://miro.com/api/v1/sso/saml/metadata?org=acme",
		EntityID:    "https://miro.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "miro-1", "Miro", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_AirtableSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://airtable.com/sso/saml/metadata/acme",
		EntityID:    "https://airtable.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "airtable-1", "Airtable", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SmartsheetSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.smartsheet.com/sso/saml/metadata/acme",
		EntityID:    "https://app.smartsheet.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "smartsheet-1", "Smartsheet", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ClickUpSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.clickup.com/sso/saml/metadata/acme",
		EntityID:    "https://app.clickup.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "clickup-1", "ClickUp", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ZohoCRMSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://accounts.zoho.com/samlauthrequest/acme/metadata",
		EntityID:    "https://crm.zoho.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zoho-crm-1", "Zoho CRM", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_EgnyteSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.egnyte.com/sso/saml/metadata",
		EntityID:    "https://acme.egnyte.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "egnyte-1", "Egnyte", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_KnowBe4SAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://training.knowbe4.com/sso/saml/metadata/acme",
		EntityID:    "https://training.knowbe4.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "knowbe4-1", "KnowBe4", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DockerHubSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://hub.docker.com/orgs/acme/sso/saml/metadata",
		EntityID:    "https://hub.docker.com/orgs/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "docker-hub-1", "Docker Hub", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TerraformCloudSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.terraform.io/sso/saml/metadata/acme",
		EntityID:    "https://app.terraform.io/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "terraform-cloud-1", "Terraform Cloud", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// --- Phase 10 wiring batch 5: SSO federation for 4 more connectors ---

func TestSSOFederation_CrispSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.crisp.chat/sso/saml/metadata/acme",
		EntityID:    "https://app.crisp.chat/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "crisp-1", "Crisp", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ShopifySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.myshopify.com/admin/sso/saml/metadata",
		EntityID:    "https://shopify.com/store/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "shopify-1", "Shopify", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NetSuiteSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://suitetalk.api.netsuite.com/sso/saml/metadata/acme",
		EntityID:    "https://netsuite.com/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "netsuite-1", "NetSuite", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CourseraSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.coursera.org/business/sso/saml/metadata/acme",
		EntityID:    "https://coursera.org/business/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "coursera-1", "Coursera", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DocuSignSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://account.docusign.com/sso/saml/metadata/acme",
		EntityID:    "https://account.docusign.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "docusign-1", "DocuSign", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DocuSignCLMSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://apius.springcm.com/sso/saml/metadata/acme",
		EntityID:    "https://apius.springcm.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "docusign-clm-1", "DocuSign CLM", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GeminiOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://accounts.google.com/.well-known/openid-configuration",
		EntityID:    "https://accounts.google.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gemini-1", "Gemini", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q; want oidc", got.ProviderID)
	}
}

func TestSSOFederation_GustoSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.gusto.com/sso/saml/metadata/acme",
		EntityID:    "https://app.gusto.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gusto-1", "Gusto", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_HibobSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.hibob.com/sso/saml/metadata/acme",
		EntityID:    "https://app.hibob.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "hibob-1", "HiBob", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_HootsuiteSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://hootsuite.com/sso/saml/metadata/acme",
		EntityID:    "https://hootsuite.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "hootsuite-1", "Hootsuite", meta); err != nil {
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

func TestSSOFederation_SproutSocialSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.sproutsocial.com/sso/saml/metadata/acme",
		EntityID:    "https://app.sproutsocial.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sprout-social-1", "Sprout Social", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BufferSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://buffer.com/sso/saml/metadata/acme",
		EntityID:    "https://buffer.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "buffer-1", "Buffer", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MagentoSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.magento.com/sso/saml/metadata",
		EntityID:    "https://acme.magento.com/sso",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "magento-1", "Magento", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SquareSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://squareup.com/sso/saml/metadata/acme",
		EntityID:    "https://squareup.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "square-1", "Square", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TwilioSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.twilio.com/sso/saml/metadata/acme",
		EntityID:    "https://twilio.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "twilio-1", "Twilio", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SendgridSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.sendgrid.com/sso/saml/metadata/acme",
		EntityID:    "https://sendgrid.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sendgrid-1", "Sendgrid", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_VonageSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://dashboard.nexmo.com/sso/saml/metadata/acme",
		EntityID:    "https://vonage.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "vonage-1", "Vonage", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WordPressSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.wordpress.com/wp-json/jetpack/v4/sso/saml/metadata",
		EntityID:    "https://wordpress.com/sso/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wordpress-1", "WordPress", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// TestSSOFederation_Batch17 (Phase 10 SSO batch 17) verifies the
// end-to-end broker flow for the 5 newly-wired Tier-2 connectors:
// Tailscale (OIDC), Heroku (SAML), DigitalOcean (SAML), Vercel (SAML)
// and Netlify (SAML). Each connector federates SSO via the
// SSOMetadataFromConfig helper.
func TestSSOFederation_TailscaleOIDC(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "oidc",
		MetadataURL: "https://login.tailscale.com/.well-known/openid-configuration",
		EntityID:    "https://login.tailscale.com",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "tailscale-1", "Tailscale", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "oidc" {
		t.Errorf("ProviderID = %q; want oidc", got.ProviderID)
	}
}

func TestSSOFederation_HerokuSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://sso.heroku.com/saml/teams/acme/metadata",
		EntityID:    "https://sso.heroku.com/saml/teams/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "heroku-1", "Heroku", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DigitalOceanSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://cloud.digitalocean.com/sso/saml/acme/metadata",
		EntityID:    "https://cloud.digitalocean.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "digitalocean-1", "DigitalOcean", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_VercelSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://vercel.com/sso/saml/teams/acme/metadata",
		EntityID:    "https://vercel.com/sso/saml/teams/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "vercel-1", "Vercel", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NetlifySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.netlify.com/sso/saml/acme/metadata",
		EntityID:    "https://app.netlify.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "netlify-1", "Netlify", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// Phase 10 batch 17 — wire 5 more connectors whose GetSSOMetadata now
// surfaces operator-supplied SAML metadata via
// access.SSOMetadataFromConfig: anvyl, expensify, navan, recurly,
// chargebee. The tests below verify ConfigureBroker accepts the
// operator-supplied URL and registers a Keycloak SAML broker.

func TestSSOFederation_AnvylSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.anvyl.com/sso/saml/acme/metadata",
		EntityID:    "https://app.anvyl.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "anvyl-1", "Anvyl", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ExpensifySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.expensify.com/sso/saml/acme/metadata",
		EntityID:    "https://www.expensify.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "expensify-1", "Expensify", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NavanSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.navan.com/sso/saml/acme/metadata",
		EntityID:    "https://app.navan.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "navan-1", "Navan", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_RecurlySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.recurly.com/sso/saml/acme/metadata",
		EntityID:    "https://app.recurly.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "recurly-1", "Recurly", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ChargebeeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.chargebee.com/sso/saml/acme/metadata",
		EntityID:    "https://app.chargebee.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "chargebee-1", "Chargebee", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CircleCISAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://circleci.com/sso/saml/acme/metadata",
		EntityID:    "https://circleci.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "circleci-1", "CircleCI", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CrowdStrikeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://falcon.crowdstrike.com/sso/saml/acme/metadata",
		EntityID:    "https://falcon.crowdstrike.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "crowdstrike-1", "CrowdStrike", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GrafanaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://grafana.acme.com/saml/metadata",
		EntityID:    "https://grafana.acme.com/saml/metadata",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "grafana-1", "Grafana", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_HeapSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://heapanalytics.com/sso/saml/acme/metadata",
		EntityID:    "https://heapanalytics.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "heap-1", "Heap", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NetskopeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.goskope.com/sso/saml/metadata",
		EntityID:    "https://acme.goskope.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "netskope-1", "Netskope", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// TestSSOFederation_Batch20 (Phase 10 SSO batch 20) — verifies SAML metadata
// flows correctly through ConfigureBroker for the connectors whose
// GetSSOMetadata returns access.SSOMetadataFromConfig(configRaw, "saml").

func TestSSOFederation_TypeformSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.typeform.com/sso/saml/metadata",
		EntityID:    "https://api.typeform.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "typeform-1", "Typeform", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SurveyMonkeySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.surveymonkey.com/sso/saml/metadata",
		EntityID:    "https://api.surveymonkey.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "surveymonkey-1", "SurveyMonkey", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_VirusTotalSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.virustotal.com/sso/saml/metadata",
		EntityID:    "https://www.virustotal.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "virustotal-1", "VirusTotal", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ZapierSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.zapier.com/sso/saml/metadata",
		EntityID:    "https://api.zapier.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zapier-1", "Zapier", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PaloAltoSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.prismacloud.io/sso/saml/metadata",
		EntityID:    "https://api.prismacloud.io/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "paloalto-1", "PaloAlto", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GhostSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.ghost.org/sso/saml/metadata",
		EntityID:    "https://api.ghost.org/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ghost-1", "Ghost", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BigCommerceSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.bigcommerce.com/sso/saml/metadata",
		EntityID:    "https://api.bigcommerce.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "bigcommerce-1", "BigCommerce", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WooCommerceSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://shop.example.com/wp-json/wc/v3/sso/saml/metadata",
		EntityID:    "https://shop.example.com/wp-json/wc/v3/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "woocommerce-1", "WooCommerce", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WixSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.wixapis.com/sso/saml/metadata",
		EntityID:    "https://www.wixapis.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wix-1", "Wix", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_FullstorySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.fullstory.com/sso/saml/metadata",
		EntityID:    "https://www.fullstory.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "fullstory-1", "Fullstory", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// TestSSOFederation_Batch22 (Phase 10 SSO batch 22) — verifies SAML metadata
// from CopyAI / Jasper / Jotform / Mistral / Make connectors brokers cleanly
// through Keycloak. Each connector returns access.SSOMetadataFromConfig with
// the `sso_metadata_url` and `sso_entity_id` config fields when present.

func TestSSOFederation_CopyAISAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.copy.ai/sso/saml/metadata",
		EntityID:    "https://app.copy.ai/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "copyai-1", "Copy.ai", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_JasperSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.jasper.ai/sso/saml/metadata",
		EntityID:    "https://app.jasper.ai/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "jasper-1", "Jasper", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_JotformSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.jotform.com/sso/saml/metadata",
		EntityID:    "https://www.jotform.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "jotform-1", "Jotform", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MistralSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://console.mistral.ai/sso/saml/metadata",
		EntityID:    "https://console.mistral.ai/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "mistral-1", "Mistral", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MakeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://eu1.make.com/sso/saml/metadata",
		EntityID:    "https://eu1.make.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "make-1", "Make", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_AppFolioSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://my.appfolio.com/sso/saml/metadata",
		EntityID:    "https://my.appfolio.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "appfolio-1", "AppFolio", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BeyondTrustSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://example.beyondtrustcloud.com/sso/saml/metadata",
		EntityID:    "https://example.beyondtrustcloud.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "beyondtrust-1", "BeyondTrust", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BitSightSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://service.bitsighttech.com/sso/saml/metadata",
		EntityID:    "https://service.bitsighttech.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "bitsight-1", "BitSight", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BuildiumSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.buildium.com/sso/saml/metadata",
		EntityID:    "https://app.buildium.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "buildium-1", "Buildium", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_YardiSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.yardione.com/sso/saml/metadata",
		EntityID:    "https://app.yardione.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "yardi-1", "Yardi", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// TestSSOFederation_Batch24 (Phase 10 SSO batch 24) — verifies SAML metadata
// flowing through ConfigureBroker for Checkpoint / Fortinet / Malwarebytes
// / NordLayer admin consoles. ForgeRock IDM (OIDC discovery) covered in
// TestSSOFederation_ForgeRockOIDC above.
func TestSSOFederation_CheckPointSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://portal.checkpoint.com/sso/saml/metadata",
		EntityID:    "https://portal.checkpoint.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "checkpoint-1", "CheckPoint", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_FortinetSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://forticloud.example.com/sso/saml/metadata",
		EntityID:    "https://forticloud.example.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "fortinet-1", "Fortinet", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MalwarebytesSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://cloud.malwarebytes.com/sso/saml/metadata",
		EntityID:    "https://cloud.malwarebytes.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "malwarebytes-1", "Malwarebytes", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NordLayerSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.nordlayer.com/sso/saml/metadata",
		EntityID:    "https://app.nordlayer.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "nordlayer-1", "NordLayer", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// TestSSOFederation_Batch25 (Phase 10 SSO batch 25) — verifies SAML metadata
// flowing through ConfigureBroker for Wufoo / Sophos XG / Practice Fusion /
// GA4 / Intercom admin consoles. The 5th wire (Intercom) is selected from
// outside the batch-25 advanced-cap set because only 4 of those 9 still
// returned nil from GetSSOMetadata; Intercom shipped real ProvisionAccess in
// an earlier batch but kept a stub GetSSOMetadata until this batch.
func TestSSOFederation_WufooSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.wufoo.com/sso/saml/metadata",
		EntityID:    "https://acme.wufoo.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wufoo-1", "Wufoo", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SophosXGSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://firewall.example.com/sso/saml/metadata",
		EntityID:    "https://firewall.example.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sophos-xg-1", "SophosXG", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PracticeFusionSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://static.practicefusion.com/sso/saml/metadata",
		EntityID:    "https://static.practicefusion.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "practice-fusion-1", "PracticeFusion", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GA4SAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://accounts.google.com/sso/saml/metadata",
		EntityID:    "https://analytics.google.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ga4-1", "GA4", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_IntercomSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.intercom.com/sso/saml/metadata",
		EntityID:    "https://app.intercom.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "intercom-1", "Intercom", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

// --- batch 26 SSO federation wires ---------------------------------------
// Six more connectors (ActiveCampaign, Brex, Close, Drift, Gong,
// HelpScout) flipped from `return nil, nil` to
// access.SSOMetadataFromConfig(configRaw, "saml") in this batch. The
// underlying advanced caps (Provision/Revoke/List) already shipped in
// earlier batches; this batch only widens the SSOFederationService
// coverage so operator-supplied SAML metadata flows through
// ConfigureBroker for these workspaces too.

func TestSSOFederation_ActiveCampaignSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.activehosted.com/sso/saml/metadata",
		EntityID:    "https://acme.activehosted.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "activecampaign-1", "ActiveCampaign", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BrexSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://dashboard.brex.com/sso/saml/metadata",
		EntityID:    "https://dashboard.brex.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "brex-1", "Brex", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CloseSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.close.com/sso/saml/metadata",
		EntityID:    "https://app.close.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "close-1", "Close", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DriftSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.drift.com/sso/saml/metadata",
		EntityID:    "https://app.drift.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "drift-1", "Drift", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GongSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.gong.io/sso/saml/metadata",
		EntityID:    "https://app.gong.io/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gong-1", "Gong", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_HelpScoutSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://secure.helpscout.net/sso/saml/metadata",
		EntityID:    "https://secure.helpscout.net/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "helpscout-1", "HelpScout", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}


func TestSSOFederation_DiscordSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.discord.com/saml/acme/metadata",
		EntityID:    "https://login.discord.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "discord-1", "Discord", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ApolloSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.apollo.io/sso/saml/acme/metadata",
		EntityID:    "https://app.apollo.io/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "apollo-1", "Apollo", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_FreshBooksSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://my.freshbooks.com/saml/acme/metadata",
		EntityID:    "https://my.freshbooks.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "freshbooks-1", "FreshBooks", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_AlibabaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://signin.alibabacloud.com/saml/acme/metadata",
		EntityID:    "https://signin.alibabacloud.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "alibaba-1", "Alibaba", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BasecampSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://launchpad.37signals.com/saml/acme/metadata",
		EntityID:    "https://launchpad.37signals.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "basecamp-1", "Basecamp", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BrazeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://dashboard.braze.com/sso/saml/acme/metadata",
		EntityID:    "https://dashboard.braze.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "braze-1", "Braze", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CopperSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.copper.com/sso/saml/acme/metadata",
		EntityID:    "https://app.copper.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "copper-1", "Copper", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_DeelSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.deel.com/sso/saml/acme/metadata",
		EntityID:    "https://app.deel.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "deel-1", "Deel", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_GorgiasSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.gorgias.com/sso/saml/metadata",
		EntityID:    "https://acme.gorgias.com/sso/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "gorgias-1", "Gorgias", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_BillDotComSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.bill.com/saml/acme/metadata",
		EntityID:    "https://login.bill.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "billdotcom-1", "BillDotCom", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_KlaviyoSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.klaviyo.com/sso/saml/acme/metadata",
		EntityID:    "https://app.klaviyo.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "klaviyo-1", "Klaviyo", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MailchimpSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.mailchimp.com/saml/acme/metadata",
		EntityID:    "https://login.mailchimp.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "mailchimp-1", "Mailchimp", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MixpanelSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://mixpanel.com/sso/saml/acme/metadata",
		EntityID:    "https://mixpanel.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "mixpanel-1", "Mixpanel", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PandaDocSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.pandadoc.com/sso/saml/acme/metadata",
		EntityID:    "https://app.pandadoc.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "pandadoc-1", "PandaDoc", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SegmentSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.segment.com/sso/saml/acme/metadata",
		EntityID:    "https://app.segment.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "segment-1", "Segment", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_StripeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://dashboard.stripe.com/sso/saml/acme/metadata",
		EntityID:    "https://dashboard.stripe.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "stripe-1", "Stripe", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SalesloftSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.salesloft.com/sso/saml/acme/metadata",
		EntityID:    "https://app.salesloft.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "salesloft-1", "Salesloft", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PipedriveSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.pipedrive.com/sso/saml/acme/metadata",
		EntityID:    "https://app.pipedrive.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "pipedrive-1", "Pipedrive", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ClioSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.clio.com/sso/saml/acme/metadata",
		EntityID:    "https://app.clio.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "clio-1", "Clio", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_CloudSigmaSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://zrh.cloudsigma.com/saml/acme/metadata",
		EntityID:    "https://zrh.cloudsigma.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "cloudsigma-1", "CloudSigma", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_HelloSignSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.hellosign.com/sso/saml/acme/metadata",
		EntityID:    "https://app.hellosign.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "hellosign-1", "HelloSign", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_InsightlySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.na1.insightly.com/sso/saml/acme/metadata",
		EntityID:    "https://api.na1.insightly.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "insightly-1", "Insightly", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_IroncladSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://ironcladapp.com/sso/saml/acme/metadata",
		EntityID:    "https://ironcladapp.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ironclad-1", "Ironclad", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_LinodeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.linode.com/saml/acme/metadata",
		EntityID:    "https://login.linode.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "linode-1", "Linode", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_LiveChatSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://accounts.livechat.com/sso/saml/acme/metadata",
		EntityID:    "https://accounts.livechat.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "livechat-1", "LiveChat", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_LoomSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.loom.com/sso/saml/acme/metadata",
		EntityID:    "https://www.loom.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "loom-1", "Loom", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MezmoSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.mezmo.com/sso/saml/acme/metadata",
		EntityID:    "https://app.mezmo.com/sso/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "mezmo-1", "Mezmo", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PaychexSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.paychex.com/saml/acme/metadata",
		EntityID:    "https://login.paychex.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "paychex-1", "Paychex", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PayPalSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.paypal.com/saml/acme/metadata",
		EntityID:    "https://www.paypal.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "paypal-1", "PayPal", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PersonioSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.personio.com/saml/acme/metadata",
		EntityID:    "https://app.personio.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "personio-1", "Personio", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PlaidSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://dashboard.plaid.com/saml/acme/metadata",
		EntityID:    "https://dashboard.plaid.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "plaid-1", "Plaid", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_RampSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.ramp.com/saml/acme/metadata",
		EntityID:    "https://app.ramp.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ramp-1", "Ramp", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TeamworkSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://teamwork.com/saml/acme/metadata",
		EntityID:    "https://teamwork.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "teamwork-1", "Teamwork", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WrikeSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://www.wrike.com/saml/acme/metadata",
		EntityID:    "https://www.wrike.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wrike-1", "Wrike", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_XeroSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://login.xero.com/saml/acme/metadata",
		EntityID:    "https://login.xero.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "xero-1", "Xero", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ZenefitsSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://secure.zenefits.com/saml/acme/metadata",
		EntityID:    "https://secure.zenefits.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zenefits-1", "Zenefits", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_Rapid7SAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://insight.rapid7.com/saml/acme/metadata",
		EntityID:    "https://insight.rapid7.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "rapid7-1", "Rapid7", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SentinelOneSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.sentinelone.net/saml/metadata",
		EntityID:    "https://acme.sentinelone.net/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sentinelone-1", "SentinelOne", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SnykSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.snyk.io/saml/acme/metadata",
		EntityID:    "https://app.snyk.io/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "snyk-1", "Snyk", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_ZoomSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.zoom.us/saml/metadata",
		EntityID:    "https://acme.zoom.us/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "zoom-1", "Zoom", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TenableSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://cloud.tenable.com/saml/acme/metadata",
		EntityID:    "https://cloud.tenable.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "tenable-1", "Tenable", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SonarCloudSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://sonarcloud.io/saml/acme/metadata",
		EntityID:    "https://sonarcloud.io/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "sonarcloud-1", "SonarCloud", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TrelloSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://id.atlassian.com/saml/acme/metadata",
		EntityID:    "https://id.atlassian.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "trello-1", "Trello", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WasabiSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://console.wasabisys.com/saml/acme/metadata",
		EntityID:    "https://console.wasabisys.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wasabi-1", "Wasabi", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_NamelySAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://acme.namely.com/saml/metadata",
		EntityID:    "https://acme.namely.com/saml",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "namely-1", "Namely", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_QualysSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://qualysguard.qualys.com/saml/acme/metadata",
		EntityID:    "https://qualysguard.qualys.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "qualys-1", "Qualys", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_VultrSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://my.vultr.com/saml/acme/metadata",
		EntityID:    "https://my.vultr.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "vultr-1", "Vultr", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_TravisCISAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://travis-ci.example.com/saml/acme/metadata",
		EntityID:    "https://travis-ci.example.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "travis-ci-1", "Travis CI", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_OVHcloudSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://eu.api.ovh.com/saml/acme/metadata",
		EntityID:    "https://eu.api.ovh.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "ovhcloud-1", "OVHcloud", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_QuipSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://platform.quip.com/saml/acme/metadata",
		EntityID:    "https://platform.quip.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "quip-1", "Quip", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_MyCaseSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://app.mycase.com/saml/acme/metadata",
		EntityID:    "https://app.mycase.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "mycase-1", "MyCase", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_SurveysparrowSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.surveysparrow.com/saml/acme/metadata",
		EntityID:    "https://api.surveysparrow.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "surveysparrow-1", "SurveySparrow", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_PandaDocCLMSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://api.pandadoc.com/saml/acme/metadata",
		EntityID:    "https://api.pandadoc.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "pandadoc-clm-1", "PandaDoc CLM", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
	}
}

func TestSSOFederation_WazuhSAML(t *testing.T) {
	mc := newMockKeycloak()
	svc := NewSSOFederationService(mc)
	meta := &SSOMetadata{
		Protocol:    "saml",
		MetadataURL: "https://wazuh.example.com/saml/acme/metadata",
		EntityID:    "https://wazuh.example.com/saml/acme",
	}
	if _, _, err := svc.ConfigureBroker(context.Background(), "shieldnet", "wazuh-1", "Wazuh", meta); err != nil {
		t.Fatalf("ConfigureBroker: %v", err)
	}
	got := mc.created[0]
	if got.ProviderID != "saml" {
		t.Errorf("ProviderID = %q; want saml", got.ProviderID)
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
