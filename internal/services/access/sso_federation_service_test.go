package access

import (
	"context"
	"errors"
	"reflect"
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
