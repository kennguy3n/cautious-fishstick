package cloudflare

import (
	"context"
	"strings"
	"testing"
)

func TestGetSSOMetadata_NilWithoutTeamDomain(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{"account_id": "abc"}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got != nil {
		t.Fatalf("got = %+v; want nil", got)
	}
}

func TestGetSSOMetadata_WithTeamDomain(t *testing.T) {
	c := New()
	got, err := c.GetSSOMetadata(context.Background(), map[string]interface{}{"account_id": "abc", "team_domain": "acme"}, nil)
	if err != nil {
		t.Fatalf("GetSSOMetadata: %v", err)
	}
	if got == nil {
		t.Fatal("got = nil")
	}
	if got.Protocol != "saml" {
		t.Errorf("Protocol = %q; want saml", got.Protocol)
	}
	if !strings.Contains(got.MetadataURL, "acme.cloudflareaccess.com") {
		t.Errorf("MetadataURL = %q", got.MetadataURL)
	}
	if got.EntityID != "https://acme.cloudflareaccess.com" {
		t.Errorf("EntityID = %q", got.EntityID)
	}
}
