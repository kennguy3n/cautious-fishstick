package access

import (
	"testing"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// TestClassifyAccessMode covers every branch of the Phase 11
// classifier so a future regression that silently flips a connector
// from sso_only to api_only (or vice versa) is caught at unit-test
// time. The branches mirror the resolution order documented on
// ClassifyAccessMode:
//
//  1. Explicit operator override via config["access_mode"].
//  2. Private-resource hints (connector_type == tunnel or
//     config["is_private"] / config["self_hosted"] truthy).
//  3. SSO federation succeeded against a connector that advertised
//     SSO metadata.
//  4. Fallback to api_only.
func TestClassifyAccessMode(t *testing.T) {
	type args struct {
		connectorType   string
		config          map[string]interface{}
		hasSSOMetadata  bool
		ssoFederationOK bool
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "explicit_override_tunnel_wins",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"access_mode": "tunnel"},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeTunnel,
		},
		{
			name: "explicit_override_sso_only_wins_over_private_hint",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"access_mode": "sso_only", "is_private": true},
				hasSSOMetadata:  false,
				ssoFederationOK: false,
			},
			want: models.AccessModeSSOOnly,
		},
		{
			name: "explicit_override_api_only_wins_over_sso_success",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"access_mode": "api_only"},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeAPIOnly,
		},
		{
			name: "invalid_override_ignored",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"access_mode": "nonsense"},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeSSOOnly,
		},
		{
			name: "connector_type_tunnel_implies_tunnel",
			args: args{
				connectorType:   "tunnel",
				config:          map[string]interface{}{},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeTunnel,
		},
		{
			name: "is_private_implies_tunnel",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"is_private": true},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeTunnel,
		},
		{
			name: "self_hosted_string_true_implies_tunnel",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"self_hosted": "true"},
				hasSSOMetadata:  false,
				ssoFederationOK: false,
			},
			want: models.AccessModeTunnel,
		},
		{
			name: "sso_metadata_and_federation_ok_implies_sso_only",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeSSOOnly,
		},
		{
			name: "sso_metadata_without_federation_falls_back_to_api_only",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{},
				hasSSOMetadata:  true,
				ssoFederationOK: false,
			},
			want: models.AccessModeAPIOnly,
		},
		{
			name: "default_api_only_when_no_signals",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{},
				hasSSOMetadata:  false,
				ssoFederationOK: false,
			},
			want: models.AccessModeAPIOnly,
		},
		{
			name: "boolean_int_truthy_self_hosted",
			args: args{
				connectorType:   "default",
				config:          map[string]interface{}{"self_hosted": 1},
				hasSSOMetadata:  true,
				ssoFederationOK: true,
			},
			want: models.AccessModeTunnel,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyAccessMode(tc.args.connectorType, tc.args.config, tc.args.hasSSOMetadata, tc.args.ssoFederationOK)
			if got != tc.want {
				t.Fatalf("ClassifyAccessMode = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestIsValidAccessMode asserts the three known modes pass and
// arbitrary strings fail. The function is one switch statement —
// the test exists to lock the public surface and catch typos that
// drift the canonical set away from docs/architecture.md §13.
func TestIsValidAccessMode(t *testing.T) {
	valid := []string{models.AccessModeTunnel, models.AccessModeSSOOnly, models.AccessModeAPIOnly}
	for _, v := range valid {
		if !models.IsValidAccessMode(v) {
			t.Errorf("IsValidAccessMode(%q) = false; want true", v)
		}
	}
	invalid := []string{"", "TUNNEL", "saas", "open", "unknown"}
	for _, v := range invalid {
		if models.IsValidAccessMode(v) {
			t.Errorf("IsValidAccessMode(%q) = true; want false", v)
		}
	}
}
