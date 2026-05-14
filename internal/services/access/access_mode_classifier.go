package access

import (
	"strings"

	"github.com/kennguy3n/cautious-fishstick/internal/models"
)

// ClassifyAccessMode picks one of the three docs/PROPOSAL.md §13
// access modes for a freshly-configured connector. The decision is
// deterministic given (connector, config, sso metadata, sso federation
// success) and is applied at Connect time before the access_connectors
// row is inserted.
//
// Resolution order (first match wins):
//
//  1. If config indicates the resource is private / self-hosted
//     (config["is_private"] == true, config["self_hosted"] == true,
//     config["access_mode"] == "tunnel", or connectorType == "tunnel"),
//     return AccessModeTunnel.
//  2. If the connector advertised SSO metadata AND the Keycloak
//     federation pass succeeded (ssoFederationOK == true), return
//     AccessModeSSOOnly. The connector is reachable through the
//     IdP broker; the access-platform does NOT need a per-grant
//     API push.
//  3. Otherwise return AccessModeAPIOnly. This is the safe default
//     — the connector is reached directly via its REST API.
//
// The classifier accepts an explicit override via config["access_mode"]
// for operators who know better (e.g. a tunneled Salesforce instance
// behind a private VPN). The override must be one of the three
// IsValidAccessMode values; invalid overrides are ignored.
func ClassifyAccessMode(
	connectorType string,
	config map[string]interface{},
	hasSSOMetadata bool,
	ssoFederationOK bool,
) string {
	// Explicit operator override.
	if raw, ok := config["access_mode"]; ok {
		if v, ok := raw.(string); ok {
			v = strings.TrimSpace(v)
			if models.IsValidAccessMode(v) {
				return v
			}
		}
	}

	// Private-resource hints in config or connector_type.
	if strings.EqualFold(strings.TrimSpace(connectorType), "tunnel") {
		return models.AccessModeTunnel
	}
	if boolFromConfig(config, "is_private") || boolFromConfig(config, "self_hosted") {
		return models.AccessModeTunnel
	}

	// SSO-only when the connector advertised SAML / OIDC metadata
	// AND the Keycloak federation pass actually configured the IdP.
	if hasSSOMetadata && ssoFederationOK {
		return models.AccessModeSSOOnly
	}

	// Default: direct API access.
	return models.AccessModeAPIOnly
}

// boolFromConfig reads a boolean-flavoured value from a connector
// config map. Accepts true booleans, the strings "true" / "1" / "yes",
// and any non-zero numeric. Anything else (including missing keys)
// returns false.
func boolFromConfig(config map[string]interface{}, key string) bool {
	raw, ok := config[key]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "y", "on":
			return true
		}
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	}
	return false
}
