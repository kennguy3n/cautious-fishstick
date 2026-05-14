//
// Config.swift — sample-app configuration.
//
// In a real deployment the host application would read these
// values from a secure store (Keychain) or its own settings
// surface. They are intentionally trivial here so the sample
// stays focused on demonstrating the SDK call shape.
//

import Foundation

enum Config {
    /// Base URL of `ztna-api`. The sample defaults to
    /// `http://localhost:8080`; replace with the real deployment
    /// before building for distribution.
    static let baseURL = URL(string: "http://localhost:8080")!

    /// Static bearer token. Replace with a real token-issuance
    /// flow (OIDC / SSO / Keycloak) before shipping.
    static let bearerToken = "REPLACE_WITH_REAL_TOKEN"
}
