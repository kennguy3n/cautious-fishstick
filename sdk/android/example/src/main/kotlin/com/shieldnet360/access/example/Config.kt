/*
 * Config.kt — sample-app configuration.
 *
 * In production these values come from a secure store; the sample
 * keeps them inline for clarity.
 */
package com.shieldnet360.access.example

internal object Config {
    /** Base URL of `ztna-api`. */
    const val BASE_URL = "http://10.0.2.2:8080"

    /** Static bearer token. Replace with a real OIDC token flow. */
    const val BEARER_TOKEN = "REPLACE_WITH_REAL_TOKEN"
}
