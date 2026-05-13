/*
 * AccessSampleApp.kt — Jetpack Compose sample demonstrating the
 * `OkHttpAccessSDKClient`. The view depends on `AccessSDKClient`
 * (interface), not the concrete class, per the DI pattern in
 * `docs/SDK_CONTRACTS.md`.
 *
 * This file is plain Kotlin so it compiles under a standard JDK
 * toolchain; host apps wrap it in an Android Activity.
 */
package com.shieldnet360.access.example

import com.shieldnet360.access.AccessSDKClient
import com.shieldnet360.access.AccessSDKException
import com.shieldnet360.access.OkHttpAccessSDKClient
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient

/** Construct an SDK client for the sample. Hosts override the dispatcher. */
fun buildClient(): AccessSDKClient = OkHttpAccessSDKClient(
    baseUrl = Config.BASE_URL,
    client = OkHttpClient(),
    authTokenProvider = { Config.BEARER_TOKEN },
)

/** Trivial JVM entry point so the sample can run via `./gradlew run`. */
fun main() {
    val client = buildClient()
    runBlocking {
        try {
            val grants = client.listGrants()
            println("listGrants -> count=${grants.size}")
        } catch (e: AccessSDKException) {
            println("listGrants failed: $e")
        }
    }
}
