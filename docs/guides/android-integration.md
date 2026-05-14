# Android Integration Guide

This guide walks an Android (or any Kotlin/JVM) host application through integrating the **ShieldNet 360 Access SDK** end-to-end. It covers installation, configuration, every method on `AccessSDKClient`, error handling, and the contractual "no on-device inference" rule that the SDK enforces.

The SDK lives at [`sdk/android/`](../../sdk/android/) and is published as a Maven artifact (`com.shieldnet360.access:access-sdk:<version>`) — see [`sdk/android/PUBLISHING.md`](../../sdk/android/PUBLISHING.md) for release coordinates. The cross-platform REST contract is documented in [`docs/SDK_CONTRACTS.md`](../SDK_CONTRACTS.md).

Source of truth for every example in this guide: the sample app under [`sdk/android/example/`](../../sdk/android/example/).

---

## 1. Installation (Gradle)

The SDK is a **plain Kotlin/JVM library**. It does not depend on the Android Gradle Plugin, the Android SDK, or any Android-specific runtime APIs. You can consume it from a pure JVM host or from any Android module (the `OkHttp` + `coroutines` dependencies it brings in are Android-safe).

### 1.1 Register the repository

The default publish target is the GitHub Packages Maven registry. Register it once in `settings.gradle.kts`:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        google()
        maven {
            name = "ShieldNet360GitHubPackages"
            url = uri("https://maven.pkg.github.com/kennguy3n/cautious-fishstick")
            credentials {
                username = providers.gradleProperty("gpr.user").orNull
                    ?: System.getenv("GITHUB_ACTOR")
                password = providers.gradleProperty("gpr.token").orNull
                    ?: System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
```

If your organisation hosts an Artifactory / Nexus mirror, point at that URL instead — the artifact name and POM are identical.

### 1.2 Declare the dependency

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.shieldnet360.access:access-sdk:0.1.0")
}
```

The artifact pulls in `OkHttp 4.12`, `kotlinx.coroutines 1.7.3`, and `org.json 20240303`. Host apps that already use these will see them resolved at the highest version present.

---

## 2. Configuration

The SDK ships the `OkHttpAccessSDKClient` concrete implementation. The host application owns:

- the **base URL** of `ztna-api` (e.g. `https://ztna-api.internal.shieldnet360.example`).
- the **auth token** — a Bearer JWT issued by your IdP through the SN360 authentication boundary.
- the (optional) **`OkHttpClient`** instance, if you want to share interceptors / timeouts with the rest of your app.

```kotlin
import com.shieldnet360.access.AccessSDKClient
import com.shieldnet360.access.OkHttpAccessSDKClient
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

object AccessSDKModule {
    fun create(
        baseUrl: String,
        authTokenProvider: () -> String,
        okHttp: OkHttpClient = OkHttpClient.Builder()
            .callTimeout(30, TimeUnit.SECONDS)
            .build(),
    ): AccessSDKClient = OkHttpAccessSDKClient(
        baseUrl = baseUrl,
        authTokenProvider = authTokenProvider,
        client = okHttp,
    )
}

// At app startup (e.g. via Hilt / Koin):
val sdk: AccessSDKClient = AccessSDKModule.create(
    baseUrl = "https://ztna-api.internal.shieldnet360.example",
    authTokenProvider = { credentialStore.requireAccessToken() },
)
```

**Dependency injection.** Always inject `AccessSDKClient` (the interface), not `OkHttpAccessSDKClient`. This keeps your `ViewModel`s testable — drop a fake implementation into unit tests without touching the network layer.

**Token rotation.** Pass `authTokenProvider` as a function reference (not a captured string). The implementation calls it on every request, so when your IdP layer refreshes the token in the credential store, the SDK picks up the new value automatically — no need to rebuild the client.

---

## 3. Method-by-method usage

`AccessSDKClient` exposes **8 suspend methods** that map 1:1 to REST endpoints on `ztna-api`. Every method throws `AccessSDKException` on failure (see §4).

Call them from a coroutine scope you control — `viewModelScope`, `lifecycleScope`, or a host-provided dispatcher.

### 3.1 `createRequest` → `POST /access/requests`

Submit a new access request for a resource the caller does not currently have.

```kotlin
val request = sdk.createRequest(
    resource = "github:shieldnet360/access-platform",
    role = "maintainer",
    justification = "Need admin to merge tomorrow's incident-response PR.",
)
Log.d(TAG, "created ${request.id}, state=${request.state.value}")
```

`role` and `justification` are nullable; production workflows for high-risk resources will deny requests with a blank justification — pass it whenever you have one.

### 3.2 `listRequests` → `GET /access/requests`

```kotlin
val pending = sdk.listRequests(
    filter = AccessRequestListFilter(
        state = AccessRequestState.REQUESTED,
        // requesterUserId / resourceExternalId default to null (self / all)
    ),
)
```

`requesterUserId` is honoured only for admin callers; non-admin callers always see their own requests.

### 3.3 `approveRequest` → `POST /access/requests/:id/approve`

```kotlin
val approved = sdk.approveRequest(id = request.id)
check(approved.state == AccessRequestState.PROVISIONING ||
      approved.state == AccessRequestState.APPROVED)
```

The server enforces workflow rules — a low-risk request may transition directly to `PROVISIONING`, while a manager-approval workflow keeps it in `REVIEWING` until the manager acts.

### 3.4 `denyRequest` → `POST /access/requests/:id/deny`

The deny reason is required and is persisted to `access_request_state_history` for audit.

```kotlin
val denied = sdk.denyRequest(
    id = request.id,
    reason = "Resource is being deprecated; use the v2 cluster instead.",
)
```

### 3.5 `cancelRequest` → `POST /access/requests/:id/cancel`

The original requester cancels their own pending request; the server returns `403` for everyone else.

```kotlin
try {
    sdk.cancelRequest(id = request.id)
} catch (e: AccessSDKException.Http) {
    if (e.statusCode == 403) {
        // We are not the requester; surface a friendlier message.
        Log.w(TAG, "cannot cancel: ${e.body}")
    } else {
        throw e
    }
}
```

### 3.6 `listGrants` → `GET /access/grants`

```kotlin
val grants = sdk.listGrants(
    filter = AccessGrantListFilter(
        userId = null,        // self only — admin pass-through
        connectorId = null,   // all connectors
    ),
)
val github = grants.filter { it.connectorId.startsWith("github:") }
```

### 3.7 `explainPolicy` → `POST /access/explain`

```kotlin
val explanation = sdk.explainPolicy(policyId = policyId)
Log.i(TAG, explanation.summary)
explanation.rationale.forEach { Log.i(TAG, "- $it") }
```

**No on-device inference.** Forwards to the `policy_recommendation` skill on `access-ai-agent` via A2A.

### 3.8 `suggestResources` → `POST /access/suggest`

```kotlin
val suggestions = sdk.suggestResources()
suggestions.forEach { Log.i(TAG, "${it.displayName} → ${it.reason}") }
```

REST only — same A2A passthrough as `explainPolicy`.

---

## 4. Error handling

Every method throws subclasses of `AccessSDKException`:

```kotlin
sealed class AccessSDKException(message: String, cause: Throwable? = null) : Exception(message, cause) {
    class Transport(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)
    class Http(val statusCode: Int, val body: String?) : AccessSDKException(...)
    class Decoding(message: String, cause: Throwable? = null) : AccessSDKException(message, cause)
    class InvalidInput(message: String) : AccessSDKException(message)
    class Unauthenticated : AccessSDKException("unauthenticated")
    class NotConfigured : AccessSDKException("SDK not configured")
}
```

Recommended pattern in a `ViewModel`:

```kotlin
class AccessRequestListViewModel(
    private val sdk: AccessSDKClient,
    private val auth: AuthCoordinator,
) : ViewModel() {

    private val _state = MutableStateFlow<UiState>(UiState.Loading)
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun refresh() = viewModelScope.launch {
        _state.value = UiState.Loading
        _state.value = try {
            UiState.Loaded(sdk.listRequests(filter = AccessRequestListFilter()))
        } catch (e: AccessSDKException.Unauthenticated) {
            auth.refreshThenRetry { refresh() }
            UiState.Loading
        } catch (e: AccessSDKException.Http) when (e.statusCode in 500..599) -> {
            UiState.Error("ztna-api is unavailable (${e.statusCode}); retry in a moment.")
        } catch (e: AccessSDKException.Http) -> {
            UiState.Error("Request failed (${e.statusCode}): ${e.body ?: ""}")
        } catch (e: AccessSDKException.Transport) -> {
            UiState.Error("Network error: ${e.message}")
        } catch (e: AccessSDKException.Decoding) -> {
            UiState.Error("Unexpected server response: ${e.message}")
        } catch (e: AccessSDKException.InvalidInput) -> {
            UiState.Error("Bad input: ${e.message}")
        } catch (e: AccessSDKException.NotConfigured) -> {
            UiState.Error("The SDK has not been configured yet.")
        }
    }
}
```

**Body parsing.** The `body` on `Http` is the raw response. `ztna-api` always returns the canonical envelope:

```json
{ "error": { "code": "policy.denied", "message": "Manager approval required." } }
```

Decode it with whatever JSON library your app already uses:

```kotlin
val body = (e as? AccessSDKException.Http)?.body
val obj = body?.let { JSONObject(it).optJSONObject("error") }
val userMessage = obj?.optString("message") ?: "Request failed."
```

**5xx retry.** 5xx responses are retriable; 4xx (other than 401, which surfaces as `Unauthenticated`) are not — they indicate a contract or policy issue.

---

## 5. The "no on-device inference" contract

**Hard rule.** The Android SDK is a REST client. It must never bundle, load, or run a model on-device.

The SDK enforces this in three ways:

1. **No imports.** There is no `import org.tensorflow.lite` and no `import ai.onnxruntime` anywhere under `sdk/android/src/main/kotlin/`. Adding one will be caught in code review.
2. **No bundled models.** There are no `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` files under `sdk/android/`. This is enforced in CI by [`scripts/check_no_model_files.sh`](../../scripts/check_no_model_files.sh), which fails the build if any of these extensions appear under `sdk/`.
3. **AI is REST.** The two AI-facing methods (`explainPolicy`, `suggestResources`) are HTTP calls to `/access/explain` and `/access/suggest`. The backend (`ztna-api`) forwards them to the `access-ai-agent` Python skill server via A2A. The Android SDK does not see the model.

If your host app has its own ML stack (e.g. a separate TFLite model for on-device biometrics), keep that out of the access surface. The access SDK is a thin transport.

See PROPOSAL.md §11.2 and §11.5 for the design rationale.

---

## 6. Sample app

A Kotlin/JVM sample app demonstrating end-to-end REST round-trips lives at [`sdk/android/example/`](../../sdk/android/example/). It shows:

- DI pattern for `AccessSDKClient` (constructor-based, no framework).
- `OkHttp`-backed implementation construction with a configurable base URL.
- Real `sdk.createRequest(…)` / `sdk.listGrants(…)` calls.
- Error display for the typed `AccessSDKException` subclasses.

Start there — every code snippet in this guide is taken from or compatible with the sample app.

---

## 7. Versioning & support

- The SDK follows semver. Breaking changes will increment MAJOR.
- The current version is **0.1.0**. The matching `ztna-api` HTTP contract is documented in `docs/SDK_CONTRACTS.md` and `docs/swagger.{json,yaml}`.
- Each tagged release is announced in `sdk/android/CHANGELOG.md`.

For bugs, open an issue on [`kennguy3n/cautious-fishstick`](https://github.com/kennguy3n/cautious-fishstick/issues) with the `area:sdk-android` label.
