# iOS Integration Guide

This guide walks an iOS host application through integrating the **ShieldNet 360 Access SDK** end-to-end. It covers installation, configuration, every method on `AccessSDKClient`, error handling, and the contractual "no on-device inference" rule that the SDK enforces.

The SDK lives at [`sdk/ios/`](../../sdk/ios/) and is published as a Swift Package — see [`sdk/ios/PUBLISHING.md`](../../sdk/ios/PUBLISHING.md) for release coordinates. The cross-platform REST contract is documented in [`docs/SDK_CONTRACTS.md`](../SDK_CONTRACTS.md).

Source of truth for every example in this guide: the sample app under [`sdk/ios/Example/`](../../sdk/ios/Example/).

---

## 1. Installation (Swift Package Manager)

The SDK targets **iOS 15+** and **macOS 12+**.

### 1.1 Xcode

1. Open your host project, then *File → Add Packages…*
2. Enter the package URL: `https://github.com/kennguy3n/cautious-fishstick.git`
3. Pick a version rule. For production builds, pin to an exact tag (`Exact Version: 0.1.0`).
4. Add the `ShieldNetAccess` product to your app target.

### 1.2 Package.swift

```swift
// Package.swift
import PackageDescription

let package = Package(
    name: "MyAccessApp",
    platforms: [.iOS(.v15), .macOS(.v12)],
    dependencies: [
        .package(
            url: "https://github.com/kennguy3n/cautious-fishstick.git",
            from: "0.1.0"
        ),
    ],
    targets: [
        .executableTarget(
            name: "MyAccessApp",
            dependencies: [
                .product(name: "ShieldNetAccess", package: "cautious-fishstick"),
            ]
        ),
    ]
)
```

The repository is private. Xcode and SwiftPM honour the standard Git auth mechanisms — set up an SSH deploy key or a GitHub Personal Access Token in your Keychain. No Swift-specific token configuration is required.

---

## 2. Configuration

The SDK ships a Foundation-only `URLSessionAccessSDKClient` that handles all 8 REST methods. The host application owns:

- the **base URL** of `ztna-api` (e.g. `https://ztna-api.internal.shieldnet360.example`).
- the **auth token** — a Bearer JWT issued by your IdP through the SN360 authentication boundary.
- the (optional) **URLSession** instance, if you want to share a session with the rest of your app.

```swift
import Foundation
import ShieldNetAccess

@MainActor
final class AccessSDKEnvironment: ObservableObject {
    let client: AccessSDKClient

    init(
        baseURL: URL,
        authToken: String,
        session: URLSession = .shared
    ) {
        self.client = URLSessionAccessSDKClient(
            baseURL: baseURL,
            authToken: authToken,
            session: session
        )
    }
}

let env = AccessSDKEnvironment(
    baseURL: URL(string: "https://ztna-api.internal.shieldnet360.example")!,
    authToken: KeychainStore.shared.requireAccessToken()
)
```

**Dependency injection.** Never instantiate `URLSessionAccessSDKClient` inside view code. Always inject `AccessSDKClient` (the protocol) — this is what makes the SDK trivially testable, and it's what enables host apps to swap to a mock implementation in unit tests.

**Token rotation.** When your IdP rotates the user's access token, construct a new `URLSessionAccessSDKClient` with the new token and re-publish it through your environment / state container. The SDK does not store credentials; the host owns the lifecycle.

---

## 3. Method-by-method usage

`AccessSDKClient` exposes **8 async methods** that map 1:1 to REST endpoints on `ztna-api`. Every method `throws` an `AccessSDKError` (see §4).

### 3.1 `createRequest` → `POST /access/requests`

Submit a new access request for a resource the caller does not currently have access to.

```swift
let request = try await env.client.createRequest(
    resource: "github:shieldnet360/access-platform",
    role: "maintainer",
    justification: "Need admin to merge tomorrow's incident-response PR."
)
print("created \(request.id), state=\(request.state.rawValue)")
```

`role` and `justification` are optional, but workflows for high-risk resources will deny requests with a blank justification — pass it whenever you have one.

### 3.2 `listRequests` → `GET /access/requests`

List the caller's requests, optionally filtered.

```swift
let pending = try await env.client.listRequests(
    state: .requested,
    requester: nil,    // self only — admins can pass another user ID
    resource: nil      // all resources
)
for request in pending {
    print(request.id, request.resourceExternalID, request.role ?? "—")
}
```

Filters are AND-ed server-side. `requester` is honoured only for admin callers; non-admin callers always see their own requests.

### 3.3 `approveRequest` → `POST /access/requests/:id/approve`

Approve a pending request. The server enforces workflow rules — a low-risk request goes directly to `provisioning`, while a manager-approval workflow transitions the request to `reviewing` until the manager acts.

```swift
let approved = try await env.client.approveRequest(id: request.id)
assert(approved.state == .provisioning || approved.state == .reviewing)
```

### 3.4 `denyRequest` → `POST /access/requests/:id/deny`

Deny a request with an operator-supplied reason. The reason is required and is surfaced to the requester via `AccessRequestStateHistory`.

```swift
let denied = try await env.client.denyRequest(
    id: request.id,
    reason: "Resource is being deprecated; use the v2 cluster instead."
)
```

### 3.5 `cancelRequest` → `POST /access/requests/:id/cancel`

The original requester cancels their own pending request. The server returns `403` for everyone else.

```swift
do {
    _ = try await env.client.cancelRequest(id: request.id)
} catch AccessSDKError.http(403, let body) {
    // We are not the requester; ignore.
    print("cannot cancel: \(body ?? "")")
}
```

### 3.6 `listGrants` → `GET /access/grants`

List the caller's active grants — the actual upstream permissions that have been provisioned.

```swift
let myGrants = try await env.client.listGrants(
    userID: nil,         // self only — admin pass-through
    connectorID: nil     // all connectors
)
let github = myGrants.filter { $0.connectorID.hasPrefix("github:") }
print("\(github.count) active GitHub grants")
```

### 3.7 `explainPolicy` → `POST /access/explain`

Ask the platform to produce a plain-English explanation of a policy. The backend forwards the request to the `policy_recommendation` skill on `access-ai-agent` via A2A.

```swift
let explanation = try await env.client.explainPolicy(policyID: policyID)
print(explanation.summary)
for bullet in explanation.rationale { print("- \(bullet)") }
```

**No on-device inference.** This method is a thin REST passthrough. Your iOS app never loads a model.

### 3.8 `suggestResources` → `POST /access/suggest`

Server-side recommendation of resources the caller might want access to.

```swift
let suggestions = try await env.client.suggestResources()
for s in suggestions {
    print(s.displayName, "→", s.reason)
}
```

Again — REST only. The `policy_recommendation` skill server-side computes the suggestions.

---

## 4. Error handling

Every method throws `AccessSDKError`, a Swift `enum`:

```swift
public enum AccessSDKError: Error, Sendable, Equatable {
    case transport(String)
    case http(statusCode: Int, body: String?)
    case decoding(String)
    case invalidInput(String)
    case unauthenticated
    case notConfigured
}
```

Recommended pattern in SwiftUI:

```swift
@MainActor
final class RequestListViewModel: ObservableObject {
    @Published var requests: [AccessRequest] = []
    @Published var loadError: String?
    private let client: AccessSDKClient

    init(client: AccessSDKClient) { self.client = client }

    func load() async {
        do {
            self.requests = try await client.listRequests(
                state: nil, requester: nil, resource: nil
            )
            self.loadError = nil
        } catch AccessSDKError.unauthenticated {
            // The token has expired. Tell the IdP layer to refresh.
            await AuthCoordinator.shared.refreshThenRetry { await self.load() }
        } catch AccessSDKError.http(let code, let body) where (500...599).contains(code) {
            self.loadError = "ztna-api is unavailable (\(code)). Try again in a moment."
            // 5xx is retriable — call self.load() after a short delay.
        } catch AccessSDKError.http(let code, let body) {
            self.loadError = "Request failed (\(code)): \(body ?? "")"
        } catch AccessSDKError.transport(let detail) {
            self.loadError = "Network error: \(detail)"
        } catch AccessSDKError.decoding(let detail) {
            // This is a contract bug — file an issue.
            self.loadError = "Unexpected server response: \(detail)"
        } catch AccessSDKError.invalidInput(let detail) {
            self.loadError = "Bad input: \(detail)"
        } catch AccessSDKError.notConfigured {
            self.loadError = "The SDK has not been configured yet."
        } catch {
            self.loadError = "Unknown error: \(error.localizedDescription)"
        }
    }
}
```

**Body parsing.** The `body` payload on `.http` is the raw response. `ztna-api` always returns the canonical envelope:

```json
{ "error": { "code": "policy.denied", "message": "Manager approval required." } }
```

So you can decode it as:

```swift
struct ErrorEnvelope: Decodable {
    struct Inner: Decodable { let code: String; let message: String }
    let error: Inner
}
if case .http(_, let body?) = err,
   let env = try? JSONDecoder().decode(ErrorEnvelope.self, from: Data(body.utf8)) {
    print(env.error.message)
}
```

---

## 5. The "no on-device inference" contract

**Hard rule.** The iOS SDK is a REST client. It must never bundle, load, or run a model on-device.

The SDK enforces this in three ways:

1. **No imports.** There is no `import CoreML` and no `import MLX` anywhere under `sdk/ios/Sources/`. Adding one will be caught in code review.
2. **No bundled models.** There are no `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` files under `sdk/ios/`. This is enforced in CI by [`scripts/check_no_model_files.sh`](../../scripts/check_no_model_files.sh), which fails the build if any of these extensions appear under `sdk/`.
3. **AI is REST.** The two AI-facing methods (`explainPolicy`, `suggestResources`) are HTTP calls to `/access/explain` and `/access/suggest`. The backend (`ztna-api`) forwards them to the `access-ai-agent` Python skill server via A2A. The iOS SDK does not see the model.

If your host application has its own ML stack (e.g. a separate CoreML model for biometric prompts), keep that out of the access surface. The access SDK is a thin transport — it should not be the place where you experiment with on-device models.

See PROPOSAL.md §11.1 and §11.5 for the design rationale.

---

## 6. Sample app

A SwiftUI sample app demonstrating end-to-end REST round-trips lives at [`sdk/ios/Example/`](../../sdk/ios/Example/). It shows:

- DI pattern for `AccessSDKClient` via `@Environment` / `EnvironmentObject`.
- `URLSession`-backed implementation construction with a configurable base URL.
- Real `await client.createRequest(…)` / `await client.listGrants(…)` calls.
- Error display for the typed `AccessSDKError` cases.

Start there — every code snippet in this guide is taken from or compatible with the sample app.

---

## 7. Versioning & support

- The SDK follows semver. Breaking changes will increment MAJOR.
- The current version is **0.1.0**. The matching `ztna-api` HTTP contract is documented in `docs/SDK_CONTRACTS.md` and `docs/swagger.{json,yaml}`.
- Each tagged release is announced in `sdk/ios/CHANGELOG.md`.

For bugs, open an issue on [`kennguy3n/cautious-fishstick`](https://github.com/kennguy3n/cautious-fishstick/issues) with the `area:sdk-ios` label.
