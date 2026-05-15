# SDK and Extension Contracts

The platform ships first-party client libraries for iOS, Android, and desktop (Electron). All three target the same REST surface on `ztna-api` and follow the same hard rule: **no on-device inference**. AI calls are REST passthroughs to the server-side `access-ai-agent`.

For end-to-end host-app integration walkthroughs see [`guides/ios.md`](guides/ios.md), [`guides/android.md`](guides/android.md), and [`guides/desktop.md`](guides/desktop.md). For the cross-cutting architecture see [`architecture.md`](architecture.md#10-client-sdk-architecture).

## No on-device inference

The SDKs are thin REST clients. There is no `CoreML` / `MLX` import on iOS, no `org.tensorflow.lite` / `ai.onnxruntime` import on Android, and no `onnxruntime` or native inference binary in the desktop extension. There are no `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` files anywhere under `sdk/`. Two complementary guards keep the rule in place:

1. **`scripts/check_no_model_files.sh`** fails CI if a model file is committed under `sdk/`. The script is driven from `go test` (`scripts/check_no_model_files_test.go`) and wired into [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) alongside the swagger and SN360-language checks.
2. **Source-level audit.** The iOS protocol declares no `import CoreML` / `import MLX`; the Android Kotlin file declares no `org.tensorflow.lite` / `ai.onnxruntime` import; the desktop TypeScript file declares no `onnxruntime-node` dependency. The "AI" SDK methods (`explainPolicy`, `suggestResources`, `queryPolicy`, `askAI`) are documented in their doc comments as REST passthroughs to `/access/explain` and `/access/suggest`.

## Shared REST surface

All three SDKs call the same eight endpoints on `ztna-api`.

| Method | Path                              | Purpose                                                          | Handler |
|--------|-----------------------------------|------------------------------------------------------------------|---------|
| `POST` | `/access/requests`                | Create an access request                                         | [`access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `GET`  | `/access/requests`                | List requests (filtered by state / requester / resource)         | [`access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/approve`    | Approve (subject to workflow)                                    | [`access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/deny`       | Deny                                                             | [`access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/cancel`     | Requester cancels their own                                      | [`access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `GET`  | `/access/grants`                  | List active grants for the calling user                          | [`access_grant_handler.go`](../internal/handlers/access_grant_handler.go)     |
| `POST` | `/access/explain`                 | Plain-English explanation of a policy or grant                   | [`ai_handler.go`](../internal/handlers/ai_handler.go)                         |
| `POST` | `/access/suggest`                 | Recommended resources for the calling user                       | [`ai_handler.go`](../internal/handlers/ai_handler.go)                         |

The `/access/explain` and `/access/suggest` handlers forward to the `policy_recommendation` skill on `access-ai-agent` over A2A. SDK consumers never call the AI agent directly.

## Per-platform contract files

| Platform              | Contract entry-point                                                                                              | Tests                                                                                                |
|-----------------------|-------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| iOS (Swift)           | [`AccessSDKProtocol.swift`](../sdk/ios/Sources/ShieldNetAccess/AccessSDKProtocol.swift) + [`Models.swift`](../sdk/ios/Sources/ShieldNetAccess/Models.swift) | [`ContractTests.swift`](../sdk/ios/Tests/ShieldNetAccessTests/ContractTests.swift)                  |
| Android (Kotlin)      | [`AccessSDKClient.kt`](../sdk/android/src/main/kotlin/com/shieldnet360/access/AccessSDKClient.kt)                 | [`ContractTest.kt`](../sdk/android/src/test/kotlin/com/shieldnet360/access/ContractTest.kt)         |
| Desktop (TypeScript)  | [`access-ipc.ts`](../sdk/desktop/src/access-ipc.ts)                                                               | [`contract.test.ts`](../sdk/desktop/src/__tests__/contract.test.ts)                                  |

## Method ↔ endpoint mapping

| Logical method     | REST endpoint                          | iOS (Swift)                          | Android (Kotlin)                     | Desktop (TypeScript)                  |
|--------------------|----------------------------------------|--------------------------------------|--------------------------------------|---------------------------------------|
| Create request     | `POST /access/requests`                | `AccessSDKClient.createRequest`      | `AccessSDKClient.createRequest`      | `AccessIPC.requestAccess.create`      |
| List requests      | `GET /access/requests`                 | `AccessSDKClient.listRequests`       | `AccessSDKClient.listRequests`       | `AccessIPC.requestAccess.list`        |
| Approve request    | `POST /access/requests/:id/approve`    | `AccessSDKClient.approveRequest`     | `AccessSDKClient.approveRequest`     | `AccessIPC.requestAccess.approve`     |
| Deny request       | `POST /access/requests/:id/deny`       | `AccessSDKClient.denyRequest`        | `AccessSDKClient.denyRequest`        | `AccessIPC.requestAccess.deny`        |
| Cancel request     | `POST /access/requests/:id/cancel`     | `AccessSDKClient.cancelRequest`      | `AccessSDKClient.cancelRequest`      | `AccessIPC.requestAccess.cancel`      |
| List grants        | `GET /access/grants`                   | `AccessSDKClient.listGrants`         | `AccessSDKClient.listGrants`         | `AccessIPC.listGrants`                |
| Explain policy     | `POST /access/explain`                 | `AccessSDKClient.explainPolicy`      | `AccessSDKClient.explainPolicy`      | `AccessIPC.queryPolicy`               |
| Suggest resources  | `POST /access/suggest`                 | `AccessSDKClient.suggestResources`   | `AccessSDKClient.suggestResources`   | `AccessIPC.askAI`                     |

## Host-app integration shape

Each SDK ships **both** the protocol / interface definition *and* a concrete REST implementation. Host applications can use the ready-made implementation or substitute their own. See the per-platform guides for the full walkthrough.

### iOS (Swift Package)

1. Add the package via Xcode → *File* → *Add Packages…* using the SwiftPM URL.
2. Use the shipped `URLSessionAccessSDKClient` (Foundation-only — no third-party HTTP libraries) or substitute your own conformer of `AccessSDKClient`. The host owns auth-token handling and base URL configuration.
3. Inject the client into SwiftUI screens as a dependency — view code never instantiates transport directly.

### Android (Kotlin library)

1. Add the AAR via the Maven registry and declare it in `build.gradle.kts`.
2. Use the shipped `OkHttpAccessSDKClient` (library-free JSON via `org.json`) or substitute your own implementation of `AccessSDKClient` with a coroutine dispatcher of your choice.
3. Provide via Hilt / Koin / manual DI to ViewModels that need it; the host owns auth and base URL.

### Desktop (Electron npm module)

1. Install the package: `npm install @shieldnet360/access-extension`.
2. In the **main process**, call `registerAccessIPC` — it registers `ipcMain.handle` for every `AccessIPCChannel` against a real `fetch`-backed client. Pass an auth-token resolver and base URL.
3. In the **preload script**, call `registerAccessRenderer` to expose a renderer-safe proxy via `contextBridge.exposeInMainWorld('access', …)` with error rehydration across the IPC boundary.
4. The renderer imports the types from `@shieldnet360/access-extension` for compile-time safety — it never imports the implementation module.

## Error handling

Each platform exposes a typed error surface, decoded uniformly from the canonical HTTP envelope at [`internal/handlers/errors.go`](../internal/handlers/errors.go) (`{ "error": { "code": "...", "message": "..." } }`):

- **iOS** — `AccessSDKError` enum with `.transport`, `.http(statusCode:body:)`, `.decoding`, `.invalidInput`, `.unauthenticated`, `.notConfigured`.
- **Android** — `AccessSDKException` sealed class with `Transport`, `Http(statusCode, body)`, `Decoding`, `InvalidInput`, `Unauthenticated`, `NotConfigured`.
- **Desktop** — `AccessIPCError extends Error` with `kind: AccessIPCErrorKind` discriminant (`transport` | `http` | `decoding` | `invalid_input` | `unauthenticated` | `not_configured`), plus optional `statusCode` and `body`.

## Published artifacts

| Platform | Registry                                                                        | Coordinates                                              | Tag prefix       | Publishing                                                  |
|----------|---------------------------------------------------------------------------------|----------------------------------------------------------|------------------|-------------------------------------------------------------|
| iOS      | SwiftPM via Git (`kennguy3n/cautious-fishstick`)                                | `from: "0.1.0"`                                          | `sdk-ios-v`      | [`sdk/ios/PUBLISHING.md`](../sdk/ios/PUBLISHING.md)         |
| Android  | GitHub Packages Maven (`maven.pkg.github.com/kennguy3n/cautious-fishstick`)     | `com.shieldnet360.access:access-sdk:0.1.0`               | `sdk-android-v`  | [`sdk/android/PUBLISHING.md`](../sdk/android/PUBLISHING.md) |
| Desktop  | GitHub Packages npm (`npm.pkg.github.com/`, scope `@shieldnet360`)              | `@shieldnet360/access-extension@0.1.0`                   | `sdk-desktop-v`  | [`sdk/desktop/PUBLISHING.md`](../sdk/desktop/PUBLISHING.md) |

Release tags trigger the per-platform release workflow in `.github/workflows/sdk-{ios,android,desktop}-release.yml`. Each workflow validates the manifest, runs the contract tests, asserts a matching `CHANGELOG.md` entry, and publishes the artifact.

## Where to read next

- [`guides/ios.md`](guides/ios.md) — iOS host-app integration walkthrough.
- [`guides/android.md`](guides/android.md) — Android host-app integration walkthrough.
- [`guides/desktop.md`](guides/desktop.md) — Electron host-app integration walkthrough.
- [`architecture.md`](architecture.md#10-client-sdk-architecture) — where the SDKs sit in the wider system.
