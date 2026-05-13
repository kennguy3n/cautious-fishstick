# ShieldNet 360 Access — SDK & Extension API Contracts

This document is the canonical reference for the Mobile SDK (iOS / Android) and Desktop Extension API contracts. All three target the same REST surface on `ztna-api`. See `PROPOSAL.md` §11 for the design rationale and `PHASES.md` Phase 2 / Phase 9 for the scope.

> **Cross-cutting invariant: no on-device inference.** The SDKs are thin REST clients. There is no `CoreML` / `MLX` import on iOS, no `org.tensorflow.lite` / `ai.onnxruntime` import on Android, and no `onnxruntime` / native inference binary in the desktop extension. There are no `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` files anywhere under `sdk/`. This rule is enforced by `scripts/check_no_model_files.sh`, which runs in CI alongside the swagger and SN360-language checks. See PROPOSAL.md §11.1 / §11.2 / §11.3 and PHASES.md Phase 9 cross-cutting criterion.

## Shared REST surface (PROPOSAL.md §11.4)

| Method | Path                              | Purpose                                                          | Handler |
|--------|-----------------------------------|------------------------------------------------------------------|---------|
| `POST` | `/access/requests`                | Create an access request                                         | [`internal/handlers/access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `GET`  | `/access/requests`                | List requests (filtered by state / requester / resource)         | [`internal/handlers/access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/approve`    | Approve (subject to workflow)                                    | [`internal/handlers/access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/deny`       | Deny                                                             | [`internal/handlers/access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `POST` | `/access/requests/:id/cancel`     | Requester cancels their own                                      | [`internal/handlers/access_request_handler.go`](../internal/handlers/access_request_handler.go) |
| `GET`  | `/access/grants`                  | List active grants for the calling user                          | [`internal/handlers/access_grant_handler.go`](../internal/handlers/access_grant_handler.go) |
| `POST` | `/access/explain`                 | Plain-English explanation of a policy or grant                   | [`internal/handlers/ai_handler.go`](../internal/handlers/ai_handler.go) |
| `POST` | `/access/suggest`                 | Recommended resources for the calling user                       | [`internal/handlers/ai_handler.go`](../internal/handlers/ai_handler.go) |

The `/access/explain` and `/access/suggest` handlers forward to the `policy_recommendation` skill on `access-ai-agent` over A2A. SDK consumers do **not** call the AI agent directly.

## Per-platform contract files

| Platform           | Contract entry-point                                                                                  | Models                                                                                       | Test                                                                                                |
|--------------------|--------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| iOS (Swift)        | [`sdk/ios/Sources/ShieldNetAccess/AccessSDKProtocol.swift`](../sdk/ios/Sources/ShieldNetAccess/AccessSDKProtocol.swift) | [`sdk/ios/Sources/ShieldNetAccess/Models.swift`](../sdk/ios/Sources/ShieldNetAccess/Models.swift) | [`sdk/ios/Tests/ShieldNetAccessTests/ContractTests.swift`](../sdk/ios/Tests/ShieldNetAccessTests/ContractTests.swift) |
| Android (Kotlin)   | [`sdk/android/src/main/kotlin/com/shieldnet360/access/AccessSDKClient.kt`](../sdk/android/src/main/kotlin/com/shieldnet360/access/AccessSDKClient.kt) | (same file)                                                                                  | [`sdk/android/src/test/kotlin/com/shieldnet360/access/ContractTest.kt`](../sdk/android/src/test/kotlin/com/shieldnet360/access/ContractTest.kt) |
| Desktop (TypeScript) | [`sdk/desktop/src/access-ipc.ts`](../sdk/desktop/src/access-ipc.ts)                                  | (same file)                                                                                  | [`sdk/desktop/src/__tests__/contract.test.ts`](../sdk/desktop/src/__tests__/contract.test.ts)        |

### Method ↔ endpoint mapping

| Logical method                                | REST endpoint                          | iOS (Swift)                               | Android (Kotlin)                          | Desktop (TypeScript)                        |
|-----------------------------------------------|-----------------------------------------|-------------------------------------------|-------------------------------------------|---------------------------------------------|
| Create request                                | `POST /access/requests`                | `AccessSDKClient.createRequest`           | `AccessSDKClient.createRequest`           | `AccessIPC.requestAccess.create`            |
| List requests                                 | `GET /access/requests`                 | `AccessSDKClient.listRequests`            | `AccessSDKClient.listRequests`            | `AccessIPC.requestAccess.list`              |
| Approve request                               | `POST /access/requests/:id/approve`    | `AccessSDKClient.approveRequest`          | `AccessSDKClient.approveRequest`          | `AccessIPC.requestAccess.approve`           |
| Deny request                                  | `POST /access/requests/:id/deny`       | `AccessSDKClient.denyRequest`             | `AccessSDKClient.denyRequest`             | `AccessIPC.requestAccess.deny`              |
| Cancel request                                | `POST /access/requests/:id/cancel`     | `AccessSDKClient.cancelRequest`           | `AccessSDKClient.cancelRequest`           | `AccessIPC.requestAccess.cancel`            |
| List grants                                   | `GET /access/grants`                   | `AccessSDKClient.listGrants`              | `AccessSDKClient.listGrants`              | `AccessIPC.listGrants`                      |
| Explain policy                                | `POST /access/explain`                 | `AccessSDKClient.explainPolicy`           | `AccessSDKClient.explainPolicy`           | `AccessIPC.queryPolicy`                     |
| Suggest resources                             | `POST /access/suggest`                 | `AccessSDKClient.suggestResources`        | `AccessSDKClient.suggestResources`        | `AccessIPC.askAI`                           |

## How "no on-device inference" is verified

Two complementary guards enforce the cross-cutting rule from PROPOSAL.md §11.1 / §11.2 / §11.3 and PHASES.md Phase 9:

1. **`scripts/check_no_model_files.sh`** — fails CI if any `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` file is committed anywhere under `sdk/`. Driven from `go test` via `scripts/check_no_model_files_test.go` (same pattern as `scripts/check_sn360_language_test.go`). The script is wired into `.github/workflows/ci.yml` alongside the swagger and SN360-language checks.
2. **Source-level audit** — the iOS protocol file declares no `import CoreML` / `import MLX`, the Android Kotlin file declares no `org.tensorflow.lite` / `ai.onnxruntime` import, and the desktop TypeScript file declares no `onnxruntime-node` / native inference dependency. The "AI" SDK methods (`explainPolicy`, `suggestResources`, `queryPolicy`, `askAI`) are documented in their doc comments as REST passthroughs to `/access/explain` and `/access/suggest`.

A future runtime probe will additionally assert that SDK builds only ever issue HTTPS REST calls (Phase 9 cross-cutting exit criterion); that probe lives in the SDK release pipeline rather than this repo.

## Integration guide outline

The contracts in this repo are interface definitions only — concrete `URLSession` / `OkHttp` / `fetch` implementations live in the host application. A canonical host integration looks like:

### iOS (Swift Package)

1. Add the package via Xcode → *File* → *Add Packages…* and point at the internal package registry URL.
2. Implement `AccessSDKClient` against `URLSession` (or your existing networking stack); the host owns auth-token handling and base URL configuration.
3. Inject the concrete client into your SwiftUI screens as a dependency — never let view code instantiate transport directly.

### Android (Kotlin library)

1. Add the AAR via the internal Maven registry and declare it in `build.gradle.kts`.
2. Implement `AccessSDKClient` with your `OkHttpClient` / `Retrofit` instance and a coroutine dispatcher of your choice.
3. Provide the implementation via Hilt / Koin / manual DI to ViewModels that need it; the host owns auth and base URL.

### Desktop (Electron npm module)

1. Install the package from the internal npm registry: `npm install @shieldnet360/access-extension`.
2. In the **main process**, implement `AccessIPC` against `node-fetch` / `undici` and register handlers with `ipcMain.handle` using the channel name constants from `AccessIPCChannel`.
3. In the **preload script**, expose a renderer-safe proxy via `contextBridge.exposeInMainWorld('access', { ... })` that calls `ipcRenderer.invoke` on the same channels.
4. The renderer imports the types from `@shieldnet360/access-extension` for compile-time safety — it never imports the implementation module.

## Error handling

Each platform exposes a typed error surface:

- **iOS:** `AccessSDKError` enum with `.transport`, `.http(statusCode:body:)`, `.decoding`, `.invalidInput`, `.unauthenticated`, `.notConfigured` cases.
- **Android:** `AccessSDKException` sealed class with `Transport`, `Http(statusCode, body)`, `Decoding`, `InvalidInput`, `Unauthenticated`, `NotConfigured` subclasses.
- **Desktop:** `AccessIPCError extends Error` with `kind: AccessIPCErrorKind` discriminant (`transport` | `http` | `decoding` | `invalid_input` | `unauthenticated` | `not_configured`), plus optional `statusCode` and `body`.

HTTP error responses follow the canonical envelope from `internal/handlers/errors.go` (`{ "error": { "code": "...", "message": "..." } }`) so all three platforms can decode them uniformly.

## Versioning

The contracts ship as `0.x` while Phase 9 is in flight. The major version locks once `PHASES.md` Phase 9 hits `✅ shipped` and the SDKs are published to the internal package / Maven / npm registries.
