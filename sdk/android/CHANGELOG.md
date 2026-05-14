# ShieldNet 360 Access SDK (Android) — Changelog

The SDK is versioned independently of the backend. Tags follow `sdk-android-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

## 0.1.0 — initial publishable cut

- First public Maven artifact (`com.shieldnet360.access:access-sdk:0.1.0`).
- Ships the `AccessSDKClient` Kotlin interface with all 8 REST methods (`createRequest`, `listRequests`, `approveRequest`, `denyRequest`, `cancelRequest`, `listGrants`, `explainPolicy`, `suggestResources`).
- Ships the `OkHttpAccessSDKClient` concrete implementation backed by `OkHttpClient` + manual `org.json` parsing (library-free per the existing data-class design).
- Ships the canonical typed-exception sealed class `AccessSDKException` with `Transport`, `Http`, `Decoding`, `InvalidInput`, `Unauthenticated`, `NotConfigured` subclasses.
- Ships a Kotlin JVM sample app under `sdk/android/example/`.
