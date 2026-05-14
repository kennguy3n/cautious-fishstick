# ShieldNetAccess iOS SDK — Changelog

The SDK is versioned independently of the backend. Tags follow `sdk-ios-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

## 0.1.0 — initial publishable cut

- First public Swift Package release.
- Ships the `AccessSDKClient` protocol with all 8 REST methods (`createRequest`, `listRequests`, `approveRequest`, `denyRequest`, `cancelRequest`, `listGrants`, `explainPolicy`, `suggestResources`).
- Ships the `URLSessionAccessSDKClient` concrete implementation backed by Foundation `URLSession` (no third-party HTTP dependencies, no on-device inference).
- Ships the canonical typed-error enum `AccessSDKError` with `.transport`, `.http`, `.decoding`, `.invalidInput`, `.unauthenticated`, `.notConfigured` cases.
- Ships a SwiftUI sample app under `sdk/ios/Example/`.
