# ShieldNet Access iOS Sample App

Minimal SwiftUI sample wiring `URLSessionAccessSDKClient` against
`ztna-api`. The app demonstrates the DI pattern from
`docs/SDK_CONTRACTS.md` — the view models depend on
`AccessSDKClient` (protocol), not the concrete class.

## Running

1. Set the API base URL and bearer token in `Config.swift`.
2. Open `AccessExample.xcodeproj` (or add the `Example/` directory
   as a SwiftPM module under a host project).
3. Build & run on iOS 16+.

There is no on-device inference here — `Explain Policy` and
`Suggest Resources` hit the server's `/access/explain` and
`/access/suggest` endpoints, which in turn forward to the
`access-ai-agent` skill server via A2A.
