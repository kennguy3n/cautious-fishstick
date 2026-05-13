# ShieldNet Access Android Sample App

Minimal Jetpack Compose sample wiring `OkHttpAccessSDKClient`
against `ztna-api`. The view models depend on `AccessSDKClient`
(interface), not the concrete class — matching the DI pattern in
`docs/SDK_CONTRACTS.md`.

## Configuration

Edit `Config.kt`:

- `BASE_URL` — `ztna-api` endpoint (e.g. `https://api.example.com`).
- `BEARER_TOKEN` — replace with a real OIDC token in production.

## Running

```bash
./gradlew :example:installDebug
```

There is no on-device inference — `explainPolicy` and
`suggestResources` are REST calls. `scripts/check_no_model_files.sh`
enforces this.
