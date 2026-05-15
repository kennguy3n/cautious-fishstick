# Publishing the Desktop Access Extension

The desktop extension is an npm package that bundles:

- `dist/access-ipc.{js,d.ts}` — IPC contract (channel name constants + type definitions, identical on main and renderer).
- `dist/main-handler.{js,d.ts}` — `registerAccessIPC` for the Electron **main process**, including the `URL`-aware `fetch()` wrapper.
- `dist/preload.{js,d.ts}` — `registerAccessRenderer` for the Electron **preload script**, including the `contextBridge.exposeInMainWorld('access', ...)` wiring.

## Coordinates

| Field | Value |
|-------|-------|
| npm name | `@shieldnet360/access-extension` |
| Current version | `0.1.0` |
| Registry (default) | `https://npm.pkg.github.com/` (GitHub Packages, scope `@shieldnet360`) |
| Tag prefix | `sdk-desktop-v` |

Consumers install with:

```bash
# .npmrc in consumer repo
@shieldnet360:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```bash
npm install @shieldnet360/access-extension@0.1.0
```

## Release flow

1. Bump the version in `sdk/desktop/package.json` and add a matching entry to `sdk/desktop/CHANGELOG.md`.
2. Open a PR with the version bump, changelog, and any code changes; land it.
3. From `main`, tag the release commit:
   ```bash
   git tag -a sdk-desktop-v0.2.0 -m "Desktop Access Extension 0.2.0"
   git push origin sdk-desktop-v0.2.0
   ```
4. The `sdk-desktop-release` workflow (`.github/workflows/sdk-desktop-release.yml`) triggers on tags matching `sdk-desktop-v*` and:
   1. Reconstructs the version from the tag and asserts it matches `package.json`.
   2. Runs `npm install --ignore-scripts` and `npm run build` (`tsc`).
   3. Runs `npm run test` (`tsc --noEmit` typecheck).
   4. Runs `npm publish --provenance` against the registry from `publishConfig.registry`, authenticated with `NODE_AUTH_TOKEN`.
5. Verify the artifact landed:
   ```bash
   npm view @shieldnet360/access-extension@0.2.0
   ```

## Verifying resolution from a clean Node project

```bash
mkdir -p /tmp/sdk-desktop-smoke && cd /tmp/sdk-desktop-smoke
cat > .npmrc <<'NPMRC'
@shieldnet360:registry=https://npm.pkg.github.com/
NPMRC
# Authenticate (either NODE_AUTH_TOKEN or GITHUB_TOKEN with packages:read scope):
echo "//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}" >>.npmrc

npm init -y
npm install @shieldnet360/access-extension@0.1.0

cat > index.mjs <<'JS'
import { AccessIPCChannel } from '@shieldnet360/access-extension';
console.log('channels:', Object.values(AccessIPCChannel).length);
JS
node index.mjs
```

Expected output:

```
channels: 8
```

## Switching to a different npm registry

Override `publishConfig.registry` (or pass `--registry` to `npm publish`) and set `NODE_AUTH_TOKEN` for that registry. The package files do not embed any registry URL beyond `publishConfig`.

## Pre-release checklist

- [ ] `npm install --ignore-scripts && npm run build && npm run test` exit 0 inside `sdk/desktop/`.
- [ ] `bash scripts/check_no_model_files.sh` passes.
- [ ] `sdk/desktop/package.json` version is bumped.
- [ ] `sdk/desktop/CHANGELOG.md` has a new entry on top.
- [ ] `docs/sdk.md` "Versioning" table is updated.
