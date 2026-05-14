# Desktop Extension Integration Guide

This guide walks an Electron host application through integrating the **ShieldNet 360 Access Extension** end-to-end. It covers installation, registering IPC handlers in the **main process**, exposing the surface to the **renderer** via `contextBridge`, the full IPC channel reference, error handling, and the contractual "no on-device inference" rule.

The extension lives at [`sdk/desktop/`](../../sdk/desktop/) and is published as `@shieldnet360/access-extension` on the internal npm registry — see [`sdk/desktop/PUBLISHING.md`](../../sdk/desktop/PUBLISHING.md) for release coordinates. The cross-platform REST contract is documented in [`docs/SDK_CONTRACTS.md`](../SDK_CONTRACTS.md).

---

## 1. Installation (npm)

The extension targets **Node 18+** and **Electron 28+**. It has no runtime dependencies — it relies on Node 18+'s built-in `fetch` and the Electron `ipcMain` / `ipcRenderer` / `contextBridge` APIs.

### 1.1 Configure the internal npm registry

In your host repo's `.npmrc`:

```ini
@shieldnet360:registry=https://npm.pkg.github.com/
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

`GITHUB_TOKEN` needs `read:packages` scope.

### 1.2 Install

```bash
npm install @shieldnet360/access-extension@0.1.0
```

### 1.3 Three importable entry-points

| Entry-point | Imported from | Where it runs |
|-------------|---------------|---------------|
| Types & channel constants | `@shieldnet360/access-extension` | main + renderer |
| Main-process handler registration | `@shieldnet360/access-extension/main-handler` | main only |
| Renderer-side preload bridge | `@shieldnet360/access-extension/preload` | preload script |

The renderer process **never** imports `main-handler` (it would pull in `fetch` against `ztna-api` directly, bypassing the security boundary). The TypeScript exports map enforces this — only the types subpath is safe for renderer code.

---

## 2. Main-process wiring

In your Electron main-process bootstrap, call `registerAccessIPC` once after `app.whenReady()`:

```ts
// src/main.ts
import { app, BrowserWindow } from 'electron';
import { registerAccessIPC } from '@shieldnet360/access-extension/main-handler';

app.whenReady().then(() => {
    registerAccessIPC({
        baseUrl: process.env.ZTNA_API_BASE_URL
            ?? 'https://ztna-api.internal.shieldnet360.example',
        getAuthToken: async () => credentialStore.requireAccessToken(),
        // Optional — override fetch (e.g. to swap in undici for a corporate
        // proxy). Defaults to the Node 18+ built-in.
        fetch: globalThis.fetch,
    });

    // Create your window after IPC is registered.
    const win = new BrowserWindow({
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            sandbox: true,
            contextIsolation: true,
        },
    });
    win.loadURL(...);
});
```

`registerAccessIPC` registers exactly 8 `ipcMain.handle` channels (one per REST method) and is idempotent — calling it twice replaces the previous handlers (useful in development with hot-reload).

**Token rotation.** Pass `getAuthToken` as an `async () => string` callback (not a captured string). The handler calls it on every request, so when your IdP layer refreshes the token in the credential store, the IPC bridge picks up the new value automatically.

---

## 3. Preload (renderer) wiring

The renderer process cannot see Node APIs (Electron sandboxing). The preload script is the bridge: it imports `registerAccessRenderer`, which uses `contextBridge.exposeInMainWorld('access', { ... })` to publish a safe proxy on `window.access`.

```ts
// src/preload.ts
import { registerAccessRenderer } from '@shieldnet360/access-extension/preload';

registerAccessRenderer();
```

That's it — one function call. The proxy object on `window.access` mirrors the `AccessIPC` TypeScript interface 1:1, so renderer code gets full type-safety:

```ts
// src/renderer.ts
import type { AccessIPC } from '@shieldnet360/access-extension';

declare global {
    interface Window {
        readonly access: AccessIPC;
    }
}

const grants = await window.access.listGrants();
console.log(grants.grants.length, 'active grants');
```

If your renderer is built with a bundler that strips `type`-only imports (Vite, esbuild, Webpack with `importsNotUsedAsValues: error`), the `import type` keeps the import out of the renderer bundle — only the type information survives.

---

## 4. IPC channel reference

The extension registers **8 IPC channels**. Channel names are exposed as TypeScript constants on `AccessIPCChannel` so renderer-side code never hardcodes them.

| Logical method | Channel name | REST endpoint | Payload | Response |
|----------------|--------------|---------------|---------|----------|
| `requestAccess.create` | `access:requestAccess.create` | `POST /access/requests` | `AccessRequestPayload` | `AccessRequestResponse` |
| `requestAccess.list` | `access:requestAccess.list` | `GET /access/requests` | `AccessRequestListFilter?` | `AccessRequestListResponse` |
| `requestAccess.approve` | `access:requestAccess.approve` | `POST /access/requests/:id/approve` | `string` (id) | `AccessRequestResponse` |
| `requestAccess.deny` | `access:requestAccess.deny` | `POST /access/requests/:id/deny` | `{ id, payload: { reason } }` | `AccessRequestResponse` |
| `requestAccess.cancel` | `access:requestAccess.cancel` | `POST /access/requests/:id/cancel` | `string` (id) | `AccessRequestResponse` |
| `listGrants` | `access:listGrants` | `GET /access/grants` | `AccessGrantListFilter?` | `GrantListResponse` |
| `queryPolicy.explain` | `access:queryPolicy.explain` | `POST /access/explain` | `PolicyQueryPayload` | `PolicyQueryResponse` |
| `askAI.suggestResources` | `access:askAI.suggestResources` | `POST /access/suggest` | (none) | `AIQueryResponse` |

Renderer usage examples:

```ts
// Create
const { request } = await window.access.requestAccess.create({
    resourceExternalId: 'github:shieldnet360/access-platform',
    role: 'maintainer',
    justification: 'Need admin to merge tomorrow\'s incident-response PR.',
});

// List with filter
const { requests } = await window.access.requestAccess.list({
    state: 'requested',
});

// Approve / Deny / Cancel
await window.access.requestAccess.approve(request.id);
await window.access.requestAccess.deny(request.id, { reason: 'use v2 cluster' });
await window.access.requestAccess.cancel(request.id);

// Grants
const { grants } = await window.access.listGrants({ connectorId: 'github:org/x' });

// AI (REST passthrough)
const { explanation } = await window.access.queryPolicy({ policyId: '...' });
const { suggestions } = await window.access.askAI();
```

---

## 5. Error handling

The bridge surfaces errors as **rejected promises** that carry an `AccessIPCError`:

```ts
export class AccessIPCError extends Error {
    readonly kind:
        | 'transport'
        | 'http'
        | 'decoding'
        | 'invalid_input'
        | 'unauthenticated'
        | 'not_configured';
    readonly statusCode?: number;
    readonly body?: string;
}
```

`AccessIPCError` is rehydrated on **both sides** of the bridge — the main process throws it, it travels through Electron's serialization layer as a structured object, and `registerAccessRenderer` reconstructs the prototype so `instanceof AccessIPCError` works in renderer code:

```ts
import { AccessIPCError } from '@shieldnet360/access-extension';

try {
    const { grants } = await window.access.listGrants();
    // ... render grants
} catch (e) {
    if (e instanceof AccessIPCError) {
        switch (e.kind) {
            case 'unauthenticated':
                await auth.refreshThenRetry();
                break;
            case 'http':
                if (e.statusCode! >= 500) {
                    toast.error(`ztna-api is unavailable (${e.statusCode}); retry in a moment.`);
                } else {
                    toast.error(`Request failed (${e.statusCode}): ${e.body ?? ''}`);
                }
                break;
            case 'transport':
                toast.error(`Network error: ${e.message}`);
                break;
            case 'decoding':
                // This is a contract bug — file an issue.
                console.error('decode error', e);
                break;
            case 'invalid_input':
                toast.warning(e.message);
                break;
            case 'not_configured':
                toast.error('The Access extension has not been configured yet.');
                break;
        }
    } else {
        throw e;  // unknown — let the global handler take it.
    }
}
```

**Body envelope.** `body` is the raw response from `ztna-api`. The server always returns the canonical envelope:

```json
{ "error": { "code": "policy.denied", "message": "Manager approval required." } }
```

So you can pull a user-facing message with `JSON.parse(e.body!).error.message`.

---

## 6. The "no on-device inference" contract

**Hard rule.** The desktop extension is a REST client. It must never bundle, load, or run a model on-device.

The extension enforces this in three ways:

1. **No imports.** There is no `import 'onnxruntime-node'`, no `import 'onnxruntime-web'`, and no native inference binary anywhere under `sdk/desktop/src/`. Adding one will be caught in code review.
2. **No bundled models.** There are no `.mlmodel`, `.tflite`, `.onnx`, or `.gguf` files under `sdk/desktop/`. This is enforced in CI by [`scripts/check_no_model_files.sh`](../../scripts/check_no_model_files.sh), which fails the build if any of these extensions appear under `sdk/`.
3. **AI is REST.** The two AI-facing channels (`access:queryPolicy.explain` and `access:askAI.suggestResources`) are HTTP calls to `/access/explain` and `/access/suggest`. The backend (`ztna-api`) forwards them to the `access-ai-agent` Python skill server via A2A. The desktop extension does not see the model.

See PROPOSAL.md §11.3 and §11.5 for the design rationale.

---

## 7. Security notes

- **Context isolation must be enabled.** The preload bridge calls `contextBridge.exposeInMainWorld`, which only works when the renderer is loaded with `contextIsolation: true`. Pair it with `sandbox: true` and `nodeIntegration: false` (the Electron defaults since v12) to keep the renderer fully sandboxed.
- **The auth token never crosses to the renderer.** `getAuthToken` runs only in the main process; the renderer can call `window.access.*` but cannot read the bearer token directly. This is the same threat model as a browser tab calling a backend through HTTPOnly cookies.
- **CSP recommendation.** Add `default-src 'self'` and `connect-src 'self' https://ztna-api.internal.shieldnet360.example` to your renderer's CSP. The bridge does the network call from the main process, so the renderer's CSP does not need to allow `ztna-api` directly — but pinning it tightens the threat model.

---

## 8. Versioning & support

- The extension follows semver. Breaking changes will increment MAJOR.
- The current version is **0.1.0**. The matching `ztna-api` HTTP contract is documented in `docs/SDK_CONTRACTS.md` and `docs/swagger.{json,yaml}`.
- Each tagged release is announced in `sdk/desktop/CHANGELOG.md`.

For bugs, open an issue on [`kennguy3n/cautious-fishstick`](https://github.com/kennguy3n/cautious-fishstick/issues) with the `area:sdk-desktop` label.
