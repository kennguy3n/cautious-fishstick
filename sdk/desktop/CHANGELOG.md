# @shieldnet360/access-extension — Changelog

The desktop extension is versioned independently of the backend. Tags follow `sdk-desktop-vMAJOR.MINOR.PATCH`. See `PUBLISHING.md` for the release flow.

## 0.1.0 — initial publishable cut

- First public npm publish (`@shieldnet360/access-extension@0.1.0`).
- Ships the `AccessIPC` TypeScript interface, the 8-channel `AccessIPCChannel` constant map, and the request / response data interfaces (`AccessRequest`, `AccessGrant`, `PolicyExplanation`, `Suggestion`).
- Ships `registerAccessIPC` for the Electron main process: `ipcMain.handle` registrations + `fetch()`-backed REST calls + `AccessIPCError` rehydration.
- Ships `registerAccessRenderer` for the Electron preload script: `contextBridge.exposeInMainWorld('access', { ... })` with error-rehydration on the renderer side of the bridge.
- Verified resolvable from a clean Node 18 project via `npm install @shieldnet360/access-extension`.
