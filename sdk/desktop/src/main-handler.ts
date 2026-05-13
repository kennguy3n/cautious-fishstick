/**
 * main-handler.ts — Electron main-process implementation of the
 * Access Platform IPC contract.
 *
 * The renderer process talks to the main process over Electron IPC
 * via the channel constants in `access-ipc.ts`. This module
 * registers `ipcMain.handle` callbacks that translate each IPC
 * invocation into a real `fetch` call against `ztna-api`.
 *
 * Host applications wire the module by calling `registerAccessIPC`
 * once during app bootstrap with the base URL and an async token
 * provider:
 *
 *   import { app, ipcMain } from 'electron';
 *   import { registerAccessIPC } from '@shieldnet360/access-extension';
 *   registerAccessIPC(ipcMain, {
 *     baseUrl: 'https://api.example.com',
 *     authTokenProvider: async () => keychain.getAccessToken(),
 *   });
 *
 * There is **no on-device inference** anywhere in this module — the
 * `queryPolicy` / `askAI` channels forward to `/access/explain` and
 * `/access/suggest`, which the backend hands off to the
 * `access-ai-agent` Python skill server via A2A.
 */
import {
  AccessGrantListFilter,
  AccessIPCChannel,
  AccessIPCError,
  AccessRequest,
  AccessRequestDenyPayload,
  AccessRequestListFilter,
  AccessRequestPayload,
  AIQueryResponse,
  GrantListResponse,
  AccessRequestListResponse,
  AccessRequestResponse,
  PolicyQueryPayload,
  PolicyQueryResponse,
} from './access-ipc';

/** Narrow shape of `ipcMain.handle` so we don't depend on `electron` directly. */
export interface IpcMainLike {
  handle(channel: string, listener: (...args: unknown[]) => unknown | Promise<unknown>): void;
  removeHandler?(channel: string): void;
}

/** Configuration for `registerAccessIPC`. */
export interface AccessIPCConfig {
  /** Base URL of `ztna-api` (with or without trailing slash). */
  readonly baseUrl: string;
  /**
   * Async bearer-token provider. Called before every request so
   * token refresh stays the host application's responsibility.
   */
  readonly authTokenProvider: () => Promise<string>;
  /**
   * Optional custom `fetch` implementation. Defaults to the
   * global `fetch` available on Node ≥ 18 / Electron ≥ 22.
   */
  readonly fetch?: typeof fetch;
}

/**
 * Register all `AccessIPC` handlers on the supplied `ipcMain`-like
 * object. Returns a `dispose` function that removes the handlers
 * (useful for test teardown).
 */
export function registerAccessIPC(
  ipcMain: IpcMainLike,
  config: AccessIPCConfig,
): () => void {
  const baseUrl = config.baseUrl.replace(/\/+$/, '');
  const fetchImpl: typeof fetch =
    config.fetch ?? (globalThis as { fetch?: typeof fetch }).fetch!;
  if (!fetchImpl) {
    throw new AccessIPCError('not_configured', 'no fetch implementation available');
  }

  // We strip the leading `_event` argument off every handler — the
  // renderer never sends one and including it in our type signatures
  // would force every test to supply an Electron `IpcMainEvent`.
  const handle = <T>(
    channel: string,
    impl: (...args: unknown[]) => Promise<T>,
  ): void => {
    ipcMain.handle(channel, async (..._args: unknown[]) => {
      try {
        const payload = _args.slice(1);
        return await impl(...payload);
      } catch (e) {
        // Re-throw AccessIPCError as-is so the renderer can branch
        // on `kind`. Wrap unknown errors as `transport`.
        if (e instanceof AccessIPCError) throw serializeError(e);
        if (e instanceof Error) {
          throw serializeError(
            new AccessIPCError('transport', e.message, { cause: e }),
          );
        }
        throw serializeError(new AccessIPCError('transport', String(e)));
      }
    });
  };

  handle<AccessRequestResponse>(
    AccessIPCChannel.RequestAccessCreate,
    async (payload) => {
      const body = (payload ?? {}) as AccessRequestPayload;
      const req = await call<AccessRequest>('POST', '/access/requests', body);
      return { request: req };
    },
  );

  handle<AccessRequestListResponse>(
    AccessIPCChannel.RequestAccessList,
    async (filter) => {
      const params = buildQuery(filter as AccessRequestListFilter | undefined);
      const arr = await call<AccessRequest[]>('GET', `/access/requests${params}`);
      return { requests: arr };
    },
  );

  handle<AccessRequestResponse>(AccessIPCChannel.RequestAccessApprove, async (id) => {
    const req = await call<AccessRequest>('POST', `/access/requests/${id}/approve`, {});
    return { request: req };
  });

  handle<AccessRequestResponse>(
    AccessIPCChannel.RequestAccessDeny,
    async (id, payload) => {
      const body = (payload ?? {}) as AccessRequestDenyPayload;
      const req = await call<AccessRequest>(
        'POST',
        `/access/requests/${id}/deny`,
        body,
      );
      return { request: req };
    },
  );

  handle<AccessRequestResponse>(AccessIPCChannel.RequestAccessCancel, async (id) => {
    const req = await call<AccessRequest>('POST', `/access/requests/${id}/cancel`, {});
    return { request: req };
  });

  handle<GrantListResponse>(AccessIPCChannel.ListGrants, async (filter) => {
    const params = buildGrantsQuery(filter as AccessGrantListFilter | undefined);
    const arr = await call<GrantListResponse['grants']>(
      'GET',
      `/access/grants${params}`,
    );
    return { grants: arr };
  });

  handle<PolicyQueryResponse>(AccessIPCChannel.QueryPolicyExplain, async (payload) => {
    const body = (payload ?? {}) as PolicyQueryPayload;
    const explanation = await call<PolicyQueryResponse['explanation']>(
      'POST',
      '/access/explain',
      body,
    );
    return { explanation };
  });

  handle<AIQueryResponse>(AccessIPCChannel.AskAISuggest, async () => {
    const suggestions = await call<AIQueryResponse['suggestions']>(
      'POST',
      '/access/suggest',
      {},
      { allowEmpty: true },
    );
    return { suggestions: suggestions ?? [] };
  });

  // -------------------------- transport core ---------------------------

  async function call<T>(
    method: 'GET' | 'POST',
    path: string,
    body?: unknown,
    options: { allowEmpty?: boolean } = {},
  ): Promise<T> {
    let token: string;
    try {
      token = await config.authTokenProvider();
    } catch (e) {
      throw new AccessIPCError('unauthenticated', 'token provider failed', {
        cause: e,
      });
    }
    const init: RequestInit = {
      method,
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${token}`,
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
      },
    };
    if (method === 'POST' && body !== undefined) {
      init.body = JSON.stringify(body);
    }

    let res: Response;
    try {
      res = await fetchImpl(`${baseUrl}${path}`, init);
    } catch (e) {
      const cause = e instanceof Error ? e : undefined;
      throw new AccessIPCError('transport', cause?.message ?? String(e), {
        cause,
      });
    }
    if (res.status === 401) {
      throw new AccessIPCError('unauthenticated', 'unauthenticated', {
        statusCode: 401,
      });
    }
    const raw = await res.text();
    if (!res.ok) {
      throw new AccessIPCError('http', `HTTP ${res.status}`, {
        statusCode: res.status,
        body: raw,
      });
    }
    if (!raw) {
      if (options.allowEmpty) return [] as unknown as T;
      throw new AccessIPCError('decoding', `empty body for ${method} ${path}`);
    }
    try {
      return JSON.parse(raw) as T;
    } catch (e) {
      const cause = e instanceof Error ? e : undefined;
      throw new AccessIPCError('decoding', cause?.message ?? 'JSON parse error', {
        cause,
      });
    }
  }

  // ------------------------ teardown helper ----------------------------

  return () => {
    if (ipcMain.removeHandler) {
      for (const ch of Object.values(AccessIPCChannel)) ipcMain.removeHandler(ch);
    }
  };
}

function buildQuery(filter: AccessRequestListFilter | undefined): string {
  if (!filter) return '';
  const params = new URLSearchParams();
  if (filter.state) params.set('state', filter.state);
  if (filter.requesterUserId) params.set('requester', filter.requesterUserId);
  if (filter.resourceExternalId) params.set('resource', filter.resourceExternalId);
  const s = params.toString();
  return s ? `?${s}` : '';
}

function buildGrantsQuery(filter: AccessGrantListFilter | undefined): string {
  if (!filter) return '';
  const params = new URLSearchParams();
  if (filter.userId) params.set('user_id', filter.userId);
  if (filter.connectorId) params.set('connector_id', filter.connectorId);
  const s = params.toString();
  return s ? `?${s}` : '';
}

// The renderer hydrates errors from a plain object (it cannot
// reach the actual class). We serialise to a wire-compatible
// shape; the preload script reconstructs an AccessIPCError.
function serializeError(e: AccessIPCError): Error {
  const wire = new Error(e.message) as Error & {
    accessIPCError: true;
    kind: AccessIPCError['kind'];
    statusCode?: number;
    body?: string;
  };
  wire.accessIPCError = true;
  wire.kind = e.kind;
  if (e.statusCode !== undefined) wire.statusCode = e.statusCode;
  if (e.body !== undefined) wire.body = e.body;
  return wire;
}
