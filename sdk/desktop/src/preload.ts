/**
 * preload.ts — renderer-side proxy exposed via `contextBridge`.
 *
 * The host Electron application loads this script as the renderer
 * preload. It exposes an `access` object on `window` whose methods
 * forward to `ipcRenderer.invoke(channel, …)`. The renderer thus
 * never touches Electron internals directly — the contextBridge
 * pattern keeps the renderer sandboxed.
 *
 * Errors thrown across IPC arrive as plain `Error` objects with
 * the `accessIPCError` flag set; the proxy rehydrates them into
 * real `AccessIPCError` instances so callers can branch on `kind`.
 */
import {
  AccessGrantListFilter,
  AccessIPCChannel,
  AccessIPCError,
  AccessIPCErrorKind,
  AccessRequestDenyPayload,
  AccessRequestListFilter,
  AccessRequestPayload,
  AccessRequestListResponse,
  AccessRequestResponse,
  AIQueryResponse,
  GrantListResponse,
  PolicyQueryPayload,
  PolicyQueryResponse,
} from './access-ipc';

interface ContextBridgeLike {
  exposeInMainWorld(name: string, api: object): void;
}

interface IpcRendererLike {
  invoke(channel: string, ...args: unknown[]): Promise<unknown>;
}

/** Configuration object for `registerAccessRenderer`. */
export interface AccessRendererConfig {
  readonly contextBridge: ContextBridgeLike;
  readonly ipcRenderer: IpcRendererLike;
  /** Name of the property exposed on `window`. Defaults to `access`. */
  readonly worldName?: string;
}

/**
 * Expose the `access` API on `window` via `contextBridge`. Call this
 * once from the host application's preload script.
 */
export function registerAccessRenderer(config: AccessRendererConfig): void {
  const worldName = config.worldName ?? 'access';
  const { contextBridge, ipcRenderer } = config;

  async function invoke<T>(channel: string, ...args: unknown[]): Promise<T> {
    try {
      return (await ipcRenderer.invoke(channel, ...args)) as T;
    } catch (e) {
      throw rehydrateError(e);
    }
  }

  const requestAccess = {
    create: (payload: AccessRequestPayload): Promise<AccessRequestResponse> =>
      invoke(AccessIPCChannel.RequestAccessCreate, payload),
    list: (filter?: AccessRequestListFilter): Promise<AccessRequestListResponse> =>
      invoke(AccessIPCChannel.RequestAccessList, filter),
    approve: (id: string): Promise<AccessRequestResponse> =>
      invoke(AccessIPCChannel.RequestAccessApprove, id),
    deny: (id: string, payload: AccessRequestDenyPayload): Promise<AccessRequestResponse> =>
      invoke(AccessIPCChannel.RequestAccessDeny, id, payload),
    cancel: (id: string): Promise<AccessRequestResponse> =>
      invoke(AccessIPCChannel.RequestAccessCancel, id),
  };

  const api = {
    requestAccess,
    listGrants: (filter?: AccessGrantListFilter): Promise<GrantListResponse> =>
      invoke(AccessIPCChannel.ListGrants, filter),
    queryPolicy: (payload: PolicyQueryPayload): Promise<PolicyQueryResponse> =>
      invoke(AccessIPCChannel.QueryPolicyExplain, payload),
    askAI: (): Promise<AIQueryResponse> => invoke(AccessIPCChannel.AskAISuggest),
  };

  contextBridge.exposeInMainWorld(worldName, api);
}

/**
 * Rehydrate a serialised `AccessIPCError` (received via IPC) into a
 * real `AccessIPCError` instance so callers can branch on `kind`.
 */
function rehydrateError(e: unknown): unknown {
  if (!e || typeof e !== 'object') return e;
  const wire = e as {
    accessIPCError?: boolean;
    kind?: string;
    message?: string;
    statusCode?: number;
    body?: string;
  };
  if (!wire.accessIPCError || !wire.kind) return e;
  const kinds: AccessIPCErrorKind[] = [
    'transport',
    'http',
    'decoding',
    'invalid_input',
    'unauthenticated',
    'not_configured',
  ];
  const kind = (kinds.includes(wire.kind as AccessIPCErrorKind)
    ? wire.kind
    : 'transport') as AccessIPCErrorKind;
  const opts: { statusCode?: number; body?: string } = {};
  if (wire.statusCode !== undefined) opts.statusCode = wire.statusCode;
  if (wire.body !== undefined) opts.body = wire.body;
  return new AccessIPCError(kind, wire.message ?? '', opts);
}
