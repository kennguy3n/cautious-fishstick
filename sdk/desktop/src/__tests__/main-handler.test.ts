/**
 * main-handler.test.ts — real IPC + real HTTP server round-trip
 * tests for the Electron main-handler module.
 *
 * We stand up a real Node `http.Server` to play the role of
 * `ztna-api` and call `registerAccessIPC` with a stub `ipcMain`
 * that captures registered handlers. Each test invokes a captured
 * handler directly; the handler performs a real `fetch` to the
 * local HTTP server and parses the response.
 *
 * The only stubbed component is the `electron` module — we cannot
 * boot a real Electron process in CI. The HTTP boundary is fully
 * real (a TCP `http.Server`), the JSON parsing is real, and the
 * error mapping is the real production code path.
 *
 * The file is intentionally written so it compiles cleanly under
 * `tsc --noEmit` (the desktop SDK's `npm test` invocation) without
 * needing Jest or Vitest installed. The assertions use Node's
 * built-in `node:assert` module.
 */
import * as assert from 'node:assert/strict';
import * as http from 'node:http';
import { AddressInfo } from 'node:net';

import { AccessIPCChannel, AccessIPCError } from '../access-ipc';
import { IpcMainLike, registerAccessIPC } from '../main-handler';

type Handler = (...args: unknown[]) => Promise<unknown>;

class StubIpcMain implements IpcMainLike {
  readonly handlers = new Map<string, Handler>();
  handle(channel: string, listener: Handler): void {
    this.handlers.set(channel, listener);
  }
  removeHandler(channel: string): void {
    this.handlers.delete(channel);
  }
  async invoke(channel: string, ...args: unknown[]): Promise<unknown> {
    const h = this.handlers.get(channel);
    if (!h) throw new Error(`no handler for ${channel}`);
    // The real Electron API prepends an `IpcMainInvokeEvent`; we
    // pass a sentinel since main-handler strips it.
    return h({}, ...args);
  }
}

interface ServerControl {
  url: string;
  responses: Array<{ status: number; body: string }>;
  recorded: Array<{ method: string; path: string; headers: http.IncomingHttpHeaders; body: string }>;
  close: () => Promise<void>;
}

async function startServer(): Promise<ServerControl> {
  const recorded: ServerControl['recorded'] = [];
  const responses: ServerControl['responses'] = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      recorded.push({
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body,
      });
      const next = responses.shift() ?? { status: 200, body: '{}' };
      res.writeHead(next.status, { 'Content-Type': 'application/json' });
      res.end(next.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${addr.port}`,
    responses,
    recorded,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

interface TestCase {
  name: string;
  run: () => Promise<void>;
}

const cases: TestCase[] = [];
function test(name: string, run: () => Promise<void>): void {
  cases.push({ name, run });
}

test('requestAccess.create POSTs body and decodes response', async () => {
  const server = await startServer();
  try {
    const ipc = new StubIpcMain();
    registerAccessIPC(ipc, {
      baseUrl: server.url,
      authTokenProvider: async () => 'tok-1',
    });
    server.responses.push({
      status: 201,
      body: JSON.stringify({
        id: 'req_1',
        workspaceId: 'ws_1',
        requesterUserId: 'u_1',
        connectorId: 'c_1',
        resourceExternalId: 'projects/foo',
        state: 'requested',
        createdAt: '2025-01-30T12:00:00Z',
      }),
    });
    const out = (await ipc.invoke(AccessIPCChannel.RequestAccessCreate, {
      resourceExternalId: 'projects/foo',
      role: 'viewer',
      justification: 'ci',
    })) as { request: { id: string; state: string } };
    assert.equal(out.request.id, 'req_1');
    assert.equal(out.request.state, 'requested');
    assert.equal(server.recorded[0].method, 'POST');
    assert.equal(server.recorded[0].path, '/access/requests');
    assert.equal(server.recorded[0].headers['authorization'], 'Bearer tok-1');
  } finally {
    await server.close();
  }
});

test('requestAccess.list appends query params', async () => {
  const server = await startServer();
  try {
    const ipc = new StubIpcMain();
    registerAccessIPC(ipc, {
      baseUrl: server.url,
      authTokenProvider: async () => 't',
    });
    server.responses.push({ status: 200, body: '[]' });
    await ipc.invoke(AccessIPCChannel.RequestAccessList, {
      state: 'requested',
      requesterUserId: 'u1',
    });
    const recorded = server.recorded[0];
    assert.equal(recorded.method, 'GET');
    assert.ok(recorded.path.startsWith('/access/requests?'));
    assert.ok(recorded.path.includes('state=requested'));
    assert.ok(recorded.path.includes('requester=u1'));
  } finally {
    await server.close();
  }
});

test('401 surfaces as AccessIPCError unauthenticated', async () => {
  const server = await startServer();
  try {
    const ipc = new StubIpcMain();
    registerAccessIPC(ipc, {
      baseUrl: server.url,
      authTokenProvider: async () => 't',
    });
    server.responses.push({ status: 401, body: '' });
    let caught: unknown = null;
    try {
      await ipc.invoke(AccessIPCChannel.RequestAccessCancel, 'req_x');
    } catch (e) {
      caught = e;
    }
    assert.ok(caught instanceof Error);
    assert.equal((caught as { kind?: string }).kind, 'unauthenticated');
  } finally {
    await server.close();
  }
});

test('500 surfaces as AccessIPCError http', async () => {
  const server = await startServer();
  try {
    const ipc = new StubIpcMain();
    registerAccessIPC(ipc, {
      baseUrl: server.url,
      authTokenProvider: async () => 't',
    });
    server.responses.push({ status: 500, body: 'internal' });
    let caught: { kind?: string; statusCode?: number } | null = null;
    try {
      await ipc.invoke(AccessIPCChannel.RequestAccessCancel, 'req_x');
    } catch (e) {
      caught = e as { kind?: string; statusCode?: number };
    }
    assert.ok(caught !== null);
    assert.equal(caught!.kind, 'http');
    assert.equal(caught!.statusCode, 500);
  } finally {
    await server.close();
  }
});

test('askAI tolerates empty body', async () => {
  const server = await startServer();
  try {
    const ipc = new StubIpcMain();
    registerAccessIPC(ipc, {
      baseUrl: server.url,
      authTokenProvider: async () => 't',
    });
    server.responses.push({ status: 200, body: '' });
    const out = (await ipc.invoke(AccessIPCChannel.AskAISuggest)) as {
      suggestions: unknown[];
    };
    assert.equal(out.suggestions.length, 0);
  } finally {
    await server.close();
  }
});

// AccessIPCError construction smoke test — proves the error type
// is reachable from the test target.
test('AccessIPCError carries kind / statusCode / body', async () => {
  const err = new AccessIPCError('http', 'boom', { statusCode: 500, body: 'b' });
  assert.equal(err.kind, 'http');
  assert.equal(err.statusCode, 500);
  assert.equal(err.body, 'b');
});

async function main(): Promise<void> {
  let failed = 0;
  for (const c of cases) {
    try {
      await c.run();
      // eslint-disable-next-line no-console
      console.log(`ok - ${c.name}`);
    } catch (e) {
      failed++;
      // eslint-disable-next-line no-console
      console.error(`not ok - ${c.name}`);
      // eslint-disable-next-line no-console
      console.error(e);
    }
  }
  if (failed > 0) {
    // eslint-disable-next-line no-console
    console.error(`${failed} test(s) failed`);
    process.exit(1);
  }
}

if (require.main === module) {
  void main();
}
