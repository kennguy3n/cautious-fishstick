/**
 * contract.test.ts — compile-time conformance check.
 *
 * The desktop extension ships type definitions only; concrete
 * implementations live in the host Electron application. This file is a
 * pure type-check: it constructs a mock object that satisfies the
 * `AccessIPC` interface. If a method signature changes in a breaking way,
 * `tsc --noEmit` fails and the test target fails to build. There are
 * intentionally **no runtime IPC round-trip tests** here.
 */

import {
  AccessGrant,
  AccessIPC,
  AccessIPCChannel,
  AccessIPCError,
  AccessRequest,
  AccessRequestPayload,
  AccessRequestResponse,
  AccessRequestListFilter,
  AccessRequestListResponse,
  AIQueryResponse,
  GrantListResponse,
  PolicyExplanation,
  PolicyQueryPayload,
  PolicyQueryResponse,
  Suggestion,
} from '../access-ipc';

function fakeRequest(state: AccessRequest['state'], id = 'req_test'): AccessRequest {
  return {
    id,
    workspaceId: 'ws_test',
    requesterUserId: 'user_test',
    resourceExternalId: 'res_test',
    state,
    createdAt: new Date(0).toISOString(),
  };
}

const mockGrant: AccessGrant = {
  id: 'grant_test',
  workspaceId: 'ws_test',
  userId: 'user_test',
  connectorId: 'conn_test',
  resourceExternalId: 'res_test',
  grantedAt: new Date(0).toISOString(),
};

const mockExplanation: PolicyExplanation = {
  policyId: 'pol_1',
  summary: 'mock',
  rationale: [],
  affectedResources: [],
};

const mockSuggestion: Suggestion = {
  id: 'sug_1',
  resourceExternalId: 'res_test',
  displayName: 'Mock Resource',
  reason: 'frequently accessed by your team',
};

const mockClient: AccessIPC = {
  requestAccess: {
    async create(payload: AccessRequestPayload): Promise<AccessRequestResponse> {
      return { request: fakeRequest('requested') };
    },
    async list(_filter?: AccessRequestListFilter): Promise<AccessRequestListResponse> {
      return { requests: [], nextCursor: null };
    },
    async approve(id: string): Promise<AccessRequestResponse> {
      return { request: fakeRequest('approved', id) };
    },
    async deny(id: string, _payload): Promise<AccessRequestResponse> {
      return { request: fakeRequest('denied', id) };
    },
    async cancel(id: string): Promise<AccessRequestResponse> {
      return { request: fakeRequest('cancelled', id) };
    },
  },

  async listGrants(): Promise<GrantListResponse> {
    return { grants: [mockGrant], nextCursor: null };
  },

  async queryPolicy(_payload: PolicyQueryPayload): Promise<PolicyQueryResponse> {
    return { explanation: mockExplanation };
  },

  async askAI(): Promise<AIQueryResponse> {
    return { suggestions: [mockSuggestion] };
  },
};

// Force usage so tsc doesn't tree-shake the assertions.
const _channelCheck: typeof AccessIPCChannel.RequestAccessCreate = 'access:requestAccess.create';

async function exerciseContract(client: AccessIPC): Promise<void> {
  const created = await client.requestAccess.create({
    resourceExternalId: 'res_test',
    role: 'viewer',
    justification: 'ci',
  });
  if (created.request.state !== 'requested') {
    throw new Error('expected requested');
  }

  const list = await client.requestAccess.list();
  if (list.requests.length !== 0) {
    throw new Error('expected empty list');
  }

  const approved = await client.requestAccess.approve('req_1');
  if (approved.request.state !== 'approved') {
    throw new Error('expected approved');
  }

  const denied = await client.requestAccess.deny('req_2', { reason: 'policy-violation' });
  if (denied.request.state !== 'denied') {
    throw new Error('expected denied');
  }

  const cancelled = await client.requestAccess.cancel('req_3');
  if (cancelled.request.state !== 'cancelled') {
    throw new Error('expected cancelled');
  }

  const grants = await client.listGrants();
  if (grants.grants.length !== 1) {
    throw new Error('expected one grant');
  }

  const explanation = await client.queryPolicy({ policyId: 'pol_1' });
  if (explanation.explanation.policyId !== 'pol_1') {
    throw new Error('expected pol_1');
  }

  const ai = await client.askAI();
  if (ai.suggestions.length !== 1) {
    throw new Error('expected one suggestion');
  }

  const err = new AccessIPCError('http', 'forbidden', { statusCode: 403 });
  if (err.kind !== 'http' || err.statusCode !== 403) {
    throw new Error('expected http kind / 403');
  }

  void _channelCheck;
}

// Top-level expression so the type-checker actually evaluates the
// assignments above and so the mock isn't tree-shaken.
void exerciseContract(mockClient);
