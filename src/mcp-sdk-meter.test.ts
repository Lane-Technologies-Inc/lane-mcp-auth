import {describe, expect, it, vi} from 'vitest';
import {guardTool} from './mcp-sdk.js';
import {USAGE_CONTEXT_HEADER} from './usage-context.js';

const CLAIMS = {
  sub: 'pairwise_abc',
  jti: 'j1',
  clientId: 'agent_1',
  scopes: [],
  token: 't',
  exp: 9_999_999_999,
  iss: 'https://lane.test',
};

/** An auth that allows everything, so these tests isolate the meter. */
const auth = {
  authorizeCall: async () => ({kind: 'allow' as const}),
  hasScope: async () => true,
} as unknown as Parameters<typeof guardTool>[0];

const CTX = JSON.stringify({
  laneIntentId: 'lint_01JABC',
  mandateId: 'mand_lint_01JABC_a1b2c3',
});

/** The SDK's `extra`, carrying the verified caller and a header bag. */
const extra = (header?: string) => ({
  // `laneClaims` is the key guardTool's default resolver reads (KEY in
  // mcp-sdk.ts). A wrong key here resolves to no caller, the guard refuses, and
  // the meter never runs -- which is how this fixture was wrong the first time.
  authInfo: {extra: {laneClaims: CLAIMS}},
  requestInfo: header ? {headers: {[USAGE_CONTEXT_HEADER]: header}} : {headers: {}},
});

const guarded = (
  handler: () => Promise<{isError?: boolean; content?: unknown[]}>,
  meter: {record: ReturnType<typeof vi.fn>},
  meterUnits?: Parameters<typeof guardTool>[3] extends undefined ? never : unknown,
) =>
  guardTool(auth, 'search_products', handler as never, {
    getClaims: () => CLAIMS as never,
    meter,
    ...(meterUnits ? {meterUnits: meterUnits as never} : {}),
  } as never);

describe('a successful call is metered', () => {
  it('records one call by default', async () => {
    const record = vi.fn();
    await guarded(async () => ({content: []}), {record})(extra(CTX));
    expect(record).toHaveBeenCalledTimes(1);
    expect(record.mock.calls[0]![0]).toMatchObject({
      productId: 'search_products',
      quantity: 1,
      unit: 'calls',
      laneIntentId: 'lint_01JABC',
      mandateId: 'mand_lint_01JABC_a1b2c3',
    });
  });

  // The pairwise sub is HMAC(userId || audience), so it differs at every
  // merchant and cannot correlate a person across servers.
  it('takes the buyer from the token, not from the agent', async () => {
    const record = vi.fn();
    await guarded(async () => ({content: []}), {record})(extra(CTX));
    expect(record.mock.calls[0]![0].buyerId).toBe('pairwise_abc');
  });

  // A non-Lane agent sends no header. The call still runs and the usage is
  // still recorded, with no address, so the server files it as unattributed.
  it('records without an address when the agent sent no context', async () => {
    const record = vi.fn();
    await guarded(async () => ({content: []}), {record})(extra());
    const ev = record.mock.calls[0]![0];
    expect(ev.laneIntentId).toBeUndefined();
    expect(ev.mandateId).toBeUndefined();
    expect(ev.productId).toBe('search_products');
  });

  it('lets a tool price itself per unit', async () => {
    const record = vi.fn();
    const g = guardTool(auth, 'summarize', (async () => ({content: []})) as never, {
      getClaims: () => CLAIMS as never,
      meter: {record},
      meterUnits: () => ({quantity: 1200, unit: 'tokens'}),
    } as never);
    await g(extra(CTX) as never);
    expect(record.mock.calls[0]![0]).toMatchObject({quantity: 1200, unit: 'tokens'});
  });
});

/**
 * A failed call did work and produced nothing, and Lane's own rule is that
 * failure releases rather than captures. Billing for it would contradict the
 * receipt.
 */
describe('a failed call is not metered', () => {
  it('skips an isError result', async () => {
    const record = vi.fn();
    await guarded(async () => ({isError: true, content: []}), {record})(extra(CTX));
    expect(record).not.toHaveBeenCalled();
  });

  it('skips a thrown handler', async () => {
    const record = vi.fn();
    const g = guarded(async () => {
      throw new Error('boom');
    }, {record});
    await expect(g(extra(CTX) as never)).rejects.toThrow('boom');
    expect(record).not.toHaveBeenCalled();
  });
});

/**
 * Metering must never be able to fail a tool call. That coupling is the whole
 * reason the token verify is offline in the first place.
 */
describe('metering cannot break the call', () => {
  it('returns the result even when the meter throws', async () => {
    const record = vi.fn(() => {
      throw new Error('meter exploded');
    });
    const res = await guarded(async () => ({content: [{type: 'text', text: 'ok'}]}), {record})(
      extra(CTX),
    );
    expect((res as {content: unknown[]}).content).toHaveLength(1);
  });

  it('does nothing at all when no meter is configured', async () => {
    const g = guardTool(auth, 'search_products', (async () => ({content: []})) as never, {
      getClaims: () => CLAIMS as never,
    } as never);
    await expect(g(extra(CTX) as never)).resolves.toBeDefined();
  });

  // A zero or negative count is a bug in the merchant's meterUnits, not a
  // billable event.
  it('records nothing for a non-positive count', async () => {
    const record = vi.fn();
    const g = guardTool(auth, 'freebie', (async () => ({content: []})) as never, {
      getClaims: () => CLAIMS as never,
      meter: {record},
      meterUnits: () => ({quantity: 0, unit: 'calls'}),
    } as never);
    await g(extra(CTX) as never);
    expect(record).not.toHaveBeenCalled();
  });
});

describe('unauthorized calls are not metered', () => {
  it('records nothing when there is no verified caller', async () => {
    const record = vi.fn();
    const g = guardTool(auth, 'search_products', (async () => ({content: []})) as never, {
      getClaims: () => null,
      meter: {record},
    } as never);
    await g({} as never);
    expect(record).not.toHaveBeenCalled();
  });
});

/**
 * The whole-server option, on both transports.
 *
 * A merchant is on the SDK or on mcp-use, not both. Metering that existed on
 * only one would look like a partial rollout rather than a missing option.
 */
describe('enableLaneAuth passes the meter to every tool', () => {
  it('meters a tool registered through the SDK entry point', async () => {
    const {enableLaneAuth} = await import('./mcp-sdk.js');
    const record = vi.fn();
    const registered: Array<(...p: unknown[]) => Promise<unknown>> = [];
    const server = {
      registerTool: (_n: string, _c: unknown, cb: (...p: unknown[]) => Promise<unknown>) => {
        registered.push(cb);
        return {};
      },
      tool: () => ({}),
      _registeredTools: {},
    };

    enableLaneAuth(server as never, auth as never, {
      meter: {record},
      // Prove meterUnits travels too, not just meter.
      meterUnits: () => ({quantity: 7, unit: 'tokens'}),
    } as never);

    (server.registerTool as never as (n: string, c: unknown, cb: unknown) => unknown)(
      'search_products',
      {},
      async () => ({content: []}),
    );

    await registered[registered.length - 1]!(extra(CTX));
    expect(record).toHaveBeenCalledTimes(1);
    expect(record.mock.calls[0]![0]).toMatchObject({
      productId: 'search_products',
      quantity: 7,
      unit: 'tokens',
    });
  });

  it('does not meter when no meter is given', async () => {
    const {enableLaneAuth} = await import('./mcp-sdk.js');
    const registered: Array<(...p: unknown[]) => Promise<unknown>> = [];
    const server = {
      registerTool: (_n: string, _c: unknown, cb: (...p: unknown[]) => Promise<unknown>) => {
        registered.push(cb);
        return {};
      },
      tool: () => ({}),
      _registeredTools: {},
    };
    enableLaneAuth(server as never, auth as never, {} as never);
    (server.registerTool as never as (n: string, c: unknown, cb: unknown) => unknown)(
      'search_products',
      {},
      async () => ({content: []}),
    );
    await expect(registered[registered.length - 1]!(extra(CTX))).resolves.toBeDefined();
  });
});
