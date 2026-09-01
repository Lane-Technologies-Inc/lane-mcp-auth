/**
 * Tool-call billing at the ingress: the merchant's own server saying which
 * PERIOD a call belongs to.
 *
 * The merchant knows their cadence at config time, so it is a guard option and
 * not a lookup. Reading merchant config on the tool-call hot path would put a
 * network round trip in front of every call, which is the same trade the offline
 * token verify exists to avoid.
 */
import {describe, expect, it, vi} from 'vitest';
import {enableLaneAuth, guardTool} from './mcp-sdk.js';
import {MCP_BILLING_CADENCES, billingMonthKey} from './meter.js';
import {USAGE_CONTEXT_HEADER} from './usage-context.js';

const CLAIMS = {
  sub: 'pairwise_abc',
  jti: 'tok_session_1',
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

const extra = (header?: string) => ({
  authInfo: {extra: {laneClaims: CLAIMS}},
  requestInfo: header ? {headers: {[USAGE_CONTEXT_HEADER]: header}} : {headers: {}},
});

/** August 2026, fixed, so the month key is not a function of the test clock. */
const AUG_2026 = Date.UTC(2026, 7, 26, 12, 0, 0);

const guarded = (
  record: ReturnType<typeof vi.fn>,
  billing?: {cadence: 'monthly' | 'per_session'; now?: () => number},
) =>
  guardTool(auth, 'search_products', (async () => ({content: []})) as never, {
    getClaims: () => CLAIMS as never,
    meter: {record},
    ...(billing ? {billing} : {}),
  } as never);

/**
 * THE SESSION IS THE ACCESS TOKEN'S LIFE. `jti` already scopes a connection to
 * one credential at one merchant and already expires, which is exactly the
 * lifetime a billing session has -- so nothing is minted for it.
 */
describe('per-session billing', () => {
  it('uses the token id as the period', async () => {
    const record = vi.fn();
    await guarded(record, {cadence: 'per_session'})(extra());
    expect(record.mock.calls[0]![0].periodKey).toBe('tok_session_1');
  });

  // A run id is `trc_*`-class observability and must never be load-bearing, so
  // it is not what a period is addressed by even when the agent sends one.
  it('ignores a run id the agent supplied', async () => {
    const record = vi.fn();
    const withRun = JSON.stringify({
      laneIntentId: 'lint_01JABC',
      mandateId: 'mand_lint_01JABC_a1b2c3',
      runId: 'flr_should_not_be_used',
    });
    await guarded(record, {cadence: 'per_session'})(extra(withRun));
    expect(record.mock.calls[0]![0].periodKey).toBe('tok_session_1');
  });
});

describe('monthly billing', () => {
  it('uses the calendar month as the period', async () => {
    const record = vi.fn();
    await guarded(record, {cadence: 'monthly', now: () => AUG_2026})(extra());
    expect(record.mock.calls[0]![0].periodKey).toBe('2026-08');
  });

  it('is the UTC month, matching the ledger`s own monthKeyOf', async () => {
    expect(billingMonthKey(AUG_2026)).toBe('2026-08');
    expect(billingMonthKey(Date.UTC(2026, 0, 1))).toBe('2026-01');
    // The last instant of December UTC is still December, not January.
    expect(billingMonthKey(Date.UTC(2026, 11, 31, 23, 59, 59))).toBe('2026-12');
  });

  it('defaults to the real clock when no seam is given', async () => {
    const record = vi.fn();
    await guarded(record, {cadence: 'monthly'})(extra());
    expect(record.mock.calls[0]![0].periodKey).toMatch(/^\d{4}-\d{2}$/);
  });
});

/**
 * The buyer is the token's pairwise subject, which is HMAC(userId || audience)
 * and therefore different at every merchant. Nothing the agent supplied is used.
 */
describe('who is charged', () => {
  it('is the token`s subject, on both cadences', async () => {
    for (const cadence of MCP_BILLING_CADENCES) {
      const record = vi.fn();
      await guarded(record, {cadence, now: () => AUG_2026})(extra(CTX));
      expect(record.mock.calls[0]![0].buyerId).toBe('pairwise_abc');
    }
  });
});

/**
 * The billing namespace and the mandate namespace are separate partitions in the
 * ledger. One call produces one event, so which namespace it lands in has to be
 * decided here rather than left to whichever field happens to be set.
 */
describe('billing and the mandate address do not mix', () => {
  it('carries no intent or mandate, even when the agent sent one', async () => {
    const record = vi.fn();
    await guarded(record, {cadence: 'per_session'})(extra(CTX));
    const ev = record.mock.calls[0]![0];
    expect(ev.periodKey).toBe('tok_session_1');
    expect(ev.laneIntentId).toBeUndefined();
    expect(ev.mandateId).toBeUndefined();
  });

  it('carries no period when the merchant is not billing for tool calls', async () => {
    const record = vi.fn();
    await guarded(record)(extra(CTX));
    const ev = record.mock.calls[0]![0];
    expect(ev.periodKey).toBeUndefined();
    expect(ev.laneIntentId).toBe('lint_01JABC');
  });
});

/** Metering is never a gate, and adding billing to it does not change that. */
describe('billing cannot break the call', () => {
  it('returns the result even when the meter throws', async () => {
    const record = vi.fn(() => {
      throw new Error('meter exploded');
    });
    const g = guardTool(auth, 'search_products', (async () => ({content: [{type: 'text', text: 'ok'}]})) as never, {
      getClaims: () => CLAIMS as never,
      meter: {record},
      billing: {cadence: 'per_session'},
    } as never);
    const res = await g(extra() as never);
    expect((res as {content: unknown[]}).content).toHaveLength(1);
  });

  // A failed call did work and produced nothing, and Lane's rule is that failure
  // releases rather than captures. Billing for it would contradict the receipt.
  it('does not bill a failed call', async () => {
    const record = vi.fn();
    const g = guardTool(auth, 'search_products', (async () => ({isError: true, content: []})) as never, {
      getClaims: () => CLAIMS as never,
      meter: {record},
      billing: {cadence: 'per_session'},
    } as never);
    await g(extra() as never);
    expect(record).not.toHaveBeenCalled();
  });
});

/**
 * A merchant opts in once for the whole server. Metering that reached only some
 * tools would look like a partial rollout rather than a missing option.
 */
describe('enableLaneAuth carries billing to every tool', () => {
  const sdkServer = () => {
    const registered: Array<(...p: unknown[]) => Promise<unknown>> = [];
    return {
      registered,
      server: {
        registerTool: (_n: string, _c: unknown, cb: (...p: unknown[]) => Promise<unknown>) => {
          registered.push(cb);
          return {};
        },
        tool: () => ({}),
        _registeredTools: {},
      },
    };
  };

  it('on the raw SDK entry point', async () => {
    const record = vi.fn();
    const {registered, server} = sdkServer();
    enableLaneAuth(server as never, auth as never, {
      meter: {record},
      billing: {cadence: 'per_session'},
    } as never);
    (server.registerTool as never as (n: string, c: unknown, cb: unknown) => unknown)(
      'search_products',
      {},
      async () => ({content: []}),
    );
    await registered[registered.length - 1]!(extra());
    expect(record.mock.calls[0]![0].periodKey).toBe('tok_session_1');
  });

  it('on the mcp-use adapter', async () => {
    // `withLaneAuth`, renamed from `enableLaneAuth` on main. It rewrites the
    // replay store and patches the registration methods, so the fake has to
    // carry both seams or it refuses to wrap at all.
    const {withLaneAuth} = await import('./mcp-use.js');
    const record = vi.fn();
    const registered: Array<(params: unknown, ctx: unknown) => Promise<unknown>> = [];
    const server = {
      tool: (_definition: unknown, callback?: (params: unknown, ctx: unknown) => Promise<unknown>) => {
        if (callback) registered.push(callback);
        return {};
      },
      registrations: {
        tools: new Map<string, {config: unknown; handler: unknown}>(),
        prompts: new Map<string, {config: unknown; handler: unknown}>(),
        resources: new Map<string, {config: unknown; handler: unknown}>(),
      },
      getServerForSession: () => ({}),
    };
    const mcpUseAuth = {
      ...(auth as unknown as Record<string, unknown>),
      authenticate: async () => ({kind: 'ok' as const, claims: CLAIMS}),
    };
    withLaneAuth(server as never, mcpUseAuth as never, {
      meter: {record},
      billing: {cadence: 'monthly', now: () => AUG_2026},
      // Off: neither needs a real mcp-use, and both would register extra tools
      // that this test would then have to skip past.
      sessionInfoTool: false,
      challengeUnauthenticatedCalls: false,
    } as never);
    (server.tool as never as (d: unknown, cb: unknown) => unknown)(
      {name: 'search_products'},
      async () => ({content: []}),
    );
    const ctx = {
      req: {header: (n: string) => (n === 'authorization' ? 'Bearer good' : undefined)},
      get: () => undefined,
      set: () => undefined,
    };
    await registered[registered.length - 1]!({}, ctx);
    expect(record.mock.calls[0]![0].periodKey).toBe('2026-08');
  });
});

/**
 * The cadence union is DECLARED HERE rather than imported. This package publishes
 * to npm with only `jose` and `zod` as dependencies, so it cannot depend on the
 * Lane monorepo's shared types -- but a local copy of a domain union is exactly
 * the kind of drift that passes every test in both places while the two
 * disagree. So `packages/types/settlement.ts` is read off disk and compared.
 *
 * Skipped outside the monorepo, where that file genuinely does not exist: the
 * published mirror ships this test and has nothing to check against.
 */
describe('the cadence union matches the monorepo definition', () => {
  it('enumerates exactly the cadences settlement.ts defines', async () => {
    const fs = await import('node:fs');
    const source = new URL('../../types/settlement.ts', import.meta.url);
    if (!fs.existsSync(source)) {
      expect(MCP_BILLING_CADENCES.length).toBeGreaterThan(0);
      return;
    }
    const text = fs.readFileSync(source, 'utf8');
    const declared = /BILLING_CADENCES\s*=\s*\[([^\]]*)\]/.exec(text)?.[1] ?? '';
    const names = [...declared.matchAll(/'([a-z_]+)'/g)].map((m) => m[1]);
    expect(names.length).toBeGreaterThan(0);
    expect([...MCP_BILLING_CADENCES].sort()).toEqual([...names].sort());
  });
});
