/**
 * The adapter, against a stand-in that mimics mcp-use's real contract:
 * `tool(definition, callback)` with the name inside the definition, and a
 * callback invoked as `(params, ctx)` where ctx is a Hono-shaped request
 * context. Both shapes are taken from mcp-use 1.34.3's own type declarations.
 */
import {describe, expect, it} from 'vitest';

import {createLaneMcpAuth, STEP_UP_TOOL} from './index.js';
import {claimsForContext, enableLaneAuth, mountDiscovery} from './mcp-use.js';
import {toAuthInfo} from './mcp-sdk.js';
import type {ConnectionKey, ConnectionRecord, ConnectionStore, VerifiedClaims} from './index.js';

const RESOURCE = 'https://acme.example/mcp';
const ISS = 'https://auth.getonlane.com/auth/mcp';

const CLAIMS: VerifiedClaims = {
  sub: 'user-1', jti: 'tok-1', clientId: 'agent-1', token: 'raw', scopes: [],
  exp: 4_000_000_000, iss: ISS,
};

function memoryConnections(seed?: ConnectionRecord): ConnectionStore {
  const rows = new Map<string, ConnectionRecord>();
  if (seed) rows.set(`${CLAIMS.sub}::${CLAIMS.jti}`, seed);
  return {
    async get(k: ConnectionKey) { return rows.get(`${k.sub}::${k.jti}`) ?? null; },
    async put(k: ConnectionKey, r: ConnectionRecord) { rows.set(`${k.sub}::${k.jti}`, r); return r; },
  };
}

/** A Hono-shaped request context, per request, as mcp-use passes one. */
function ctxFor(bearer?: string, auth?: unknown) {
  const bag = new Map<string, unknown>();
  return {
    req: {header: (n: string) => (n.toLowerCase() === 'authorization' && bearer ? `Bearer ${bearer}` : undefined)},
    get: (k: string) => bag.get(k),
    set: (k: string, v: unknown) => void bag.set(k, v),
    ...(auth ? {auth} : {}),
    _verifications: () => bag,
  };
}

/** Stands in for mcp-use: records definitions, and REPLAYS them per session. */
function fakeServer() {
  type Def = {name: string; [key: string]: unknown};
  const registered: {definition: Def; callback?: (...p: never[]) => unknown}[] = [];
  const routes = new Map<string, (c: unknown) => unknown>();
  return {
    registered,
    routes,
    tool(definition: Def, callback?: (...p: never[]) => unknown) {
      registered.push({definition, callback});
      return this;
    },
    app: {get(path: string, handler: (c: unknown) => unknown) { routes.set(path, handler); return this; }},
    /** What a new client connection does: replay onto a fresh native server. */
    replayForSession() {
      return new Map(registered.map((r) => [r.definition.name, r.callback]));
    },
  };
}

function build(seed?: ConnectionRecord, verified: VerifiedClaims | null = CLAIMS) {
  const auth = createLaneMcpAuth({
    resource: RESOURCE,
    connections: memoryConnections(seed),
    exchanger: {async exchange() { return {accessToken: 'exchanged', scopes: ['email']}; }},
    // Injected so the test exercises the adapter, not jose.
    verifyToken: async (token: string) => {
      if (verified && token === 'good') return verified;
      throw new Error('bad token');
    },
  });
  return {auth, server: fakeServer()};
}

const textOf = (r: unknown) => JSON.stringify((r as {content?: unknown}).content ?? r);
const ok = (t: string) => ({content: [{type: 'text' as const, text: t}]});

describe('enableLaneAuth on mcp-use', () => {
  it('hands mcp-use a TWO-PARAMETER callback, or it is never given a context', () => {
    // mcp-use decides whether to pass its request context by reading the
    // callback's arity, and `guardTool` returns a rest-param function whose
    // length is 0. Registering that directly meant every guarded tool was
    // called with no context and refused every request as unauthenticated --
    // while the step-up tool, written `(params, ctx)`, worked. Only an
    // end-to-end run showed it; this is the unit-level guard.
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    server.tool({name: 'search', schema: {}}, (async () => ok('RESULTS')) as never);
    const registered = server.registered.find((r) => r.definition.name === 'search')!;
    expect(registered.callback).toHaveLength(2);
  });

  it('reads the tool name from the DEFINITION, not a positional argument', async () => {
    const {auth, server} = build({scopes: [], createdAt: 0});
    enableLaneAuth(server, auth, {scopes: {place_order: 'payments:write'}});
    server.tool({name: 'place_order', schema: {}}, (async () => ok('ORDERED')) as never);

    const cb = server.replayForSession().get('place_order')!;
    // Connected, but lacking the scope the map demands.
    const out = textOf(await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('good')));
    expect(out).not.toContain('ORDERED');
    expect(out).toContain('payments:write');
  });

  it('gates a tool for a caller with no connection, naming the step-up tool', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    server.tool({name: 'search', schema: {}}, (async () => ok('RESULTS')) as never);

    const cb = server.replayForSession().get('search')!;
    const out = textOf(await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('good')));
    expect(out).not.toContain('RESULTS');
    expect(out).toContain(STEP_UP_TOOL);
  });

  it('lets a connected caller through', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 0});
    enableLaneAuth(server, auth, {scopes: {place_order: 'email'}});
    server.tool({name: 'place_order', schema: {}}, (async () => ok('ORDERED')) as never);

    const cb = server.replayForSession().get('place_order')!;
    expect(textOf(await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('good')))).toContain('ORDERED');
  });

  it('refuses a bad token as a tool RESULT, not a thrown transport error', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 0});
    enableLaneAuth(server, auth);
    server.tool({name: 'search', schema: {}}, (async () => ok('RESULTS')) as never);

    const cb = server.replayForSession().get('search')!;
    const out = textOf(await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('rubbish')));
    expect(out).toContain('unauthorized');
    expect(out).not.toContain('RESULTS');
  });

  it('covers EVERY session, because the wrapper is applied before the replay', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    server.tool({name: 'search', schema: {}}, (async () => ok('RESULTS')) as never);

    // Two client connections, each replaying the stored registrations.
    for (const session of [server.replayForSession(), server.replayForSession()]) {
      const cb = session.get('search')!;
      const out = textOf(await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('good')));
      expect(out).toContain(STEP_UP_TOOL);
    }
  });

  it('registers the step-up tool, and does not gate it', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    const names = server.registered.map((r) => r.definition.name);
    expect(names).toContain(STEP_UP_TOOL);

    // It must answer for an unconnected caller -- it is the way OUT of the gate.
    const cb = server.replayForSession().get(STEP_UP_TOOL)!;
    const result = (await (cb as (...p: unknown[]) => Promise<unknown>)({}, ctxFor('good'))) as {
      content: {text: string}[];
    };
    // The step-up returns its payload as JSON text; parse rather than
    // string-match, because `textOf` escapes the inner quotes.
    expect(JSON.parse(result.content[0]!.text)).toMatchObject({ok: true});
  });

  it('gives the step-up a Zod OBJECT, not the SDK\'s raw shape', () => {
    // The two frameworks disagree about what a schema is: the SDK's
    // `inputSchema` is `{task: z.string()}`, mcp-use's `schema` is
    // `z.object({task: z.string()})`. Passing the shape through was accepted at
    // runtime as a schema matching nothing, which drops `task` -- so consent
    // could never record a summary and the failure was silent.
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    const def = server.registered.find((r) => r.definition.name === STEP_UP_TOOL)!.definition;
    const schema = def.schema as {parse?: unknown; safeParse?: unknown; shape?: unknown};
    expect(typeof schema.safeParse).toBe('function');
    expect(schema.shape).toHaveProperty('task');
  });

  it('translates the step-up definition into mcp-use\'s shape', () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    const def = server.registered.find((r) => r.definition.name === STEP_UP_TOOL)!
      .definition as Record<string, unknown>;
    // mcp-use reads `schema`; `inputSchema` would be ignored and the tool's
    // arguments dropped.
    expect(def.schema).toBeDefined();
    expect(def.inputSchema).toBeUndefined();
  });
});

describe('claimsForContext', () => {
  it('verifies once per request and caches, including a negative answer', async () => {
    let calls = 0;
    const auth = createLaneMcpAuth({
      resource: RESOURCE,
      connections: memoryConnections(),
      exchanger: {async exchange() { return {accessToken: 'x', scopes: []}; }},
      verifyToken: async () => { calls++; throw new Error('bad'); },
    });
    const ctx = ctxFor('rubbish');
    expect(await claimsForContext(auth, ctx)).toBeNull();
    expect(await claimsForContext(auth, ctx)).toBeNull();
    expect(calls).toBe(1);
  });

  it('uses claims a server already put on the context, without re-verifying', async () => {
    const {auth} = build(undefined, null); // its own verifier would refuse
    const bag = new Map<string, unknown>([['laneClaims', CLAIMS]]);
    const ctx = {
      req: {header: () => undefined},
      get: (k: string) => bag.get(k),
      set: (k: string, v: unknown) => void bag.set(k, v),
    };
    expect((await claimsForContext(auth, ctx))?.sub).toBe(CLAIMS.sub);
  });

  it('does NOT read mcp-use\'s own ctx.auth', async () => {
    // That is another OAuth system's result. Accepting it would let whatever it
    // decided stand in for Lane's verification -- which is the one thing the
    // gate exists to do. An earlier version of this adapter read it; this test
    // is why it does not.
    const {auth} = build(undefined, null);
    const bag = new Map<string, unknown>();
    const ctx = {
      req: {header: () => undefined},
      get: (k: string) => bag.get(k),
      set: (k: string, v: unknown) => void bag.set(k, v),
      auth: toAuthInfo(CLAIMS),
    };
    expect(await claimsForContext(auth, ctx as never)).toBeNull();
  });
});

describe('mountDiscovery', () => {
  it('serves the document at BOTH well-known paths', () => {
    const {auth, server} = build();
    expect(mountDiscovery(server, auth)).toBe(true);
    const {root, derived} = auth.metadataPaths();
    expect(server.routes.has(root)).toBe(true);
    expect(server.routes.has(derived!)).toBe(true);
  });

  it('reports FALSE rather than pretending, when the build exposes no app', () => {
    const {auth} = build();
    expect(mountDiscovery({tool() { return this; }}, auth)).toBe(false);
  });
});
