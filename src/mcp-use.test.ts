/**
 * The adapter, against a stand-in that mimics mcp-use 1.34.x's real contract:
 * `tool(definition, callback)` with the name inside the definition, callbacks
 * dispatched on arity, a `registrations` replay store, and
 * `getServerForSession` building a fresh native server whose `tools/list`
 * handler lives in `server._requestHandlers`.
 */
import {describe, expect, it, vi} from 'vitest';

import {createLaneMcpAuth, SESSION_INFO_TOOL, STEP_UP_TOOL} from './index.js';
import {AUTH_GUIDE_NAME} from './auth-guide.js';
import {claimsForContext, McpUseSeamMissingError, withLaneAuth} from './mcp-use.js';
import {toAuthInfo} from './mcp-sdk.js';
import type {ConnectionKey, ConnectionRecord, ConnectionStore, VerifiedClaims} from './index.js';

const RESOURCE = 'https://acme.example/mcp';
const ISS = 'https://auth.example/mcp';

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
  };
}

type Def = {name: string; description?: string; uri?: string; [key: string]: unknown};
type Handler = (...p: unknown[]) => Promise<unknown>;
type Registration = {config: Def; handler: Handler};

/** Stands in for mcp-use 1.34.x: stores registrations for replay, and builds a
 *  native-server stand-in per session with a real `tools/list` handler. */
function fakeServer(instructions?: string) {
  const registrations = {
    tools: new Map<string, Registration>(),
    prompts: new Map<string, Registration>(),
    resources: new Map<string, Registration>(),
  };
  const routes = new Map<string, (c: unknown) => unknown>();
  const middleware: ((c: unknown, next: () => Promise<void>) => unknown)[] = [];
  return {
    registrations,
    routes,
    middleware,
    config: {instructions} as {instructions?: string},
    tool(def: Def, cb?: Handler) {
      const handler = cb ?? (def.cb as Handler | undefined);
      if (handler) registrations.tools.set(def.name, {config: def, handler});
      return this;
    },
    prompt(def: Def, cb?: Handler) {
      const handler = cb ?? (def.cb as Handler | undefined);
      if (handler) registrations.prompts.set(def.name, {config: def, handler});
      return this;
    },
    resource(def: Def, cb?: Handler) {
      const handler = cb ?? (def.readCallback as Handler | undefined);
      if (handler) registrations.resources.set(`${def.name}:${def.uri}`, {config: def, handler});
      return this;
    },
    app: {
      get(path: string, handler: (c: unknown) => unknown) { routes.set(path, handler); return this; },
      use(_path: string, handler: (c: unknown, next: () => Promise<void>) => unknown) {
        middleware.push(handler); return this;
      },
    },
    getServerForSession(_sessionId?: string) {
      const handlers = new Map<string, Handler>();
      handlers.set('tools/list', async () => ({
        tools: [...registrations.tools.values()].map((r) => ({
          name: r.config.name,
          description: r.config.description ?? '',
          inputSchema: {type: 'object'},
        })),
      }));
      return {server: {_requestHandlers: handlers}};
    },
    /** What a new client connection does: replay the stored registrations. */
    replayForSession() {
      return new Map([...registrations.tools].map(([name, r]) => [name, r.handler]));
    },
  };
}

function build(
  seed?: ConnectionRecord,
  verified: VerifiedClaims | null = CLAIMS,
  instructions?: string
) {
  const auth = createLaneMcpAuth({
    resource: RESOURCE,
    connections: memoryConnections(seed),
    exchanger: {async exchange() { return {accessToken: 'exchanged', scopes: ['email']}; }},
    // Injected so the suite exercises the adapter, not jose.
    verifyToken: async (token: string) => {
      if (verified && token === 'good') return verified;
      throw new Error('bad token');
    },
  });
  return {auth, server: fakeServer(instructions)};
}

const textOf = (r: unknown) => JSON.stringify((r as {content?: unknown}).content ?? r);
const ok = (t: string) => ({content: [{type: 'text' as const, text: t}]});

/** Anonymous / bearer-carrying `extra`, as the SDK transport builds it. */
const extraFor = (bearer?: string) => ({
  requestInfo: {headers: bearer ? {authorization: `Bearer ${bearer}`} : {}},
});

async function listTools(server: ReturnType<typeof fakeServer>, bearer?: string) {
  const native = server.getServerForSession() as {server: {_requestHandlers: Map<string, Handler>}};
  const handler = native.server._requestHandlers.get('tools/list')!;
  return (await handler({method: 'tools/list'}, extraFor(bearer))) as {
    tools: {name: string; description: string}[];
  };
}

describe('withLaneAuth: the gate', () => {
  it('returns the SAME instance', () => {
    const {auth, server} = build();
    expect(withLaneAuth(server, auth)).toBe(server);
  });

  it('gates a tool registered BEFORE the call — no call-order dependency', async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('RESULTS'));
    withLaneAuth(server, auth);
    const cb = server.registrations.tools.get('search')!.handler;
    const out = textOf(await cb({}, ctxFor('good')));
    expect(out).not.toContain('RESULTS');
    expect(out).toContain(STEP_UP_TOOL);
  });

  it('gates a tool registered AFTER the call', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    server.tool({name: 'search'}, async () => ok('RESULTS'));
    const cb = server.registrations.tools.get('search')!.handler;
    const out = textOf(await cb({}, ctxFor('good')));
    expect(out).not.toContain('RESULTS');
    expect(out).toContain(STEP_UP_TOOL);
  });

  it('preserves arity: mcp-use dispatches on fn.length', () => {
    const {auth, server} = build();
    server.tool({name: 'before'}, async () => ok('B'));
    server.prompt({name: 'p-before'}, async () => ok('P'));
    server.resource({name: 'r-before', uri: 'config://r1'}, async () => ok('R'));
    withLaneAuth(server, auth);
    server.tool({name: 'after'}, async () => ok('A'));
    server.prompt({name: 'p-after'}, async () => ok('P'));
    server.resource({name: 'r-after', uri: 'config://r2'}, async () => ok('R'));

    expect(server.registrations.tools.get('before')!.handler).toHaveLength(2);
    expect(server.registrations.tools.get('after')!.handler).toHaveLength(2);
    expect(server.registrations.prompts.get('p-before')!.handler).toHaveLength(2);
    expect(server.registrations.prompts.get('p-after')!.handler).toHaveLength(2);
    expect(server.registrations.resources.get('r-before:config://r1')!.handler).toHaveLength(1);
    expect(server.registrations.resources.get('r-after:config://r2')!.handler).toHaveLength(1);
  });

  it('guards a callback carried INSIDE the definition (`cb`)', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    server.tool({name: 'inline', cb: (async () => ok('INLINE')) as never});
    const out = textOf(await server.registrations.tools.get('inline')!.handler({}, ctxFor('good')));
    expect(out).not.toContain('INLINE');
  });

  it('does not double-guard when called twice', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 0});
    server.tool({name: 'search'}, async () => ok('RESULTS'));
    withLaneAuth(server, auth);
    const once = server.registrations.tools.get('search')!.handler;
    withLaneAuth(server, auth);
    expect(server.registrations.tools.get('search')!.handler).toBe(once);
  });

  it('enforces the scope map, reading the name from the definition', async () => {
    const {auth, server} = build({scopes: [], createdAt: 0});
    server.tool({name: 'place_order'}, async () => ok('ORDERED'));
    withLaneAuth(server, auth, {scopes: {place_order: 'payments:write'}});
    const cb = server.registrations.tools.get('place_order')!.handler;
    const out = textOf(await cb({}, ctxFor('good')));
    expect(out).not.toContain('ORDERED');
    expect(out).toContain('payments:write');
  });

  it('lets a connected caller through', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 0});
    withLaneAuth(server, auth, {scopes: {place_order: 'email'}});
    server.tool({name: 'place_order'}, async () => ok('ORDERED'));
    const cb = server.registrations.tools.get('place_order')!.handler;
    expect(textOf(await cb({}, ctxFor('good')))).toContain('ORDERED');
  });

  it('refuses a bad token as a tool RESULT, not a thrown transport error', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 0});
    withLaneAuth(server, auth);
    server.tool({name: 'search'}, async () => ok('RESULTS'));
    const out = textOf(await server.registrations.tools.get('search')!.handler({}, ctxFor('rubbish')));
    expect(out).toContain('unauthorized');
    expect(out).not.toContain('RESULTS');
  });

  it('covers EVERY session, because the replay store holds the guarded handler', async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('RESULTS'));
    withLaneAuth(server, auth);
    for (const session of [server.replayForSession(), server.replayForSession()]) {
      const out = textOf(await session.get('search')!({}, ctxFor('good')));
      expect(out).toContain(STEP_UP_TOOL);
    }
  });

  it('throws a NAMED error when `registrations` is absent', () => {
    const {auth, server} = build();
    const bare = {...server, registrations: undefined};
    expect(() => withLaneAuth(bare as never, auth)).toThrow(McpUseSeamMissingError);
    try {
      withLaneAuth(bare as never, auth);
    } catch (err) {
      expect((err as Error).name).toBe('McpUseSeamMissingError');
      expect((err as Error).message).toContain('registrations');
    }
  });

  it('throws a NAMED error when `getServerForSession` is absent', () => {
    const {auth, server} = build();
    const bare = {...server, getServerForSession: undefined};
    expect(() => withLaneAuth(bare as never, auth)).toThrow(McpUseSeamMissingError);
  });
});

describe('withLaneAuth: prompts and resources', () => {
  it('gates a pre-registered prompt and resource', async () => {
    const {auth, server} = build();
    server.prompt({name: 'summarise'}, async () => ok('PROMPT'));
    server.resource({name: 'settings', uri: 'config://settings'}, async () => ok('RESOURCE'));
    withLaneAuth(server, auth);
    const p = textOf(await server.registrations.prompts.get('summarise')!.handler({}, ctxFor('good')));
    expect(p).not.toContain('PROMPT');
    const r = textOf(
      await server.registrations.resources.get('settings:config://settings')!.handler(ctxFor('good'))
    );
    expect(r).not.toContain('RESOURCE');
  });

  it('a resource reads its caller from the FIRST argument', async () => {
    const {auth, server} = build({scopes: [], createdAt: 0});
    withLaneAuth(server, auth);
    server.resource({name: 'settings', uri: 'config://settings'}, async () => ok('RESOURCE'));
    const cb = server.registrations.resources.get('settings:config://settings')!.handler;
    expect(textOf(await cb(ctxFor('good')))).toContain('RESOURCE');
  });

  it('leaves `public.resources` names ungated, before and after the call', async () => {
    const {auth, server} = build();
    server.resource({name: 'how-before', uri: 'config://a'}, async () => ok('HOW'));
    withLaneAuth(server, auth, {public: {resources: ['how-before', 'how-after']}});
    server.resource({name: 'how-after', uri: 'config://b'}, async () => ok('HOW'));
    for (const key of ['how-before:config://a', 'how-after:config://b']) {
      expect(textOf(await server.registrations.resources.get(key)!.handler(ctxFor()))).toContain('HOW');
    }
  });

  it('leaves `public.prompts` names ungated', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {public: {prompts: ['getting-started']}});
    server.prompt({name: 'getting-started'}, async () => ok('START'));
    const cb = server.registrations.prompts.get('getting-started')!.handler;
    expect(textOf(await cb({}, ctxFor()))).toContain('START');
  });
});

describe('withLaneAuth: the reserved tools', () => {
  it('registers the step-up tool, ungated', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const reg = server.registrations.tools.get(STEP_UP_TOOL)!;
    const result = (await reg.handler({}, ctxFor('good'))) as {content: {text: string}[]};
    expect(JSON.parse(result.content[0]!.text)).toMatchObject({ok: true});
  });

  it("gives the step-up a Zod OBJECT in mcp-use's `schema` key", () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const def = server.registrations.tools.get(STEP_UP_TOOL)!.config;
    const schema = def.schema as {safeParse?: unknown; shape?: Record<string, unknown>};
    expect(typeof schema.safeParse).toBe('function');
    expect(schema.shape).toHaveProperty('task');
    expect(def.inputSchema).toBeUndefined();
  });

  it('registers lane_session_info, exempt from the connection gate', async () => {
    // The tool exists FOR verified-but-not-connected callers; gating it would
    // make its `connected: false` branch unreachable.
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const reg = server.registrations.tools.get(SESSION_INFO_TOOL)!;
    const result = (await reg.handler({}, ctxFor('good'))) as {content: {text: string}[]};
    const report = JSON.parse(result.content[0]!.text);
    expect(report.connected).toBe(false);
    expect(report.next_step).toContain(STEP_UP_TOOL);
    expect(report.identity.customer_id).toBe(CLAIMS.sub);
  });

  it('lane_session_info reports a connection once one exists', async () => {
    const {auth, server} = build({scopes: ['email'], createdAt: 1_700_000_000_000});
    withLaneAuth(server, auth);
    const reg = server.registrations.tools.get(SESSION_INFO_TOOL)!;
    const result = (await reg.handler({probe_scope: 'email'}, ctxFor('good'))) as {
      content: {text: string}[];
    };
    const report = JSON.parse(result.content[0]!.text);
    expect(report.connected).toBe(true);
    expect(report.session.scopes).toEqual(['email']);
    expect(report.scope_probe).toEqual({scope: 'email', granted: true});
  });

  it('lane_session_info still refuses an UNVERIFIED caller', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const out = textOf(await server.registrations.tools.get(SESSION_INFO_TOOL)!.handler({}, ctxFor()));
    expect(out).toContain('unauthorized');
  });

  it('sessionInfoTool: false leaves it unregistered', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {sessionInfoTool: false});
    expect(server.registrations.tools.has(SESSION_INFO_TOOL)).toBe(false);
  });
});

describe('withLaneAuth: the auth guide', () => {
  it('registers a PUBLIC resource that explains the step-up', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const [key] = [...server.registrations.resources.keys()].filter((k) =>
      k.startsWith(`${AUTH_GUIDE_NAME}:`)
    );
    expect(key).toBeDefined();
    // Ungated: readable with no bearer at all.
    const result = (await server.registrations.resources.get(key!)!.handler(ctxFor())) as {
      contents: {text: string}[];
    };
    expect(result.contents[0]!.text).toContain(STEP_UP_TOOL);
    expect(result.contents[0]!.text).toContain(auth.metadataPaths().root);
  });

  it('mentions lane_session_info only when the tool exists', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {sessionInfoTool: false});
    const [key] = [...server.registrations.resources.keys()];
    const result = (await server.registrations.resources.get(key!)!.handler(ctxFor())) as {
      contents: {text: string}[];
    };
    expect(result.contents[0]!.text).not.toContain(SESSION_INFO_TOOL);
  });

  it('appends operator prose via {append}', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {authGuide: {append: 'Acme staging resets nightly.'}});
    const [key] = [...server.registrations.resources.keys()];
    const result = (await server.registrations.resources.get(key!)!.handler(ctxFor())) as {
      contents: {text: string}[];
    };
    expect(result.contents[0]!.text).toMatch(/Acme staging resets nightly\.$/);
  });

  it('authGuide: false leaves it unregistered', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {authGuide: false});
    expect([...server.registrations.resources.keys()]).toHaveLength(0);
  });
});

describe('withLaneAuth: the anonymous tools/list', () => {
  it('narrows the list for an UNVERIFIED caller to the reserved tools', async () => {
    const {auth, server} = build();
    server.tool({name: 'search', description: 'Find things.'}, async () => ok('R'));
    server.tool({name: 'place_order', description: 'Order things.'}, async () => ok('R'));
    withLaneAuth(server, auth);
    const anonymous = await listTools(server);
    expect(anonymous.tools.map((t) => t.name).sort()).toEqual([STEP_UP_TOOL, SESSION_INFO_TOOL].sort());
  });

  it('shows a VERIFIED caller everything, connected or not', async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('R'));
    withLaneAuth(server, auth);
    const verified = await listTools(server, 'good');
    expect(verified.tools.map((t) => t.name)).toContain('search');
    // And the step-up description carries no hidden-count hint for them.
    const step = verified.tools.find((t) => t.name === STEP_UP_TOOL)!;
    expect(step.description).not.toContain('gated');
  });

  it('says the server is gated, naming how many tools registering unlocks', async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('R'));
    server.tool({name: 'place_order'}, async () => ok('R'));
    withLaneAuth(server, auth);
    const anonymous = await listTools(server);
    const step = anonymous.tools.find((t) => t.name === STEP_UP_TOOL)!;
    expect(step.description).toContain('2 more tools');
  });

  it("anonymousToolList: 'full' leaves the list untouched", async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('R'));
    withLaneAuth(server, auth, {anonymousToolList: 'full'});
    const anonymous = await listTools(server);
    expect(anonymous.tools.map((t) => t.name)).toContain('search');
  });

  it('anonymousToolList: {include} adds named tools to the anonymous list', async () => {
    const {auth, server} = build();
    server.tool({name: 'search'}, async () => ok('R'));
    server.tool({name: 'place_order'}, async () => ok('R'));
    withLaneAuth(server, auth, {anonymousToolList: {include: ['search']}});
    const anonymous = await listTools(server);
    const names = anonymous.tools.map((t) => t.name);
    expect(names).toContain('search');
    expect(names).not.toContain('place_order');
  });

  it('fails OPEN with one warning when the handler map is unreachable', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const {auth, server} = build();
      const opaque = {...server, getServerForSession: () => ({})};
      withLaneAuth(opaque as never, auth);
      opaque.getServerForSession();
      opaque.getServerForSession();
      const seamWarnings = warn.mock.calls.filter(([m]) => String(m).includes('tools/list'));
      expect(seamWarnings).toHaveLength(1);
    } finally {
      warn.mockRestore();
    }
  });
});

describe('withLaneAuth: initialize instructions', () => {
  it('appends the step-up instruction to the operator’s own config', () => {
    const {auth, server} = build(undefined, CLAIMS, 'Acme tools.');
    withLaneAuth(server, auth);
    expect(server.config.instructions).toContain('Acme tools.');
    expect(server.config.instructions).toContain(STEP_UP_TOOL);
  });

  it('writes them even when the operator supplied none, and is idempotent', () => {
    const {auth, server} = build(undefined, CLAIMS, undefined);
    withLaneAuth(server, auth);
    const once = server.config.instructions;
    expect(once).toContain(STEP_UP_TOOL);
    withLaneAuth(server, auth);
    expect(server.config.instructions).toBe(once);
  });

  it('says reuse the SESSION across servers, not the token', () => {
    const {auth, server} = build(undefined, CLAIMS, 'Acme tools.');
    withLaneAuth(server, auth);
    const text = server.config.instructions ?? '';
    expect(text).toMatch(/reuse the SAME agent session/i);
    expect(text.toLowerCase()).toContain('do not carry an access token from another server');
  });
});

describe('withLaneAuth: discovery', () => {
  function invoke(handler: (c: unknown) => unknown) {
    let seen: {body?: string; init?: {status?: number}} = {};
    handler({
      body(body: string, init?: {status?: number}) {
        seen = {body, init};
        return seen;
      },
    });
    return seen;
  }

  it('serves the RFC 9728 document at both well-known paths', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const {root, derived} = auth.metadataPaths();
    expect(server.routes.has(root)).toBe(true);
    expect(server.routes.has(derived!)).toBe(true);
    const doc = invoke(server.routes.get(root)!);
    expect(doc.init?.status).toBeUndefined();
    expect(JSON.parse(doc.body!).authorization_servers).toBeDefined();
  });

  it('answers 404 on a well-known path it did not mount, AFTER the documents', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const handler = server.routes.get('/.well-known/*');
    expect(handler).toBeDefined();
    expect(invoke(handler!).init?.status).toBe(404);
    const paths = [...server.routes.keys()];
    expect(paths.indexOf(auth.metadataPaths().root)).toBeLessThan(paths.indexOf('/.well-known/*'));
  });

  it('wellKnown: {notFoundCatchAll: false} serves documents without the catch-all', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {wellKnown: {notFoundCatchAll: false}});
    expect(server.routes.has(auth.metadataPaths().root)).toBe(true);
    expect(server.routes.has('/.well-known/*')).toBe(false);
  });

  it('wellKnown: false mounts nothing', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {wellKnown: false});
    expect(server.routes.size).toBe(0);
  });
});

/**
 * The 401 challenge. A 401 tells an MCP client "your token is stale", so only a
 * caller the server cannot IDENTIFY gets one — a verified caller with no
 * connection stays a tool result, because a refresh cannot fix a missing
 * consent.
 */
describe('withLaneAuth: the 401 challenge', () => {
  function ctxFor401(body: unknown, bearer?: string) {
    const captured: {status?: number; headers?: Record<string, string>} = {};
    let nexted = false;
    return {
      captured,
      wasNexted: () => nexted,
      next: async () => { nexted = true; },
      ctx: {
        req: {
          method: 'POST',
          header: (n: string) =>
            n.toLowerCase() === 'authorization' && bearer ? `Bearer ${bearer}` : undefined,
          raw: new Request('https://acme.example/mcp', {
            method: 'POST',
            body: JSON.stringify(body),
            headers: {'content-type': 'application/json'},
          }),
        },
        json(_b: unknown, status?: number, headers?: Record<string, string>) {
          captured.status = status; captured.headers = headers; return captured;
        },
      },
    };
  }

  const CALL = {jsonrpc: '2.0', id: 1, method: 'tools/call', params: {name: 'search'}};

  it('challenges an unauthenticated tools/call with 401 + WWW-Authenticate', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const t = ctxFor401(CALL);
    await server.middleware[0]!(t.ctx, t.next);
    expect(t.captured.status).toBe(401);
    expect(t.captured.headers?.['WWW-Authenticate']).toContain('resource_metadata=');
    expect(t.wasNexted()).toBe(false);
  });

  it('does NOT challenge a VALID token with no connection', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const t = ctxFor401(CALL, 'good');
    await server.middleware[0]!(t.ctx, t.next);
    expect(t.captured.status).toBeUndefined();
    expect(t.wasNexted()).toBe(true);
  });

  it('leaves tools/list anonymous', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const t = ctxFor401({jsonrpc: '2.0', id: 1, method: 'tools/list'});
    await server.middleware[0]!(t.ctx, t.next);
    expect(t.captured.status).toBeUndefined();
    expect(t.wasNexted()).toBe(true);
  });

  it('challenges a BATCH containing a tools/call', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const t = ctxFor401([{jsonrpc: '2.0', id: 1, method: 'tools/list'}, CALL]);
    await server.middleware[0]!(t.ctx, t.next);
    expect(t.captured.status).toBe(401);
  });

  it('does not consume the body the real handler needs', async () => {
    const {auth, server} = build();
    withLaneAuth(server, auth);
    const t = ctxFor401({jsonrpc: '2.0', id: 1, method: 'tools/list'});
    await server.middleware[0]!(t.ctx, t.next);
    expect(t.ctx.req.raw.bodyUsed).toBe(false);
    await expect(t.ctx.req.raw.json()).resolves.toMatchObject({method: 'tools/list'});
  });

  it('challengeUnauthenticatedCalls: false mounts nothing', () => {
    const {auth, server} = build();
    withLaneAuth(server, auth, {challengeUnauthenticatedCalls: false});
    expect(server.middleware).toHaveLength(0);
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

  it("does NOT read mcp-use's own ctx.auth — another identity system's verdict", async () => {
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
