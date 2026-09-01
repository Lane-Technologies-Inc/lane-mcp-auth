/**
 * `enableLaneAuth` must gate a server whichever registration method its tools
 * were written against.
 *
 * The MCP SDK carries two: `registerTool`, and the deprecated-but-live `tool`.
 * `tool` does NOT delegate -- it writes to the server's registry itself -- so
 * patching only the modern one would leave every tool registered the old way
 * with no gate at all.
 */
import {describe, expect, it} from 'vitest';

import {createLaneMcpAuth, STEP_UP_TOOL} from './index.js';
import {
  enableLaneAuth,
  guardTool,
  laneTagsFrom,
  registerGuardedTool,
  requiredTagsFor,
  toAuthInfo,
} from './mcp-sdk.js';
import type {ConnectionKey, ConnectionRecord, ConnectionStore, VerifiedClaims} from './index.js';

const RESOURCE = 'https://acme.example/mcp';

const CLAIMS: VerifiedClaims = {
  sub: 'user-1',
  jti: 'tok-1',
  clientId: 'agent-1',
  token: 'raw',
  scopes: [],
  exp: 4_000_000_000,
  iss: 'https://auth.getonlane.com/auth/mcp',
};

/** What the SDK passes as the last argument to a tool handler. */
const extra = () => ({authInfo: toAuthInfo(CLAIMS)});

function memoryConnections(seed?: ConnectionRecord): ConnectionStore {
  const rows = new Map<string, ConnectionRecord>();
  if (seed) rows.set(`${CLAIMS.sub}::${CLAIMS.jti}`, seed);
  return {
    async get(key: ConnectionKey) {
      return rows.get(`${key.sub}::${key.jti}`) ?? null;
    },
    async put(key: ConnectionKey, record: ConnectionRecord) {
      rows.set(`${key.sub}::${key.jti}`, record);
      return record;
    },
  };
}

/** A stand-in with BOTH registration methods, recording what each was given. */
function fakeServer() {
  const handlers = new Map<string, (...p: never[]) => Promise<unknown>>();
  return {
    handlers,
    registerTool(name: string, _config: Record<string, unknown>, cb: unknown) {
      handlers.set(name, cb as (...p: never[]) => Promise<unknown>);
      return {name};
    },
    tool(name: string, ...rest: unknown[]) {
      handlers.set(name, rest[rest.length - 1] as (...p: never[]) => Promise<unknown>);
      return {name};
    },
  };
}

function build(seed?: ConnectionRecord) {
  const auth = createLaneMcpAuth({
    resource: RESOURCE,
    connections: memoryConnections(seed),
    exchanger: {
      async exchange() {
        return {accessToken: 'exchanged', scopes: []};
      },
    },
  });
  const server = fakeServer();
  return {auth, server};
}

const textOf = (result: unknown): string =>
  JSON.stringify((result as {content?: unknown}).content ?? result);

describe('enableLaneAuth covers every registration method', () => {
  it('gates a tool registered with registerTool', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);

    server.registerTool('modern', {description: 'd', inputSchema: {}}, async () => ({
      content: [{type: 'text', text: 'RAN UNGATED'}],
    }));

    const out = textOf(await server.handlers.get('modern')!(extra() as never));
    expect(out).not.toContain('RAN UNGATED');
    expect(out).toContain(STEP_UP_TOOL);
  });

  it('gates a tool registered with the legacy tool()', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);

    // The old four-argument overload: (name, description, schema, cb).
    server.tool('legacy', 'a description', {}, async () => ({
      content: [{type: 'text', text: 'RAN UNGATED'}],
    }));

    const out = textOf(await server.handlers.get('legacy')!(extra() as never));
    expect(out).not.toContain('RAN UNGATED');
    expect(out).toContain(STEP_UP_TOOL);
  });

  it('applies the scope map to a legacy registration too', async () => {
    // Connected, but without the scope the tool demands.
    const {auth, server} = build({scopes: [], createdAt: 0});
    enableLaneAuth(server, auth, {scopes: {place_order: 'payments:write'}});

    server.tool('place_order', async () => ({
      content: [{type: 'text', text: 'RAN WITHOUT THE SCOPE'}],
    }));

    const out = textOf(await server.handlers.get('place_order')!(extra() as never));
    expect(out).not.toContain('RAN WITHOUT THE SCOPE');
    expect(out).toContain('payments:write');
  });

  it('lets a connected caller through when the scope is held', async () => {
    const {auth, server} = build({scopes: ['payments:write'], createdAt: 0});
    enableLaneAuth(server, auth, {scopes: {place_order: 'payments:write'}});

    server.tool('place_order', async () => ({
      content: [{type: 'text', text: 'ordered'}],
    }));

    expect(textOf(await server.handlers.get('place_order')!(extra() as never))).toContain(
      'ordered'
    );
  });

  it('leaves the step-up tool reachable', async () => {
    const {auth, server} = build();
    enableLaneAuth(server, auth);
    expect(server.handlers.has(STEP_UP_TOOL)).toBe(true);
  });
});

describe('guardTool: finding the caller when the framework passes no `extra`', () => {
  // mcp-use calls a tool handler with the ARGUMENTS ONLY. The default resolver
  // reads `extra.authInfo`, so without a seam every guarded tool on such a
  // framework refuses every call -- a gate that fails closed on all traffic.
  const ok = (t: string) => ({content: [{type: 'text' as const, text: t}]});
  const frameworkStyleHandler = async (_args: {sku: string}) => ok('ORDERED');

  it('refuses everything by default, which is the bug this seam exists for', async () => {
    const {auth} = build({scopes: [], createdAt: 0});
    const guarded = guardTool(auth, 'place_order', frameworkStyleHandler);
    // No second argument, exactly as mcp-use would call it.
    const out = textOf(await guarded({sku: 'x'}));
    expect(out).not.toContain('ORDERED');
    expect(out).toContain('unauthorized');
  });

  it('reads the caller from a resolver instead, and the gate then works', async () => {
    const {auth} = build({scopes: [], createdAt: 0});
    const guarded = guardTool(auth, 'place_order', frameworkStyleHandler, {
      getClaims: () => CLAIMS,
    });
    expect(textOf(await guarded({sku: 'x'}))).toContain('ORDERED');
  });

  it('still applies the scope layer through the resolver', async () => {
    // Connected, but without the scope the tool demands.
    const {auth} = build({scopes: [], createdAt: 0});
    const guarded = guardTool(auth, 'place_order', frameworkStyleHandler, {
      scopes: {place_order: 'payments:write'},
      getClaims: () => CLAIMS,
    });
    const out = textOf(await guarded({sku: 'x'}));
    expect(out).not.toContain('ORDERED');
    expect(out).toContain('payments:write');
  });

  it('treats a null from the resolver as unauthenticated, not as a crash', async () => {
    const {auth} = build({scopes: [], createdAt: 0});
    const guarded = guardTool(auth, 'place_order', frameworkStyleHandler, {
      getClaims: () => null,
    });
    expect(textOf(await guarded({sku: 'x'}))).toContain('unauthorized');
  });

  it('hands the resolver the handler arguments, so it can read a framework ctx', async () => {
    const {auth} = build({scopes: [], createdAt: 0});
    let saw: unknown = 'never called';
    const guarded = guardTool(
      auth,
      'place_order',
      async (_args: {sku: string}, ctx: {laneClaims: typeof CLAIMS}) => ok(`ORDERED for ${ctx.laneClaims.sub}`),
      {getClaims: ((_args: unknown, ctx: {laneClaims: typeof CLAIMS}) => { saw = ctx; return ctx.laneClaims; }) as never},
    );
    const out = textOf(await guarded({sku: 'x'}, {laneClaims: CLAIMS}));
    expect(saw).toEqual({laneClaims: CLAIMS});
    expect(out).toContain('ORDERED for user-1');
  });
});

describe('Lane authority tags declared in annotations', () => {
  it('laneTagsFrom reads an array or a space-separated string, else none', () => {
    expect(laneTagsFrom({'lane/tags': ['purchase', 'manage']})).toEqual(['purchase', 'manage']);
    expect(laneTagsFrom({'lane/tags': 'read purchase'})).toEqual(['read', 'purchase']);
    expect(laneTagsFrom({'lane/tags': 42})).toEqual([]);
    expect(laneTagsFrom(undefined)).toEqual([]);
  });

  it('requiredTagsFor lets a per-tool scopes entry override the annotation', () => {
    const ann = {'lane/tags': ['read']};
    expect(requiredTagsFor('t', ann, undefined)).toEqual(['read']);
    expect(requiredTagsFor('t', ann, {t: 'purchase'})).toEqual(['purchase']);
    expect(requiredTagsFor('t', {}, undefined)).toEqual([]);
  });

  it('refuses a tool whose lane/tags the connection does not hold', async () => {
    const {auth, server} = build({scopes: [], createdAt: 0});
    enableLaneAuth(server, auth);
    server.registerTool(
      'confirm_order',
      {description: 'd', inputSchema: {}, annotations: {'lane/tags': ['purchase']}},
      async () => ({content: [{type: 'text', text: 'CHARGED'}]})
    );
    const out = textOf(await server.handlers.get('confirm_order')!(extra() as never));
    expect(out).not.toContain('CHARGED');
    expect(out).toContain('purchase');
  });

  it('lets the caller through when the connection holds the tag', async () => {
    const {auth, server} = build({scopes: ['purchase'], createdAt: 0});
    enableLaneAuth(server, auth);
    server.registerTool(
      'confirm_order',
      {description: 'd', inputSchema: {}, annotations: {'lane/tags': ['purchase']}},
      async () => ({content: [{type: 'text', text: 'ordered'}]})
    );
    expect(textOf(await server.handlers.get('confirm_order')!(extra() as never))).toContain(
      'ordered'
    );
  });

  it('requires EVERY tag when a tool declares more than one', async () => {
    // Holds purchase, lacks manage.
    const {auth, server} = build({scopes: ['purchase'], createdAt: 0});
    enableLaneAuth(server, auth);
    server.registerTool(
      'modify_order',
      {description: 'd', inputSchema: {}, annotations: {'lane/tags': ['purchase', 'manage']}},
      async () => ({content: [{type: 'text', text: 'modified'}]})
    );
    const out = textOf(await server.handlers.get('modify_order')!(extra() as never));
    expect(out).not.toContain('modified');
    expect(out).toContain('manage');
  });

  it('the scopes map overrides the annotation for enforcement', async () => {
    // Author tagged it `read`, the deployment gates it on `purchase`.
    const {auth, server} = build({scopes: ['read'], createdAt: 0});
    enableLaneAuth(server, auth, {scopes: {soft_tool: 'purchase'}});
    server.registerTool(
      'soft_tool',
      {description: 'd', inputSchema: {}, annotations: {'lane/tags': ['read']}},
      async () => ({content: [{type: 'text', text: 'ran'}]})
    );
    const out = textOf(await server.handlers.get('soft_tool')!(extra() as never));
    expect(out).not.toContain('ran');
    expect(out).toContain('purchase');
  });

  it('registerGuardedTool writes the tags into annotations and enforces them', async () => {
    const {auth} = build({scopes: [], createdAt: 0});
    let captured: Record<string, unknown> | undefined;
    const handlers = new Map<string, (...p: never[]) => Promise<unknown>>();
    const srv = {
      registerTool(name: string, config: Record<string, unknown>, cb: unknown) {
        captured = config;
        handlers.set(name, cb as (...p: never[]) => Promise<unknown>);
        return {name};
      },
    };
    registerGuardedTool(
      srv as never,
      auth,
      {name: 'buy', description: 'd', inputSchema: {}, tags: ['purchase']},
      async () => ({content: [{type: 'text', text: 'bought'}]})
    );
    expect((captured?.annotations as Record<string, unknown>)['lane/tags']).toEqual(['purchase']);
    // Connected (empty scopes) but lacks the tag -> insufficient_scope.
    const out = textOf(await handlers.get('buy')!(extra() as never));
    expect(out).not.toContain('bought');
    expect(out).toContain('purchase');
  });
});
