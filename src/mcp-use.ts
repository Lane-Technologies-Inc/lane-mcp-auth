/**
 * @fileoverview mcp-use adapter. `withLaneAuth(server, auth)` takes an
 * ALREADY-BUILT `MCPServer` — tools registered or not — and returns the same
 * instance, gated. Built against mcp-use 1.34.x.
 */
import {z} from 'zod';

import {
  guardTool,
  requiredTagsFor,
  stepUpTool,
  type GuardOptions,
  type SdkToolResult,
} from './mcp-sdk.js';
import {AUTH_GUIDE_NAME, AUTH_GUIDE_URI, authGuideText} from './auth-guide.js';
import {describeSession, sessionInfoDescription, type SessionArgs} from './session-info.js';
import {
  SESSION_INFO_TOOL,
  STEP_UP_TOOL,
  type LaneMcpAuth,
  type VerifiedClaims,
} from './index.js';

/** Where the verified caller is cached on the request context. */
const CTX_KEY = 'laneClaims';

// Marks a handler the gate already wrapped, so a second withLaneAuth cannot
// double-guard it.
const GUARDED = Symbol.for('lane.mcpAuth.guarded');

/** The parts of mcp-use's Hono request context this adapter touches.
 *  Structural: a type dependency on mcp-use would make every consumer install it. */
export type McpUseContext = {
  req?: {header(name: string): string | undefined};
  get?(key: string): unknown;
  set?(key: string, value: unknown): void;
};

/** A tool definition as mcp-use takes it: name inside, `schema` not `inputSchema`. */
export type McpUseToolDefinition = {
  name: string;
  title?: string;
  description?: string;
  schema?: unknown;
  annotations?: Record<string, unknown>;
  [key: string]: unknown;
};

/** One replayable registration, as mcp-use stores it. `any` because naming
 *  mcp-use's own config and callback types would require importing it. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type McpUseRegistration = {config: any; handler: any};

/**
 * The mcp-use surface `withLaneAuth` needs, structurally.
 *
 * The registration methods are `any`-parameterised on purpose: mcp-use declares
 * them as PROPERTIES holding generic arrow functions, so `strictFunctionTypes`
 * checks them contravariantly and any narrower hand-written type makes a real
 * `MCPServer` unassignable.
 */
export type McpUseServerLike = {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool: (...args: any[]) => unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  prompt?: (...args: any[]) => unknown;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  resource?: (...args: any[]) => unknown;
  /** mcp-use's replay store: "Storage for registrations that can be replayed on
   *  new server instances". Optional in the TYPE so the wrap-time check, not an
   *  assignability error, is what reports an unsupported mcp-use. */
  registrations?: {
    tools: Map<string, McpUseRegistration>;
    prompts: Map<string, McpUseRegistration>;
    resources: Map<string, McpUseRegistration>;
  };
  /** The single funnel every server instance that answers HTTP passes through,
   *  including stateless mode. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getServerForSession?: (...args: any[]) => any;
  /** Hono app, used to serve discovery and the 401 challenge. */
  app?: {
    get(path: string, handler: (c: unknown) => unknown): unknown;
    use?(path: string, handler: (c: unknown, next: () => Promise<void>) => unknown): unknown;
  };
  /** mcp-use's public server config; `initialize` instructions live here. */
  config?: {instructions?: string};
};

/** Everything `withLaneAuth` accepts. All fields have defaults. */
export type LaneAuthOptions = {
  /** Which scope each tool needs, by tool name. A tool absent from the map is
   *  reachable by any CONNECTED caller — never by anyone. Default `{}`. */
  scopes?: Record<string, string>;
  /**
   * Gate EXEMPTIONS: prompt/resource names reachable WITHOUT a connection.
   *
   * The only good reason to exempt one is content that explains how to
   * authenticate — gating that is the same mistake as gating the step-up tool.
   * This is authorization; `anonymousToolList` is visibility. There is
   * deliberately no `public.tools`.
   */
  public?: {prompts?: readonly string[]; resources?: readonly string[]};

  /**
   * Where to record metered usage. Omit and no metering happens.
   *
   * Present on BOTH transports deliberately. A merchant is on the SDK or on
   * mcp-use, not both, and metering that existed on only one would look like a
   * partial rollout rather than a missing option.
   */
  meter?: GuardOptions['meter'];
  /** How many units a call of a given tool costs. Omit for one `calls` each. */
  meterUnits?: GuardOptions['meterUnits'];
  /**
   * This merchant charges for tool calls, at this cadence. See
   * {@link GuardOptions.billing}.
   *
   * Present on BOTH transports for the same reason the meter is: a merchant is
   * on the SDK or on mcp-use, and billing that reached only one of them would
   * look like a partial rollout rather than a missing option.
   */
  billing?: GuardOptions['billing'];
  /**
   * What an UNVERIFIED caller sees in `tools/list`. Default `'step-up-only'`:
   * Lane's reserved tools, with the step-up's description noting how many more
   * exist after registering.
   *
   * VISIBILITY, not authorization: every hidden tool is still gated at
   * `tools/call`, and any verified caller sees the full list.
   */
  anonymousToolList?: 'step-up-only' | 'full' | {include: readonly string[]};
  /**
   * Answer an unauthenticated `tools/call` with `401 + WWW-Authenticate`.
   * Default true.
   *
   * Only a caller the server cannot IDENTIFY gets the 401. A verified caller
   * with no connection gets a tool result: a 401 tells a client to refresh its
   * token, which cannot fix a missing consent.
   */
  challengeUnauthenticatedCalls?: boolean;
  /** RFC 9728 discovery on the server's own app. Default
   *  `{notFoundCatchAll: true}`: serve the document at every advertised path,
   *  and answer 404 on other `/.well-known/*` paths — mcp-use's SPA catch-all
   *  otherwise answers them `200 text/html`, which breaks OAuth discovery. */
  wellKnown?: false | {notFoundCatchAll?: boolean};
  /** Register the built-in PUBLIC resource explaining how to authenticate.
   *  Default true. `{append}` adds operator prose at the end. */
  authGuide?: boolean | {append?: string};
  /** Register `lane_session_info`. Default true. Exempt from the connection
   *  gate: it exists for verified callers who have not stepped up yet. */
  sessionInfoTool?: boolean;
};

/** Thrown by {@link withLaneAuth} when the mcp-use surface it needs is absent
 *  (e.g. a 2.x server), rather than degrading to a server that gates nothing. */
export class McpUseSeamMissingError extends Error {
  constructor(seam: string) {
    super(
      `withLaneAuth: this server exposes no \`${seam}\`. The adapter is built ` +
        'against mcp-use 1.34.x, whose MCPServer has both `registrations` and ' +
        '`getServerForSession`. Refusing to continue rather than gating nothing.'
    );
    this.name = 'McpUseSeamMissingError';
  }
}

const bearerOf = (header: string | undefined): string | undefined => {
  const match = /^Bearer\s+(.+)$/i.exec((header ?? '').trim());
  return match?.[1];
};

const bearerFrom = (ctx: McpUseContext | undefined): string | undefined =>
  bearerOf(ctx?.req?.header('authorization'));

const bearerFromHeaders = (headers: unknown): string | undefined => {
  const h = headers as Record<string, string | undefined> | undefined;
  return bearerOf(h?.authorization ?? h?.Authorization);
};

/**
 * Find the verified caller for one mcp-use tool call: a cached answer for this
 * request, else the `Authorization` header, verified here and cached — the
 * negative answer too.
 *
 * NOT `ctx.auth`. mcp-use populates that from its OWN OAuth; it is another
 * identity system's verdict, never a verified Lane caller. A server that has
 * already verified a Lane token itself can put the claims on the context under
 * the key this reads.
 */
export async function claimsForContext(
  auth: LaneMcpAuth,
  ctx: McpUseContext | undefined
): Promise<VerifiedClaims | null> {
  const cached = ctx?.get?.(CTX_KEY);
  if (cached !== undefined) return cached as VerifiedClaims | null;

  const outcome = await auth.authenticate(bearerFrom(ctx));
  const claims = outcome.kind === 'ok' ? outcome.claims : null;
  ctx?.set?.(CTX_KEY, claims);
  return claims;
}

type AnyHandler = (...params: unknown[]) => Promise<SdkToolResult>;
type ListHandler = (request: unknown, extra: unknown) => Promise<unknown>;
type ListedTool = {name: string; description?: string; [key: string]: unknown};

const text = (body: string, isError?: boolean): SdkToolResult => ({
  content: [{type: 'text', text: body}],
  ...(isError ? {isError: true} : {}),
});

const unauthorized = (): SdkToolResult =>
  text('unauthorized: no verified caller on this request', true);

const isGuarded = (fn: unknown): boolean =>
  typeof fn === 'function' && Boolean((fn as unknown as Record<symbol, unknown>)[GUARDED]);

const mark = <T>(fn: T): T => {
  (fn as unknown as Record<symbol, unknown>)[GUARDED] = true;
  return fn;
};

/**
 * Gate an entire mcp-use server in one call, whatever order it was built in.
 *
 *     const server = new MCPServer({...});
 *     server.tool({name: 'place_order', schema}, placeOrder);
 *     withLaneAuth(server, auth, {scopes: {place_order: 'email'}});
 *
 * Rewrites every existing registration with the guarded handler and patches the
 * registration methods for late ones, so there is no call-order dependency.
 * Also registers the step-up tool, `lane_session_info` and the auth guide;
 * appends the step-up instruction to `initialize`; serves RFC 9728 discovery;
 * answers unauthenticated `tools/call` with 401; and narrows the anonymous
 * `tools/list`. Each piece is controlled by one field of {@link LaneAuthOptions}.
 *
 * Refusals are tool RESULTS, not transport errors: a 401 thrown from inside a
 * tool call tells the client to refresh a token that may be perfectly good.
 *
 * Throws {@link McpUseSeamMissingError} when the server lacks the mcp-use
 * surface this relies on.
 */
export function withLaneAuth<S extends McpUseServerLike>(
  server: S,
  auth: LaneMcpAuth,
  options: LaneAuthOptions = {}
): S {
  const registrations = server.registrations;
  if (!registrations?.tools || !registrations.prompts || !registrations.resources) {
    throw new McpUseSeamMissingError('registrations');
  }
  if (typeof server.getServerForSession !== 'function') {
    throw new McpUseSeamMissingError('getServerForSession');
  }

  const scopes = options.scopes ?? {};
  const publicPrompts = new Set(options.public?.prompts ?? []);
  const publicResources = new Set(options.public?.resources ?? []);
  const sessionInfo = options.sessionInfoTool !== false;
  const challenge = options.challengeUnauthenticatedCalls !== false;
  const reserved = new Set([STEP_UP_TOOL, SESSION_INFO_TOOL]);

  const getClaimsSecond = ((_params: unknown, ctx: McpUseContext | undefined) =>
    claimsForContext(auth, ctx)) as never;
  const getClaimsFirst = ((ctx: McpUseContext | undefined) =>
    claimsForContext(auth, ctx)) as never;

  // METERED ON TOOLS AND NOTHING ELSE. `guard2` wraps prompts as well as tools,
  // and a prompt fetch or a resource read is not a billable tool call -- passing
  // the meter to all three would bill a cardholder for opening a description.
  // Spread rather than set: `guardTool` distinguishes an absent meter from an
  // undefined one, and an undefined one is how metering silently stops.
  const metering = {
    ...(options.meter ? {meter: options.meter} : {}),
    ...(options.meterUnits ? {meterUnits: options.meterUnits} : {}),
    ...(options.billing ? {billing: options.billing} : {}),
  };

  // mcp-use dispatches on fn.length (>=2 for tools/prompts, >=1 for resources)
  // — keep the parameters explicit, never a rest parameter. The tool's own
  // `lane/tags` annotation is the requirement (the `scopes` map overrides per
  // tool), resolved once here so it travels with the tool rather than in a map.
  // Metering rides only on TOOL calls (`guardToolCall`): prompts and resources
  // are gated identically but never billed.
  const guardToolCall = (name: string, handler: AnyHandler, annotations?: unknown): AnyHandler => {
    const guarded = guardTool(auth, name, handler, {
      requiredScopes: requiredTagsFor(name, annotations, scopes),
      ...metering,
      getClaims: getClaimsSecond,
    });
    return mark(((params: unknown, ctx: unknown) => guarded(params, ctx)) as AnyHandler);
  };
  const guard2 = (name: string, handler: AnyHandler, annotations?: unknown): AnyHandler => {
    const guarded = guardTool(auth, name, handler, {
      requiredScopes: requiredTagsFor(name, annotations, scopes),
      getClaims: getClaimsSecond,
    });
    return mark(((params: unknown, ctx: unknown) => guarded(params, ctx)) as AnyHandler);
  };
  const guard1 = (name: string, handler: AnyHandler, annotations?: unknown): AnyHandler => {
    const guarded = guardTool(auth, name, handler, {
      requiredScopes: requiredTagsFor(name, annotations, scopes),
      getClaims: getClaimsFirst,
    });
    return mark(((ctx: unknown) => guarded(ctx)) as AnyHandler);
  };
  const annotationsOf = (config: unknown): unknown =>
    (config as {annotations?: unknown} | undefined)?.annotations;

  // ── 1. Existing registrations: rewrite the replay store in place ─────────
  for (const [name, reg] of registrations.tools) {
    if (reserved.has(name) || isGuarded(reg.handler)) continue;
    reg.handler = guardToolCall(name, reg.handler as AnyHandler, annotationsOf(reg.config));
  }
  for (const [name, reg] of registrations.prompts) {
    if (publicPrompts.has(name) || isGuarded(reg.handler)) continue;
    reg.handler = guard2(name, reg.handler as AnyHandler, annotationsOf(reg.config));
  }
  for (const [, reg] of registrations.resources) {
    const name = String((reg.config as {name?: unknown})?.name ?? '');
    if (name === AUTH_GUIDE_NAME || publicResources.has(name) || isGuarded(reg.handler)) continue;
    reg.handler = guard1(name, reg.handler as AnyHandler, annotationsOf(reg.config));
  }

  // ── 2. Late registrations: patch the methods ──────────────────────────────
  const originalTool = server.tool.bind(server);
  server.tool = ((definition: McpUseToolDefinition, callback?: unknown) => {
    const cb = (callback ?? definition?.cb) as AnyHandler | undefined;
    if (typeof cb !== 'function' || reserved.has(definition?.name) || isGuarded(cb)) {
      return originalTool(definition, callback);
    }
    return originalTool(definition, guardToolCall(definition.name, cb, definition?.annotations));
  }) as S['tool'];

  const originalPrompt = server.prompt?.bind(server);
  if (originalPrompt) {
    server.prompt = ((definition: McpUseToolDefinition, callback?: unknown) => {
      const cb = (callback ?? definition?.cb) as AnyHandler | undefined;
      if (typeof cb !== 'function' || publicPrompts.has(definition?.name) || isGuarded(cb)) {
        return originalPrompt(definition, callback);
      }
      return originalPrompt(definition, guard2(definition.name, cb, definition?.annotations));
    }) as S['prompt'];
  }

  const originalResource = server.resource?.bind(server);
  if (originalResource) {
    server.resource = ((definition: McpUseToolDefinition, callback?: unknown) => {
      const cb = (callback ?? definition?.readCallback) as AnyHandler | undefined;
      const name = definition?.name;
      if (
        typeof cb !== 'function' ||
        name === AUTH_GUIDE_NAME ||
        publicResources.has(name) ||
        isGuarded(cb)
      ) {
        return originalResource(definition, callback);
      }
      return originalResource(definition, guard1(name, cb, definition?.annotations));
    }) as S['resource'];
  }

  // ── 3. Lane's own surface, through the ORIGINALS: never gated ────────────
  const step = stepUpTool(auth);
  const stepConfig = step.config as {description?: string; inputSchema?: unknown};
  originalTool(
    {
      name: step.name,
      ...(stepConfig.description ? {description: stepConfig.description} : {}),
      // The SDK's inputSchema is a raw shape; mcp-use's `schema` is a whole Zod
      // object. The raw shape would be accepted as a schema matching nothing.
      ...(stepConfig.inputSchema
        ? {schema: z.object(stepConfig.inputSchema as Record<string, z.ZodTypeAny>)}
        : {}),
    },
    mark(async (params: Record<string, unknown>, ctx: McpUseContext | undefined) => {
      const claims = await claimsForContext(auth, ctx);
      if (!claims) return unauthorized();
      return step.handler(params ?? {}, {authInfo: {extra: {laneClaims: claims}}} as never);
    }) as never
  );

  if (sessionInfo) {
    originalTool(
      {
        name: SESSION_INFO_TOOL,
        description: sessionInfoDescription(),
        schema: z.object({
          probe_scope: z
            .string()
            .max(64)
            .optional()
            .describe('Optional. Report whether this connection carries a named scope.'),
        }),
      },
      mark(async (args: SessionArgs, ctx: McpUseContext | undefined) => {
        const claims = await claimsForContext(auth, ctx);
        if (!claims) return unauthorized();
        return text(JSON.stringify(await describeSession(auth, claims, args ?? {}), null, 2));
      }) as never
    );
  }

  const guideOpt = options.authGuide ?? true;
  if (guideOpt !== false) {
    if (originalResource) {
      const body = authGuideText(auth, {
        sessionInfo,
        challenge,
        ...(typeof guideOpt === 'object' && guideOpt.append ? {append: guideOpt.append} : {}),
      });
      originalResource(
        {
          name: AUTH_GUIDE_NAME,
          uri: AUTH_GUIDE_URI,
          title: 'How to register a session',
          description:
            'What to call before using this server’s tools, and what carries ' +
            'across Lane servers. Readable without authenticating.',
          mimeType: 'text/markdown',
        },
        // One parameter — a resource callback is `(ctx)`.
        mark(async (_ctx: unknown) => ({
          contents: [{uri: AUTH_GUIDE_URI, mimeType: 'text/markdown', text: body}],
        })) as never
      );
    } else {
      console.warn(
        '[mcp-auth] withLaneAuth: this server exposes no `resource`; the auth ' +
          'guide was not registered.'
      );
    }
  }

  // ── 4. initialize instructions ────────────────────────────────────────────
  // getServerForSession reads config.instructions on every initialize, so this
  // reaches every client that connects afterwards. Idempotent.
  if (server.config) {
    server.config.instructions = auth.decorateInstructions(server.config.instructions);
  }

  // ── 5. RFC 9728 discovery, then the well-known 404 catch-all ─────────────
  if (options.wellKnown !== false) {
    mountDiscovery(server, auth, options.wellKnown?.notFoundCatchAll !== false);
  }

  // ── 6. 401 challenge, scoped to unauthenticated tools/call ───────────────
  if (challenge) {
    mountUnauthenticatedChallenge(server, auth);
  }

  // ── 7. Narrow the anonymous tools/list at the SDK dispatch layer ─────────
  const visibility = options.anonymousToolList ?? 'step-up-only';
  if (visibility !== 'full') {
    const visible = new Set<string>([STEP_UP_TOOL]);
    if (sessionInfo) visible.add(SESSION_INFO_TOOL);
    if (typeof visibility === 'object') for (const name of visibility.include) visible.add(name);

    const originalGss = server.getServerForSession.bind(server);
    let warnedSeam = false;
    const warnSeamOnce = (): void => {
      if (warnedSeam) return;
      warnedSeam = true;
      console.warn(
        '[mcp-auth] withLaneAuth: could not reach the SDK tools/list handler; ' +
          'the anonymous tool list is NOT narrowed. Visibility only — every ' +
          'tool is still gated at tools/call.'
      );
    };
    server.getServerForSession = ((...args: unknown[]) => {
      const native = originalGss(...args);
      if (!narrowAnonymousToolList(native, auth, visible)) warnSeamOnce();
      return native;
    }) as S['getServerForSession'];

    // Probe once so a missing seam is loud at wrap time, not at first traffic.
    // The probe instance is built, inspected and discarded.
    try {
      if (!narrowAnonymousToolList(originalGss(), auth, visible)) warnSeamOnce();
    } catch {
      warnSeamOnce();
    }
  }

  return server;
}

/**
 * Wrap the SDK server's own `tools/list` handler so an unverified caller sees
 * only `visible`. Wrapping, not replacing: the SDK's schema serialisation is
 * reused, and there is no response parsing anywhere.
 *
 * Fails OPEN (returns false) when the handler map is unreachable — this is
 * visibility, not authorization.
 */
function narrowAnonymousToolList(
  native: unknown,
  auth: LaneMcpAuth,
  visible: ReadonlySet<string>
): boolean {
  const handlers = (native as {server?: {_requestHandlers?: Map<string, ListHandler>}} | undefined)
    ?.server?._requestHandlers;
  const original = handlers?.get('tools/list');
  if (!handlers || typeof original !== 'function') return false;

  handlers.set('tools/list', async (request, extra) => {
    const result = await original(request, extra);
    const headers = (extra as {requestInfo?: {headers?: unknown}} | undefined)?.requestInfo
      ?.headers;
    const outcome = await auth.authenticate(bearerFromHeaders(headers));
    // Any VERIFIED caller sees everything, connected or not.
    if (outcome.kind === 'ok') return result;

    const listed = (result as {tools?: unknown} | undefined)?.tools;
    if (!Array.isArray(listed)) return result;
    const kept = (listed as ListedTool[]).filter((t) => visible.has(t.name));
    const hidden = listed.length - kept.length;
    // An anonymous crawler should see a server that says it is gated, not one
    // indistinguishable from empty — in this response only.
    const hint =
      `This server is gated: registering unlocks ${hidden} more ` +
      `tool${hidden === 1 ? '' : 's'}.`;
    const tools =
      hidden > 0
        ? kept.map((t) =>
            t.name === STEP_UP_TOOL
              ? {...t, description: t.description ? `${t.description} ${hint}` : hint}
              : t
          )
        : kept;
    return {...(result as object), tools};
  });
  return true;
}

/** Serve the RFC 9728 document at every advertised path; optionally answer 404
 *  on every other `/.well-known/*` path. */
function mountDiscovery(server: McpUseServerLike, auth: LaneMcpAuth, catchAll: boolean): void {
  const app = server.app;
  if (!app?.get) {
    console.warn(
      '[mcp-auth] withLaneAuth: this server exposes no Hono app; RFC 9728 ' +
        'discovery was not mounted. A gated server whose discovery document is ' +
        'missing cannot be authenticated against.'
    );
    return;
  }
  const {root, derived, endpoint} = auth.metadataPaths();
  const body = auth.protectedResourceDocument();
  // A Set: the endpoint form usually coincides with one of the other two.
  for (const path of new Set([root, derived, endpoint])) {
    if (!path) continue;
    app.get(path, (c: unknown) => {
      const ctx = c as {body?: (b: string, init?: unknown) => unknown};
      return ctx.body?.(body, {headers: {'content-type': 'application/json'}});
    });
  }

  // AFTER the documents — Hono matches in registration order, and registered
  // first this wildcard would shadow them. 404, because the MCP SDK's client
  // branches on that status alone; mcp-use's SPA catch-all answers 200
  // text/html, which the client parses as metadata and dies on.
  if (catchAll) {
    app.get('/.well-known/*', (c: unknown) => {
      const ctx = c as {body?: (b: string, init?: unknown) => unknown};
      return ctx.body?.('{"error":"not_found"}', {
        status: 404,
        headers: {'content-type': 'application/json'},
      });
    });
  }
}

/**
 * Answer `401 + WWW-Authenticate` to an UNAUTHENTICATED `tools/call`, and
 * nothing else. A verified caller with a missing connection stays a tool
 * result: a 401 tells an MCP client to refresh its token, which cannot fix a
 * missing consent. `initialize` and the list methods keep answering without a
 * bearer, so anonymous discovery is unchanged.
 */
function mountUnauthenticatedChallenge(server: McpUseServerLike, auth: LaneMcpAuth): void {
  const app = server.app;
  if (!app?.use) {
    console.warn(
      '[mcp-auth] withLaneAuth: this server exposes no `app.use`; the 401 ' +
        'challenge was not mounted, so clients get no protocol signal that ' +
        'authentication exists.'
    );
    return;
  }

  app.use('*', async (c: unknown, next: () => Promise<void>) => {
    const ctx = c as McpUseContext & {
      req: {method?: string; raw?: Request};
      json(body: unknown, status?: number, headers?: Record<string, string>): unknown;
    };
    if (ctx.req?.method !== 'POST') return next();

    // Cloned, never read in place — the framework still needs the body stream.
    let isToolsCall = false;
    try {
      const parsed = (await ctx.req.raw?.clone().json()) as
        | {method?: unknown}
        | Array<{method?: unknown}>
        | undefined;
      // A batch with any tools/call member needs a credential for the batch.
      const members = Array.isArray(parsed) ? parsed : [parsed];
      isToolsCall = members.some((m) => m?.method === 'tools/call');
    } catch {
      return next();
    }
    if (!isToolsCall) return next();

    const outcome = await auth.authenticate(bearerFrom(ctx));
    if (outcome.kind !== 'unauthenticated') return next();

    return ctx.json(
      {error: 'unauthorized', error_description: 'authenticate to call tools on this server'},
      401,
      {'WWW-Authenticate': outcome.challenge, 'cache-control': 'no-store'}
    );
  });
}
