/**
 * mcp-use adapter. Mirrors `./mcp-sdk` for a framework that does not look like
 * the SDK it wraps.
 *
 * WHY THIS FILE EXISTS. mcp-use sits on `@modelcontextprotocol/sdk`, and the
 * SDK adapter cannot reach it:
 *
 *   - Tools are declared through `server.tool(definition, callback)` -- one
 *     config OBJECT, name inside it -- not `registerTool(name, config, cb)`.
 *     Patching `registerTool` patches a method mcp-use does not define, so
 *     `enableLaneAuth` would appear to succeed and gate nothing.
 *   - `registerStepUpTool` would throw at boot for the same reason.
 *   - Each connected client gets its OWN native server instance, with
 *     registrations replayed onto it ("Storage for registrations that can be
 *     replayed on new server instances", mcp-server.d.ts). Patching the native
 *     server would cover the template and miss every session.
 *
 * `server.tool` is the one funnel every registration passes through before that
 * replay, so wrapping it covers every session by construction.
 *
 * WHERE THE CALLER COMES FROM. mcp-use calls a tool with `(params, ctx)`, and
 * `ctx` extends Hono's context -- so the request, and its `Authorization`
 * header, are available per call. That is better than it sounds: Hono's context
 * is per-request by construction, so there is no ambient state to leak between
 * concurrent callers and no AsyncLocalStorage to thread. Verification happens
 * once per request and is cached on the context.
 */
import {z} from 'zod';

import {guardTool, stepUpTool, type SdkToolResult} from './mcp-sdk.js';
import {STEP_UP_TOOL, type LaneMcpAuth, type VerifiedClaims} from './index.js';

/** Where the verified caller is cached on the request context. */
const CTX_KEY = 'laneClaims';

/**
 * The parts of mcp-use's context this adapter touches.
 *
 * Structural, not imported: taking a type dependency on mcp-use would make
 * every consumer of this package install it.
 */
export type McpUseContext = {
  req?: {header(name: string): string | undefined};
  get?(key: string): unknown;
  set?(key: string, value: unknown): void;
};

/** A tool definition as mcp-use takes it. `schema`, not `inputSchema`. */
export type McpUseToolDefinition = {
  name: string;
  title?: string;
  description?: string;
  schema?: unknown;
  annotations?: Record<string, unknown>;
  [key: string]: unknown;
};

export type McpUseServerLike = {
  /**
   * Deliberately loose, and `any` is the right call rather than a lazy one.
   *
   * mcp-use declares `tool` as a PROPERTY holding a generic arrow function, so
   * `strictFunctionTypes` checks it contravariantly -- a hand-written parameter
   * type has to be at least as wide as `ToolDefinition<TInput, TOutput,
   * HasOAuth>` in every position or a real `MCPServer` is not assignable. It
   * cannot be, without importing mcp-use and making every consumer of this
   * package install it. Describing the shape faithfully in
   * `McpUseToolDefinition` below and reading it there is the honest split: the
   * value is typed where this adapter uses it, and the seam it plugs into is
   * typed as wide as the framework needs.
   */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool: (...args: any[]) => unknown;
  /** Hono app, when this build exposes one. Used only to serve discovery. */
  app?: {get(path: string, handler: (c: unknown) => unknown): unknown};
};

export type EnableLaneAuthOptions = {
  /** Which scope each tool needs, by tool name. A tool absent from the map is
   *  reachable by any CONNECTED caller -- never by anyone. */
  scopes?: Record<string, string>;
};

const bearerFrom = (ctx: McpUseContext | undefined): string | undefined => {
  const header = ctx?.req?.header('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1];
};

/**
 * Find the verified caller for one mcp-use tool call.
 *
 * Two sources: a cached answer for this request, then the `Authorization`
 * header, verified here. Cached because verification is not free and a tool may
 * ask more than once -- including the negative answer, since re-verifying a
 * known-bad token per call buys nothing.
 *
 * NOT `ctx.auth`. mcp-use populates that from its OWN OAuth, and an earlier
 * version of this adapter read Lane claims out of it. That was wrong on
 * principle rather than merely mistyped: mcp-use's `AuthInfo` is a different
 * identity system's result, and treating it as a verified Lane caller would let
 * whatever that system decided stand in for Lane's own verification. A server
 * that has already verified a Lane token itself can put the claims on the
 * context under the key this reads, which is explicit and checkable.
 *
 * Exported because a server that would rather guard by hand still wants this.
 */
export async function claimsForContext(
  auth: LaneMcpAuth,
  ctx: McpUseContext | undefined
): Promise<VerifiedClaims | null> {
  const cached = ctx?.get?.(CTX_KEY);
  if (cached !== undefined) return cached as VerifiedClaims | null;

  const outcome = await auth.authenticate(bearerFrom(ctx));
  const claims = outcome.kind === 'ok' ? outcome.claims : null;
  // Cached even when null: a bad token is still an answer, and re-verifying it
  // on every tool call in the same request buys nothing.
  ctx?.set?.(CTX_KEY, claims);
  return claims;
}

/**
 * Gate an entire mcp-use server in one call.
 *
 *     enableLaneAuth(server, auth, {scopes: {place_order: 'email'}});
 *     // ...then declare tools normally. Every one is gated.
 *
 * CALL IT BEFORE YOUR TOOLS. It wraps `server.tool`, so what it guards is what
 * is declared afterwards; a tool declared earlier would be silently ungated.
 *
 * Refusals are tool RESULTS, not transport errors -- including for a bad token.
 * That is deliberate and it differs from the raw-SDK path, where the integrator
 * owns the HTTP layer and can answer 401. Here the adapter is inside the tool
 * call by the time it knows, and a 401 thrown from a tool would be read by a
 * client as "refresh your token" for a token that may be perfectly good. Serve
 * `mountDiscovery` so a client can still find out where to authenticate.
 */
export function enableLaneAuth(
  server: McpUseServerLike,
  auth: LaneMcpAuth,
  opts: EnableLaneAuthOptions = {}
): void {
  const original = server.tool.bind(server);
  const getClaims = ((_params: unknown, ctx: McpUseContext | undefined) =>
    claimsForContext(auth, ctx)) as never;

  server.tool = ((definition: McpUseToolDefinition, callback?: (...p: never[]) => unknown) => {
    // Lane's own tool is registered below, already wrapped. Guarding it here
    // would gate the way OUT of the gate.
    if (!callback || definition?.name === STEP_UP_TOOL) return original(definition, callback);
    const guarded = guardTool(
      auth,
      definition.name,
      callback as (...p: unknown[]) => Promise<SdkToolResult>,
      {...(opts.scopes ? {scopes: opts.scopes} : {}), getClaims}
    );
    // ── DECLARED WITH TWO PARAMETERS, AND THAT IS LOAD-BEARING ──────────────
    //
    // mcp-use decides whether to hand a callback its request context by reading
    // the function's ARITY. `guardTool` returns `async (...params) => ...`, and
    // a rest parameter reports `length === 0`, so handing the guard over
    // directly got it called with the arguments and nothing else -- no context,
    // no header, no caller. Every guarded tool then refused every request as
    // unauthenticated while the step-up tool, written with an explicit `(params,
    // ctx)`, worked fine. That asymmetry is what made it visible; nothing in a
    // unit test would have.
    //
    // So the wrapper is spelled out rather than spread. Do not "simplify" it to
    // `original(definition, guarded)`.
    const arity2 = (params: unknown, ctx: unknown) =>
      (guarded as (...p: unknown[]) => Promise<SdkToolResult>)(params, ctx);
    return original(definition, arity2 as never);
  }) as McpUseServerLike['tool'];

  registerStepUpTool(server, auth);
}

/**
 * Register the step-up tool, re-shaped for mcp-use.
 *
 * `stepUpTool` describes it for the SDK, where the schema key is `inputSchema`
 * and the handler is called `(args, extra)`. mcp-use wants `schema` and calls
 * `(params, ctx)`, so the definition is translated rather than passed through.
 *
 * AND THE TWO SCHEMAS ARE NOT THE SAME KIND OF THING. The SDK's `inputSchema`
 * is a RAW SHAPE -- `{task: z.string()}` -- and mcp-use's `schema` is a whole
 * Zod type, `z.object({task: z.string()})`. Handing the shape straight over
 * typechecks nowhere and, worse, would be accepted at runtime as a schema
 * matching nothing, so the step-up's `task` would be dropped and consent could
 * never record a summary. Wrapped here, once, rather than left as a trap.
 */
export function registerStepUpTool(server: McpUseServerLike, auth: LaneMcpAuth): void {
  const step = stepUpTool(auth);
  const config = step.config as {description?: string; inputSchema?: unknown};
  server.tool(
    {
      name: step.name,
      ...(config.description ? {description: config.description} : {}),
      // Raw shape -> Zod object. See the note above.
      ...(config.inputSchema
        ? {schema: z.object(config.inputSchema as Record<string, z.ZodTypeAny>)}
        : {}),
    },
    (async (params: Record<string, unknown>, ctx: McpUseContext | undefined) => {
      const claims = await claimsForContext(auth, ctx);
      if (!claims) {
        return {
          content: [{type: 'text', text: 'unauthorized: no verified caller on this request'}],
          isError: true,
        };
      }
      return step.handler(params ?? {}, {authInfo: {extra: {laneClaims: claims}}} as never);
    }) as never
  );
}

/**
 * Serve the RFC 9728 document on this server's own Hono app, at BOTH paths.
 *
 * Separate from `enableLaneAuth` because it is the one part a server might
 * already do itself, and because it needs an app this build may not expose.
 * Skipping it silently would be wrong -- a gated server whose discovery
 * document is missing is one a client cannot authenticate against -- so this
 * returns whether it mounted.
 */
export function mountDiscovery(server: McpUseServerLike, auth: LaneMcpAuth): boolean {
  const app = server.app;
  if (!app?.get) return false;
  const {root, derived} = auth.metadataPaths();
  const body = auth.protectedResourceDocument();
  for (const path of [root, derived]) {
    if (!path) continue;
    app.get(path, (c: unknown) => {
      const ctx = c as {body?: (b: string, init?: unknown) => unknown};
      return ctx.body?.(body, {headers: {'content-type': 'application/json'}});
    });
  }
  return true;
}
