/**
 * @fileoverview Adapter for the official MCP TypeScript SDK.
 *
 * Wraps the two things the SDK owns and the gate needs: the HTTP hop, where a
 * bearer becomes an `AuthInfo`, and the tool handler, where the gate decides.
 * Frameworks built on the SDK -- mcp-use, mcp-handler, Cloudflare Agents --
 * inherit this for free, because they inherit its request handlers.
 */
import {z} from 'zod';

import {
  PROMPT_MAX_CHARS,
  STEP_UP_TOOL,
  type LaneMcpAuth,
  type VerifiedClaims,
} from './index.js';

/** The SDK's `AuthInfo`, structurally. Declared rather than imported so this
 *  module adds no dependency on the SDK. */
export type SdkAuthInfo = {
  token: string;
  clientId: string;
  scopes: string[];
  expiresAt?: number;
  extra?: Record<string, unknown>;
};

/** What the SDK hands a tool handler. Only the field this adapter reads. */
export type SdkExtra = {authInfo?: SdkAuthInfo};

/** A tool result, as the SDK expects one. */
export type SdkToolResult = {
  content: {type: 'text'; text: string}[];
  isError?: boolean;
};

const KEY = 'laneClaims';

/**
 * Turn a verified bearer into the SDK's `AuthInfo`.
 *
 * `scopes` is deliberately the TOKEN's, which is empty before the step-up: it
 * is what the SDK's own scope checks read, and reporting the connection's
 * authority here would make those checks pass on a grant the SDK knows nothing
 * about. The real authority travels in `extra`.
 */
export function toAuthInfo(claims: VerifiedClaims): SdkAuthInfo {
  return {
    token: claims.token,
    clientId: claims.clientId,
    scopes: claims.scopes,
    expiresAt: claims.exp,
    extra: {[KEY]: claims},
  };
}

/** Recover the claims this adapter attached, or `null`. */
export function claimsFrom(extra: SdkExtra | undefined): VerifiedClaims | null {
  const carried = extra?.authInfo?.extra?.[KEY];
  return carried ? (carried as VerifiedClaims) : null;
}

/**
 * The SDK's `extra`, which is always the LAST argument.
 *
 * Found by POSITION, not by shape. The SDK changes arity -- a tool with an
 * input schema is called `(args, extra)`, one without is called `(extra)` --
 * but `extra` is last either way, so nothing a caller sends can shadow it.
 * Scanning by shape instead meant a tool declaring an argument named `signal`
 * had `args` win the scan, so every call was refused as unauthorized. The
 * structural check remains only as a fallback for a handler invoked some other
 * way.
 */
function findExtra(params: unknown[]): SdkExtra | undefined {
  const last = params[params.length - 1];
  if (last && typeof last === 'object' && 'authInfo' in last) return last as SdkExtra;
  for (const p of params) {
    if (p && typeof p === 'object' && ('authInfo' in p || 'requestId' in p || 'signal' in p)) {
      return p as SdkExtra;
    }
  }
  return undefined;
}

const text = (body: string, isError?: boolean): SdkToolResult => ({
  content: [{type: 'text', text: body}],
  ...(isError ? {isError: true} : {}),
});

/** Options for {@link guardTool}. */
export type GuardOptions = {
  /** Which scope a tool needs, by tool name. Absent means "a connection is
   *  enough". */
  scopes?: Record<string, string>;
  /**
   * Where to find the verified caller, when it does not arrive on the SDK's
   * `extra`.
   *
   * The default reads `extra.authInfo`, which is right for a server on
   * `@modelcontextprotocol/sdk` and wrong for every framework that wraps it
   * without forwarding that argument. `mcp-use` calls a tool handler with the
   * arguments ONLY -- no `extra`, no `authInfo` -- so a guard with no seam here
   * sees no caller and refuses everything. `apps/shell-mcp` in the Lane
   * monorepo hit exactly that and carries the credential in an
   * `AsyncLocalStorage` instead; this is the hook that lets an adapter do the
   * same without reimplementing the gate.
   *
   * Receives the handler's own arguments, so a resolver can read a framework's
   * context object out of them or ignore them entirely and read a request-scoped
   * store. Returning `null` is "not authenticated" and is refused exactly as a
   * missing `authInfo` is.
   *
   * The Python package has had this since it shipped (`get_claims` on
   * `guarded`); TypeScript not having it was an oversight, not a decision.
   */
  getClaims?: (...params: never[]) => VerifiedClaims | null | Promise<VerifiedClaims | null>;
};

/**
 * Wrap a tool handler in both layers of the gate.
 *
 * One wrapper for both checks, because they must not be independently
 * rememberable: `authorizeCall` asks whether a connection exists, `hasScope`
 * asks whether it carries this authority, and wiring only the first gives a
 * server where every tool is reachable by anyone who registered.
 *
 * Refusals are tool RESULTS, never thrown: an MCP client reads a transport
 * error as "my token is stale" and will refresh a token that was never the
 * problem.
 */
export function guardTool<A extends unknown[]>(
  auth: LaneMcpAuth,
  toolName: string,
  // Generic over the parameters so a caller's own `(args, extra) => ...` keeps
  // its types; pinning a shape here would force a cast at every call site.
  handler: (...params: A) => Promise<SdkToolResult>,
  opts: GuardOptions = {}
): (...params: A) => Promise<SdkToolResult> {
  const resolve = opts.getClaims as
    | ((...p: A) => VerifiedClaims | null | Promise<VerifiedClaims | null>)
    | undefined;
  return async (...params: A): Promise<SdkToolResult> => {
    // Awaited, so a resolver may VERIFY rather than just look up. mcp-use hands
    // a tool its Hono request context and nothing else, so the only way to find
    // the caller there is to read the header and verify it -- which is async.
    const claims = resolve ? await resolve(...params) : claimsFrom(findExtra(params));
    // No claims means the transport did not authenticate this request.
    if (!claims) return text('unauthorized: no verified caller on this request', true);

    const verdict = await auth.authorizeCall(toolName, claims);
    if (verdict.kind !== 'allow') return text(verdict.message, true);

    const need = opts.scopes?.[toolName];
    if (need && !(await auth.hasScope(claims, need))) {
      return text(`insufficient_scope: this connection lacks \`${need}\``, true);
    }

    return handler(...params);
  };
}

/**
 * The step-up tool, as a first-class SDK tool.
 *
 * Registered rather than injected into a `tools/list` response: inside the SDK
 * the server owns that response, and rewriting it would miss pagination.
 */
export function stepUpTool(auth: LaneMcpAuth) {
  return {
    name: STEP_UP_TOOL,
    config: {
      description:
        'Complete authentication for this session. Call this first; every other ' +
        'tool is refused until you do. Optionally pass a short summary of your task.',
      /**
       * A zod raw shape, because `registerTool` accepts nothing else. Declaring
       * one is not optional: a tool registered without a schema has its
       * arguments DROPPED by the SDK, so `task` would never arrive.
       *
       * The cap duplicates `PROMPT_MAX_CHARS` on purpose -- this bound is a hint
       * to the model, and the library caps and sanitises the value again on the
       * way in.
       */
      inputSchema: {
        task: z
          .string()
          .max(PROMPT_MAX_CHARS)
          .optional()
          .describe('A brief summary of what you are trying to do.'),
      },
    },
    handler: async (...params: unknown[]): Promise<SdkToolResult> => {
      const claims = claimsFrom(findExtra(params));
      if (!claims) return text('unauthorized: no verified caller on this request', true);
      const args = (params[0] ?? {}) as Record<string, unknown>;
      return text(JSON.stringify(await auth.completeStepUp(args, claims), null, 2));
    },
  };
}

/** The one method this adapter calls, described structurally so importing it
 *  costs no dependency. */
export type SdkServerLike = {
  registerTool(
    name: string,
    config: Record<string, unknown>,
    cb: (...params: never[]) => unknown
  ): unknown;
};

/** A zod raw shape: `{}` for a tool that takes no arguments. */
export type ZodRawShape = Record<string, unknown>;

/** One tool, declared with its schema and required scope together. */
export type GuardedToolSpec = {
  name: string;
  description: string;
  /**
   * Required, and `{}` is the explicit answer for a tool with no arguments.
   *
   * Omitting it is what the SDK reads as "no inputs", which silently drops
   * whatever the caller sent and shifts the handler's arity.
   */
  inputSchema: ZodRawShape;
  /**
   * The scope this tool needs.
   *
   * ABSENT MEANS "ANY CONNECTED CALLER", never "anyone". Registration is the
   * floor: every tool on this server requires a completed step-up, and omitting
   * a scope only removes the SECOND check.
   */
  scope?: string;
  annotations?: Record<string, unknown>;
};

/**
 * Register a tool behind the gate.
 *
 * The only way to register a tool with this adapter: there is no variant that
 * skips the connection check. Omitting `scope` drops the second check, not the
 * first.
 */
export function registerGuardedTool<A extends unknown[]>(
  server: SdkServerLike,
  auth: LaneMcpAuth,
  spec: GuardedToolSpec,
  handler: (...params: A) => Promise<SdkToolResult>
): void {
  const {name, description, inputSchema, scope, annotations} = spec;
  const guarded = guardTool(auth, name, handler, scope ? {scopes: {[name]: scope}} : {});
  server.registerTool(
    name,
    {description, inputSchema, ...(annotations ? {annotations} : {})},
    guarded as unknown as (...params: never[]) => unknown
  );
}

/**
 * Register the step-up tool.
 *
 * Call it once, before or after your own tools. Without it a caller has no way
 * out of the gate, which is a server where every tool is permanently refused.
 */
export function registerStepUpTool(server: SdkServerLike, auth: LaneMcpAuth): void {
  const step = stepUpTool(auth);
  server.registerTool(
    step.name,
    step.config,
    step.handler as unknown as (...params: never[]) => unknown
  );
}

/** What `enableLaneAuth` patches. Structural, so this module still imports
 *  nothing from the SDK. */
export type McpServerLike = SdkServerLike & {
  registerTool(name: string, config: Record<string, unknown>, cb: unknown): unknown;
  /** The pre-`registerTool` API. Still live, still writes straight to the
   *  server's registry, so it has to be patched too. */
  tool?(name: string, ...rest: unknown[]): unknown;
};

/** Options for {@link enableLaneAuth}. */
export type EnableLaneAuthOptions = {
  /** Which scope each tool needs, by tool name. A tool absent from the map is
   *  reachable by any CONNECTED caller -- never by anyone. */
  scopes?: Record<string, string>;
};

/**
 * Gate an entire server in one call.
 *
 * ```ts
 * enableLaneAuth(mcp, auth, {scopes: {place_order: 'email'}});
 * // ...then register tools normally. Every one is gated.
 * ```
 *
 * CALL IT BEFORE YOUR TOOLS, the way `app.use(cors())` goes above the routes.
 * It patches this instance's registration methods, so what it guards is what is
 * registered AFTERWARDS; a tool registered before would be silently ungated.
 * If any tools already exist it throws and names them.
 */
export function enableLaneAuth(
  server: McpServerLike,
  auth: LaneMcpAuth,
  opts: EnableLaneAuthOptions = {}
): void {
  const existing = existingToolNames(server);
  if (existing.length > 0) {
    throw new Error(
      'enableLaneAuth must be called BEFORE registering tools; these are already ' +
        `registered and would be left ungated: ${existing.join(', ')}. ` +
        'Move the call above them, as you would `app.use(cors())`.'
    );
  }

  const original = server.registerTool.bind(server);
  server.registerTool = ((name: string, config: Record<string, unknown>, cb: unknown) => {
    // The step-up tool is Lane's own and is registered below, already wrapped.
    // Guarding it here would gate the way OUT of the gate.
    if (name === STEP_UP_TOOL) return original(name, config, cb);
    const guarded = guardTool(
      auth,
      name,
      cb as (...p: unknown[]) => Promise<SdkToolResult>,
      opts.scopes ? {scopes: opts.scopes} : {}
    );
    return original(name, config, guarded);
  }) as McpServerLike['registerTool'];

  // `tool()` is deprecated but live, and it does NOT delegate to
  // `registerTool` -- it writes to the server's registry itself. Patching only
  // the modern method left every tool registered the old way completely
  // ungated, which is the exact failure this function exists to prevent.
  const originalTool = server.tool?.bind(server);
  if (originalTool) {
    server.tool = ((name: string, ...rest: unknown[]) => {
      // The callback is always last, whichever overload was used.
      const cb = rest[rest.length - 1];
      if (name === STEP_UP_TOOL || typeof cb !== 'function') {
        return originalTool(name, ...rest);
      }
      const guarded = guardTool(
        auth,
        name,
        cb as (...p: unknown[]) => Promise<SdkToolResult>,
        opts.scopes ? {scopes: opts.scopes} : {}
      );
      return originalTool(name, ...rest.slice(0, -1), guarded);
    }) as McpServerLike['tool'];
  }

  registerStepUpTool(server, auth);
}

/**
 * Tools already on the server, or `[]` if this build does not expose them.
 *
 * Reads a private field deliberately: a wrong answer here costs a thrown error
 * at boot, where the alternative is letting a late `enableLaneAuth` call
 * silently leave earlier tools ungated. If a future SDK renames the field this
 * degrades to "assume none" and the documented ordering is what holds.
 */
function existingToolNames(server: McpServerLike): string[] {
  try {
    const registry = (server as unknown as {_registeredTools?: Record<string, unknown>})
      ._registeredTools;
    if (!registry || typeof registry !== 'object') return [];
    return Object.keys(registry).filter((n) => n !== STEP_UP_TOOL);
  } catch {
    return [];
  }
}
