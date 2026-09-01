/**
 * @fileoverview Adapter for the official MCP TypeScript SDK.
 *
 * Wraps the two things the SDK owns and the gate needs: the HTTP hop, where a
 * bearer becomes an `AuthInfo`, and the tool handler, where the gate decides.
 * Frameworks built on the SDK -- mcp-use, mcp-handler, Cloudflare Agents --
 * inherit this for free, because they inherit its request handlers.
 */
import {billingMonthKey, meterIdempotencyKey, type McpBillingCadence} from './meter.js';
import {usageContextFrom} from './usage-context.js';
import {z} from 'zod';

import {
  LANE_TAGS_ANNOTATION,
  PROMPT_MAX_CHARS,
  STEP_UP_TOOL,
  type LaneMcpAuth,
  type VerifiedClaims,
} from './index.js';

/**
 * The Lane authority tags a tool declares in its MCP `annotations`, normalized
 * to a string list. Accepts an array or a space-separated string; anything else
 * is no tags. Shared by both adapters so the gate reads the requirement from
 * the SAME place a tool author wrote it.
 */
export function laneTagsFrom(annotations: unknown): string[] {
  const raw = (annotations as Record<string, unknown> | undefined)?.[LANE_TAGS_ANNOTATION];
  if (Array.isArray(raw)) return raw.filter((t): t is string => typeof t === 'string' && t !== '');
  if (typeof raw === 'string') return raw.split(/\s+/).filter(Boolean);
  return [];
}

/**
 * The tags THIS tool requires: the operator's per-tool `scopes` override wins
 * when present (a deployment can gate a tool its author did not tag), otherwise
 * the tool's own `lane/tags` annotation. Empty means "any connected caller".
 */
export function requiredTagsFor(
  name: string,
  annotations: unknown,
  scopes: Record<string, string> | undefined
): readonly string[] {
  const override = scopes?.[name];
  if (override) return [override];
  return laneTagsFrom(annotations);
}

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
 * but `extra` is last either way, so nothing a caller sends can shadow it. A
 * shape-based scan would instead be won by a tool argument named `signal`, and
 * refuse every call as unauthorized. The structural check remains only as a
 * fallback for a handler invoked some other way.
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
  /**
   * Where to record metered usage, when the merchant is billing for tool calls.
   *
   * OPTIONAL, AND NEVER A GATE. A merchant who does not meter passes nothing and
   * this code path does not run. A merchant who does meter cannot have a tool
   * call fail because metering failed: the record happens after the handler
   * returns and its outcome is not consulted.
   */
  meter?: {
    record: (event: {
      laneIntentId?: string;
      mandateId?: string;
      /** Set only when `billing` is configured. See {@link GuardOptions.billing}. */
      periodKey?: string;
      productId: string;
      buyerId?: string;
      quantity: number;
      unit: string;
      idempotencyKey: string;
    }) => void;
  };
  /**
   * How many billable calls one invocation counts as. Absent means one.
   *
   * LANE PRICES PER TOOL CALL, so `unit` is `calls` and a merchant's own cost
   * for a call -- model tokens, a third-party API, compute -- is wrapped into
   * their per-call price. This hook exists for the case where one invocation
   * genuinely is several billable calls, such as a batch tool that fans out.
   *
   * It takes the RESULT because that count is not always knowable in advance.
   */
  meterUnits?: (
    toolName: string,
    result: SdkToolResult,
  ) => {quantity: number; unit: string} | null;
  /**
   * This merchant charges for tool calls, at this cadence.
   *
   * FROM CONFIG, NOT FROM A LOOKUP. The merchant's own server knows its cadence
   * when it starts up, so it is stated once here. Reading merchant config per
   * call would put a network round trip in front of every tool call, which is
   * the same cost the offline token verify exists to avoid.
   *
   * Set it and every metered event carries a `periodKey`, which is what puts the
   * usage in the billing namespace: the access token's `jti` for `per_session`,
   * the calendar month for `monthly`. Leave it unset and metering behaves exactly
   * as before -- the events are mandate-attributed or unattributed.
   *
   * STILL NEVER A GATE. This changes what a metered event says, not whether a
   * tool call proceeds.
   */
  billing?: {
    cadence: McpBillingCadence;
    /** Clock override, milliseconds since epoch. Test seam; the monthly period
     *  key is the only thing that reads it. */
    now?: () => number;
  };
  /** Which scope a tool needs, by tool name. Absent means "a connection is
   *  enough". */
  scopes?: Record<string, string>;
  /**
   * The authority tags THIS tool requires, resolved once by the caller (an
   * adapter reads them from `annotations['lane/tags']`). Takes precedence over
   * the `scopes` map above, and the caller holds the connection only if it
   * carries EVERY tag listed. Empty or absent means "any connected caller".
   */
  requiredScopes?: readonly string[];
  /**
   * Where to find the verified caller, when it does not arrive on the SDK's
   * `extra`.
   *
   * The default reads `extra.authInfo`, which is right for a server on
   * `@modelcontextprotocol/sdk` and wrong for every framework that wraps it
   * without forwarding that argument. `mcp-use` calls a tool handler with the
   * arguments ONLY -- no `extra`, no `authInfo` -- so a guard with no seam here
   * sees no caller and refuses everything. A server that instead carries the
   * credential in an `AsyncLocalStorage`, or any other request-scoped store,
   * hooks it in here rather than reimplementing the gate.
   *
   * Receives the handler's own arguments, so a resolver can read a framework's
   * context object out of them or ignore them entirely and read a request-scoped
   * store. Returning `null` is "not authenticated" and is refused exactly as a
   * missing `authInfo` is.
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

    // Every required tag must be held. `requiredScopes` (annotation-derived, and
    // already override-resolved by the adapter) wins; the `scopes` map is the
    // back-compatible single-scope fallback for a direct caller of guardTool.
    const need =
      opts.requiredScopes && opts.requiredScopes.length > 0
        ? opts.requiredScopes
        : opts.scopes?.[toolName]
          ? [opts.scopes[toolName]]
          : [];
    for (const scope of need) {
      if (!(await auth.hasScope(claims, scope))) {
        return text(`insufficient_scope: this connection lacks \`${scope}\``, true);
      }
    }

    const result = await handler(...params);

    // METERED AFTER A SUCCESSFUL CALL, and only then.
    //
    // A tool that threw did work and produced nothing, and Lane's own failure
    // rule is that a failed call releases rather than captures -- so billing for
    // it would contradict the receipt. A thrown handler propagates from the line
    // above and never reaches here, which is the behaviour we want.
    //
    // `isError` results are also skipped: the SDK uses them for a refused or
    // failed call, which is the same case wearing a different shape.
    if (opts.meter && result?.isError !== true) {
      recordUsage(opts, toolName, params, claims, result);
    }
    return result;
  };
}

/**
 * Hand one unit to the meter.
 *
 * SWALLOWS EVERYTHING. This runs after a tool has already succeeded and its
 * result is already decided. An exception here would turn a successful call into
 * a failed one over a billing detail, which is exactly the coupling metering
 * must not introduce.
 */
function recordUsage(
  opts: GuardOptions,
  toolName: string,
  params: unknown[],
  claims: VerifiedClaims,
  result: SdkToolResult
): void {
  try {
    const units = opts.meterUnits?.(toolName, result) ?? {quantity: 1, unit: 'calls'};
    if (!units || units.quantity <= 0) return;

    // The agent's context, if the harness sent it. Absent for a non-Lane agent,
    // and absence is a valid state: the server records the usage as
    // unattributed.
    const ctx = usageContextFrom(findExtra(params)) ?? usageContextFrom(params[params.length - 1]);

    // ── WHICH NAMESPACE THIS UNIT LANDS IN ────────────────────────────────
    //
    // One call produces one event, and the ledger keeps billing, mandate and
    // unattributed usage in separate partitions -- so exactly one address is
    // chosen here. BILLING WINS when the merchant configured it: that is their
    // own product decision, made at config time, while the mandate ids arrive
    // from the agent and may be absent on any given call. A merchant who bills
    // per call bills whether or not the agent passed an intent through.
    //
    // The intent and mandate are then deliberately omitted. Sending both
    // addresses would leave the server choosing, and a unit counted in two
    // partitions is a unit charged twice.
    const address = opts.billing
      ? {
          periodKey:
            opts.billing.cadence === 'per_session'
              ? // THE SESSION IS THE ACCESS TOKEN'S LIFE. `jti` is already
                // verified and already scopes a connection to one credential at
                // one merchant, so nothing new is minted for it. A run id is
                // never used: it is `trc_*`-class observability.
                claims.jti
              : billingMonthKey(opts.billing.now?.()),
        }
      : ctx
        ? {laneIntentId: ctx.laneIntentId, mandateId: ctx.mandateId}
        : {};

    opts.meter?.record({
      ...address,
      productId: toolName,
      // THE TOKEN'S PAIRWISE SUBJECT, never anything the agent supplied. It is
      // HMAC(userId || audience), so it differs at every merchant and cannot
      // correlate a person across servers.
      buyerId: claims.sub,
      quantity: units.quantity,
      unit: units.unit,
      idempotencyKey: meterIdempotencyKey(toolName, ctx?.laneIntentId ?? ''),
    });
  } catch {
    // Deliberately silent. See the doc comment.
  }
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
  /**
   * The Lane authority tags this tool needs. Written into the tool's
   * `annotations['lane/tags']` so they travel in `tools/list`, and enforced by
   * the gate (the caller must hold EVERY one). Prefer this over `scope`: it is
   * the co-located form the index reads at onboarding. `scope`, if also given,
   * takes precedence for enforcement.
   */
  tags?: readonly string[];
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
  const {name, description, inputSchema, scope, tags, annotations} = spec;
  // Tags declared on the spec are ALSO written into annotations, so they reach
  // `tools/list` exactly as if the author had put them there by hand.
  const declaredTags = tags && tags.length ? [...tags] : laneTagsFrom(annotations);
  const mergedAnnotations =
    declaredTags.length > 0
      ? {...(annotations ?? {}), [LANE_TAGS_ANNOTATION]: declaredTags}
      : annotations;
  // `scope` still wins for enforcement, per its doc; otherwise the tags do.
  const requiredScopes = scope ? [scope] : declaredTags;
  const guarded = guardTool(auth, name, handler, {requiredScopes});
  server.registerTool(
    name,
    {description, inputSchema, ...(mergedAnnotations ? {annotations: mergedAnnotations} : {})},
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
  /**
   * Where to record metered usage. Omit and no metering happens.
   *
   * Passed straight through to every guarded tool, so a merchant opts in once
   * rather than per tool. Metering can never fail a call -- see `recordUsage`.
   */
  meter?: GuardOptions['meter'];
  /** How many units a call of a given tool costs. Omit for one `calls` each. */
  meterUnits?: GuardOptions['meterUnits'];
  /** This merchant charges for tool calls, at this cadence. See
   *  {@link GuardOptions.billing}. */
  billing?: GuardOptions['billing'];
};

/**
 * Guard options built from the whole-server options.
 *
 * ONE PLACE, because `enableLaneAuth` calls `guardTool` from three call sites
 * (registerTool, tool, and the legacy shim). Passing the meter at two of them
 * and forgetting the third is the shape of bug that shows up as "metering works
 * for some of my tools".
 */
function guardOptionsFrom(opts: EnableLaneAuthOptions): GuardOptions {
  return {
    ...(opts.scopes ? {scopes: opts.scopes} : {}),
    ...(opts.meter ? {meter: opts.meter} : {}),
    ...(opts.meterUnits ? {meterUnits: opts.meterUnits} : {}),
    ...(opts.billing ? {billing: opts.billing} : {}),
  };
}

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
    // The tool's own `lane/tags` annotation is the requirement; the `scopes`
    // map, if the deployment passed one, overrides per tool. Metering options
    // ride along unchanged.
    const guarded = guardTool(auth, name, cb as (...p: unknown[]) => Promise<SdkToolResult>, {
      ...guardOptionsFrom(opts),
      requiredScopes: requiredTagsFor(
        name,
        (config as {annotations?: unknown})?.annotations,
        opts.scopes
      ),
    });
    return original(name, config, guarded);
  }) as McpServerLike['registerTool'];

  // `tool()` is deprecated but live, and it does NOT delegate to
  // `registerTool` -- it writes to the server's registry itself. Patching only
  // the modern method would leave every tool registered the old way completely
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
        guardOptionsFrom(opts)
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
