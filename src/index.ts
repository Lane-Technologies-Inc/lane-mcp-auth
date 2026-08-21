/**
 * @fileoverview `@getonlane/mcp-auth` — one call turns an MCP server into an OAuth
 * resource server fronted by Lane, with the step-up gate and the reserved tool
 * already wired.
 */
import {createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey} from 'jose';

import {
  PERSONALIZATION_SCOPE,
  PROMPT_MAX_CHARS,
  STEP_UP_TOOL,
  type ConnectionRecord,
  type EnforcementMode,
  type GateEvent,
  type Identity,
  type LaneMcpAuthConfig,
  type Session,
  type VerifiedClaims,
} from './types.js';

export * from './types.js';
export {createTokenExchanger, type TokenExchangerConfig} from './exchanger.js';

const DEFAULT_ISSUER = 'https://auth.getonlane.com/auth/mcp';

/** Lane's canonical resource: the audience a step-down token carries when the
 *  client did not name a `resource`. See `LaneMcpAuthConfig.canonicalResource`. */
const DEFAULT_CANONICAL_RESOURCE = 'https://app-mcp.getonlane.com';
/** RFC 9068 §2.1 — an access token says `at+jwt`; an id_token says `JWT`.
 *  Checking it is what stops an id_token being replayed as an access token. */
const ACCESS_TOKEN_TYP = 'at+jwt';

/** Both paths a client may look for the metadata at. RFC 9728 derives the path
 *  from the RESOURCE path, but plenty of clients (and Lane's own prober) read
 *  the root, so serve both. */
export function metadataPaths(resource: string): {root: string; derived: string | null} {
  const url = new URL(resource);
  const path = url.pathname.replace(/\/+$/, '');
  return {
    root: '/.well-known/oauth-protected-resource',
    derived: path === '' ? null : `/.well-known/oauth-protected-resource${path}`,
  };
}

/** The sentence appended to `initialize` instructions. */
export function stepUpInstruction(): string {
  return (
    `Authentication is not complete until you call \`${STEP_UP_TOOL}\` on this server. ` +
    'Other tools are unavailable until you do. Call it once, with a one-line summary ' +
    'of what you are trying to accomplish, and then retry what you were doing.'
  );
}

/** What a gated tool call answers with. Instructive on purpose: this text IS the
 *  steering mechanism, and it is the only one that works on every client. */
export function stepUpRequiredMessage(): string {
  return (
    `Login incomplete — call \`${STEP_UP_TOOL}\` with a brief summary of your task, ` +
    'then retry this call.'
  );
}

/** A tool as it appears in `tools/list`. */
export type ToolDefinition = {name: string; description: string; inputSchema: unknown};

/** The reserved tool, as it appears in `tools/list`.
 *
 *  Keep the schema minimal: every field added here is context budget taken from
 *  the operator's own tools on every request. */
export function stepUpToolDefinition(): ToolDefinition {
  return {
    name: STEP_UP_TOOL,
    description:
      'Complete authentication for this server. Call this once before using other ' +
      'tools. Optionally include a one-line summary of your task so results can be ' +
      'tailored to it; the call works with no arguments at all.',
    inputSchema: {
      type: 'object',
      properties: {
        task: {
          type: 'string',
          description:
            "One line on what you are trying to accomplish, in the user's terms. Optional.",
          maxLength: PROMPT_MAX_CHARS,
        },
      },
      required: [],
      additionalProperties: false,
    },
  };
}

/** The result of verifying a bearer. */
export type AuthOutcome =
  /** The credential is good. Whether it may CALL anything is a separate question. */
  | {kind: 'ok'; claims: VerifiedClaims}
  /** HTTP 401 + challenge. Token problems only — never a connection problem. */
  | {kind: 'unauthenticated'; challenge: string};

/** The gate's decision about one tool call. */
export type CallVerdict =
  | {kind: 'allow'}
  /** A tool-result error, at HTTP 200. Never a 401. */
  | {kind: 'step-up-required'; message: string}
  /** `log-only`: the call proceeds, and the operator is told what would have
   *  happened. */
  | {kind: 'allow'; wouldHaveBlocked: true};

/** The resource server and gate returned by {@link createLaneMcpAuth}. */
export type LaneMcpAuth = {
  /** RFC 9728 document, serialized. */
  protectedResourceDocument(): string;
  metadataPaths(): {root: string; derived: string | null};
  /** The `WWW-Authenticate` value for a 401. */
  challenge(): string;
  /** Verify a bearer. TOKEN problems only. */
  authenticate(bearer: string | undefined): Promise<AuthOutcome>;
  /** May this verified caller invoke `toolName`? CONNECTION problems only. */
  authorizeCall(toolName: string, claims: VerifiedClaims): Promise<CallVerdict>;
  /** Handle the reserved tool. Returns the payload for a tool result. */
  completeStepUp(
    args: {task?: unknown},
    claims: VerifiedClaims
  ): Promise<{ok: true; personalized: boolean; scopes: string[]}>;
  /** The authority this caller actually has. Resolved from the connection --
   *  `claims.scopes` is empty before the step-up and stale after it. */
  effectiveScopes(claims: VerifiedClaims): Promise<string[]>;
  /** Convenience over `effectiveScopes` for a single check. */
  hasScope(claims: VerifiedClaims, scope: string): Promise<boolean>;
  /** Who is calling. Available as soon as the token verifies -- before the
   *  step-up, and without touching the connection store. */
  identity(claims: VerifiedClaims): Identity;
  /** The caller's connection: scopes, task summary, when they connected.
   *  `null` before the step-up. */
  session(claims: VerifiedClaims): Promise<Session | null>;
  /** `initialize` — append the step-up sentence to whatever the operator wrote. */
  decorateInstructions(instructions: string | undefined): string;
  /** `tools/list` — merge the reserved tool onto the FINAL page only. */
  mergeTools(tools: ToolDefinition[], opts?: {nextCursor?: string}): ToolDefinition[];
  /** True when this is the reserved name — handle locally, never forward. */
  isStepUpTool(name: string): boolean;
};

function scopesOf(payload: Record<string, unknown>): string[] {
  const raw = payload.scope ?? payload.scp;
  if (typeof raw === 'string') return raw.split(' ').filter(Boolean);
  if (Array.isArray(raw)) return raw.filter((s): s is string => typeof s === 'string');
  return [];
}

/** Build the resource server and gate for one MCP server. */
export function createLaneMcpAuth(config: LaneMcpAuthConfig): LaneMcpAuth {
  const issuer = config.issuer ?? DEFAULT_ISSUER;
  const {resource, connections, exchanger} = config;
  const canonicalResource = config.canonicalResource ?? DEFAULT_CANONICAL_RESOURCE;
  const enforcement: EnforcementMode = config.enforcement ?? 'gate-all';
  const onGateEvent = config.onGateEvent;
  const now = config.now ?? (() => Date.now());
  const paths = metadataPaths(resource);
  const origin = new URL(resource).origin;
  const metadataUrl = `${origin}${paths.derived ?? paths.root}`;
  // One issuer in the steady state; more only while an operator moves their
  // authorization server behind Lane.
  const accepted = [issuer, ...(config.additionalIssuers ?? [])];

  // Lazily built: `createRemoteJWKSet` throws synchronously on a malformed URL,
  // and at module scope that takes the process down on a bad config value.
  const keySets = new Map<string, JWTVerifyGetKey>();
  const keysFor = (iss: string): JWTVerifyGetKey => {
    let set = keySets.get(iss);
    if (!set) {
      set = createRemoteJWKSet(new URL(`${iss}/jwks`));
      keySets.set(iss, set);
    }
    return set;
  };

  const verify =
    config.verifyToken ??
    (async (token: string): Promise<VerifiedClaims> => {
      let lastErr: unknown;
      for (const iss of accepted) {
        try {
          const {payload, protectedHeader} = await jwtVerify(token, keysFor(iss), {
            issuer: iss,
            // Either audience: `jose` reads a list as any-of, and both are
            // accepted as a subject token at the exchange. They are not equally
            // bound -- see the README.
            audience: [canonicalResource, resource],
          });
          if (protectedHeader.typ !== ACCESS_TOKEN_TYP) {
            throw new Error(`expected typ ${ACCESS_TOKEN_TYP}`);
          }
          const sub = typeof payload.sub === 'string' ? payload.sub : '';
          const jti = typeof payload.jti === 'string' ? payload.jti : '';
          // Without `jti` a connection could only be keyed on the user, so one
          // step-up would silently cover every credential they ever hold.
          if (!sub || !jti) throw new Error('token is missing sub or jti');
          return {
            sub,
            jti,
            clientId: typeof payload.client_id === 'string' ? payload.client_id : '',
            token,
            scopes: scopesOf(payload as Record<string, unknown>),
            exp: typeof payload.exp === 'number' ? payload.exp : 0,
            ...(typeof payload.auth_time === 'number'
              ? {authenticatedAt: payload.auth_time}
              : {}),
            iss,
          };
        } catch (err) {
          lastErr = err;
        }
      }
      throw lastErr ?? new Error('token verification failed');
    });

  /**
   * A connection that is still good, or `null`.
   *
   * Expiry is enforced HERE so that every reader gets it -- the gate and
   * `effectiveScopes` alike. A stored expiry that nothing enforces is worse
   * than none, because the shape of the code says it is enforced.
   *
   * `expiresAt` is in seconds, matching the exchange's `expires_in` and every
   * `exp` claim; `now()` is milliseconds.
   */
  const liveRecord = (record: ConnectionRecord | null): ConnectionRecord | null => {
    if (!record) return null;
    if (record.expiresAt !== undefined && Math.floor(now() / 1000) >= record.expiresAt) {
      return null;
    }
    return record;
  };

  const gatedByEnforcement = (toolName: string): boolean => {
    if (enforcement === 'log-only') return false;
    if (enforcement === 'gate-all') return true;
    // The list names the tools that STILL require a connection, so a tool
    // absent from it is UNGATED -- including one added later. That is
    // fail-open, and deliberate: this mode is a rollout stage, not a steady
    // state. Under `gate-all` every tool requires a connection.
    return enforcement.allow.includes(toolName);
  };

  return {
    protectedResourceDocument: () =>
      `${JSON.stringify(
        {
          resource,
          // Always the primary issuer, even mid-migration: the document is what
          // walks clients forward onto it.
          authorization_servers: [issuer],
          bearer_methods_supported: ['header'],
        },
        null,
        2
      )}\n`,

    metadataPaths: () => paths,

    // RFC 9728 §5.1 — tells a client that has never seen this server where to
    // authenticate, instead of leaving it to guess a well-known path.
    challenge: () => `Bearer resource_metadata="${metadataUrl}"`,

    async authenticate(bearer) {
      const challenge = `Bearer resource_metadata="${metadataUrl}"`;
      if (!bearer) return {kind: 'unauthenticated', challenge};
      try {
        return {kind: 'ok', claims: await verify(bearer)};
      } catch {
        // Every failure collapses to one answer: naming which check failed
        // walks a caller toward a token this server would accept.
        return {kind: 'unauthenticated', challenge};
      }
    },

    async authorizeCall(toolName, claims) {
      const emit = (decision: GateEvent['decision'], scopes: string[]): void => {
        if (!onGateEvent) return;
        try {
          onGateEvent({decision, tool: toolName, identity: this.identity(claims), scopes});
        } catch {
          // A log sink must never be able to fail a tool call.
        }
      };

      // The step-up is how a caller ESCAPES the gate: never gated, and never
      // reported, since it is not a gate decision.
      if (toolName === STEP_UP_TOOL) return {kind: 'allow'};
      // Expired reads as absent: the caller is told to step up again, which is
      // the honest answer and the one that can succeed.
      const record = liveRecord(await connections.get({sub: claims.sub, jti: claims.jti}));
      if (record) {
        emit('allowed', record.scopes);
        return {kind: 'allow'};
      }
      if (!gatedByEnforcement(toolName)) {
        // log-only, or a tool outside the allowlist: proceed, but say what the
        // enforcing configuration would have done.
        const wouldBlock = enforcement === 'log-only';
        emit(wouldBlock ? 'would-have-blocked' : 'allowed', []);
        return wouldBlock ? {kind: 'allow', wouldHaveBlocked: true} : {kind: 'allow'};
      }
      emit('blocked', []);
      return {kind: 'step-up-required', message: stepUpRequiredMessage()};
    },

    async completeStepUp(args, claims) {
      // The RFC 8693 exchange, server-side: the result is stored rather than
      // returned so it cannot reach model context. `granted.scopes` is what the
      // authorization server decides NOW -- an exchange can be refused, which is
      // why authority is not a signed claim.
      const granted = await exchanger.exchange({
        subjectToken: claims.token,
        resource,
      });

      // Consent is mechanical, and reads from what was just GRANTED. Without
      // the scope the step-up still succeeds -- the caller gets its connection,
      // and only the model-authored summary is dropped.
      const consented = granted.scopes.includes(PERSONALIZATION_SCOPE.connection);
      const raw = typeof args.task === 'string' ? args.task : undefined;
      const prompt = consented && raw ? sanitizePrompt(raw) : undefined;

      await connections.put(
        {sub: claims.sub, jti: claims.jti},
        {
          ...(prompt ? {prompt} : {}),
          scopes: granted.scopes,
          accessToken: granted.accessToken,
          ...(granted.expiresIn ? {expiresAt: Math.floor(now() / 1000) + granted.expiresIn} : {}),
        }
      );
      // Scopes are reported so an agent knows what it may now do. The TOKEN is
      // deliberately absent from this return type.
      return {ok: true, personalized: Boolean(prompt), scopes: granted.scopes};
    },

    identity(claims) {
      return {
        customerId: claims.sub,
        agentId: claims.clientId,
        credentialId: claims.jti,
        ...(claims.authenticatedAt === undefined
          ? {}
          : {authenticatedAt: claims.authenticatedAt}),
        issuer: claims.iss,
      };
    },

    async session(claims) {
      const record = liveRecord(await connections.get({sub: claims.sub, jti: claims.jti}));
      if (!record) return null;
      return {
        identity: this.identity(claims),
        scopes: record.scopes,
        ...(record.prompt === undefined ? {} : {task: record.prompt}),
        connectedAt: record.createdAt,
        ...(record.expiresAt === undefined ? {} : {expiresAt: record.expiresAt}),
      };
    },

    async effectiveScopes(claims) {
      // Never `claims.scopes`: a step-down token carries none before the
      // step-up, and stale ones after it. An EXPIRED connection carries none
      // either, or `hasScope` would outlive the gate that guards it.
      const record = liveRecord(await connections.get({sub: claims.sub, jti: claims.jti}));
      return record?.scopes ?? [];
    },

    async hasScope(claims, scope) {
      return (await this.effectiveScopes(claims)).includes(scope);
    },

    decorateInstructions(instructions) {
      const sentence = stepUpInstruction();
      // Appended, never replacing: the operator's own instructions are theirs.
      if (!instructions?.trim()) return sentence;
      return instructions.includes(STEP_UP_TOOL)
        ? instructions
        : `${instructions.trim()}\n\n${sentence}`;
    },

    mergeTools(tools, opts) {
      // Cursor-aware: appending on every page would show the tool N times to a
      // client that paginates. Merge only when there is no next page.
      if (opts?.nextCursor) return tools;
      if (tools.some(t => t.name === STEP_UP_TOOL)) return tools;
      return [...tools, stepUpToolDefinition()];
    },

    isStepUpTool: name => name === STEP_UP_TOOL,
  };

  /** Caps and de-fangs model-authored text. Stored and shown, never executed. */
  function sanitizePrompt(value: string): string {
    return (
      value
        // Stripping control characters IS the point here, so the rule that
        // flags them inside a regex is the wrong rule for this line.
        // eslint-disable-next-line no-control-regex
        .replace(/[\x00-\x1f\x7f]/g, ' ')
        .trim()
        .slice(0, PROMPT_MAX_CHARS)
    );
  }
}

/** Convenience for adapters: a record's age, for TTL policies that live above
 *  this package rather than inside it. */
export function connectionAgeMs(record: ConnectionRecord, nowMs: number): number {
  return nowMs - record.createdAt;
}
