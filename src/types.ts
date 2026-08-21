/**
 * @fileoverview Types an operator configures and receives back.
 *
 * Refusals come in two kinds on purpose: a token problem is a 401, a missing
 * connection is a normal tool-result error. The README explains why.
 */

/** What a verified bearer proved. Identity and authority, never a user profile. */
export type VerifiedClaims = {
  /** The end user, opaque here. */
  sub: string;
  /** Token id. Scopes a connection to one credential, not to the user. */
  jti: string;
  /** The agent, per RFC 9068 `client_id`. Stable per agent at your server only;
   *  different at another merchant, so it cannot be used to correlate. */
  clientId: string;
  /** When the user last authenticated, seconds since epoch. Not the token's
   *  issue time -- a refresh does not move it. */
  authenticatedAt?: number;
  /**
   * The token's own `scope` claim — empty until the step-up.
   *
   * Not authority. Use {@link LaneMcpAuth.hasScope} instead.
   */
  scopes: string[];
  /** The raw bearer, presented as the exchange's `subject_token`. Never log it. */
  token: string;
  /** Seconds since epoch. */
  exp: number;
  /** Which issuer minted it. Only interesting mid-migration. */
  iss: string;
  /** The operator's own subject and organization. `federated` mode only. */
  upstream?: {subject: string; organizationId?: string};
};

/**
 * Where connections live.
 *
 * Injected because this is server-side state one service owns: two replicas
 * with in-memory stores would give two answers.
 */
export interface ConnectionStore {
  get(key: ConnectionKey): Promise<ConnectionRecord | null>;
  put(key: ConnectionKey, value: ConnectionInput): Promise<ConnectionRecord>;
  /** Withdraw a connection. Optional. After a delete the caller is refused and
   *  told to step up again, the same path a first-time caller takes. */
  delete?(key: ConnectionKey): Promise<void>;
}

/** Both fields, so a connection covers one credential rather than every
 *  credential its user holds. */
export type ConnectionKey = {sub: string; jti: string};

/** What the step-up writes to the store. */
export type ConnectionInput = {
  /** Task summary from the caller. Untrusted; capped and sanitised already. */
  prompt?: string;
  /** Granted at the exchange. The only authority in the system. */
  scopes: string[];
  /** The exchanged token, if this server calls Lane on the user's behalf.
   *  A live credential — store it encrypted. */
  accessToken?: string;
  /** Seconds since epoch. */
  expiresAt?: number;
};

/** A stored connection, as the store hands it back. */
export type ConnectionRecord = ConnectionInput & {createdAt: number};

/** Who is calling, in one place. Both ids are opaque and stable at YOUR server
 *  only -- neither identifies the person or agent anywhere else. */
export type Identity = {
  /** The end user. Different at every other merchant, so two servers cannot
   *  join records on it. */
  customerId: string;
  /** The agent acting for them. */
  agentId: string;
  /** The credential in use. A user with two clients has two of these. */
  credentialId: string;
  /** Seconds since epoch, when present. */
  authenticatedAt?: number;
  issuer: string;
};

/** What a connected caller may do and when they agreed to it. `null` before the
 *  step-up. */
export type Session = {
  identity: Identity;
  /** Granted at the exchange. The only authority in the system. */
  scopes: string[];
  /** The caller's own task summary, if it sent one and consent allowed it. */
  task?: string;
  /** Milliseconds since epoch. */
  connectedAt: number;
  /** Seconds since epoch, if the grant expires. */
  expiresAt?: number;
};

/**
 * Performs the RFC 8693 exchange at the step-up.
 *
 * Server-side only: the exchanged token is stored, never returned, so it cannot
 * reach model context.
 */
export interface TokenExchanger {
  exchange(args: {subjectToken: string; resource: string}): Promise<ExchangedToken>;
}

/** The result of a successful exchange. */
export type ExchangedToken = {
  accessToken: string;
  /** What was granted, not what was asked for. */
  scopes: string[];
  /** Seconds from now. */
  expiresIn?: number;
};

/** How much the gate binds. The README describes the rollout path. */
export type EnforcementMode =
  /** Every tool requires a connection. */
  | 'gate-all'
  /** Only these tools require one. */
  | {allow: string[]}
  /** Nothing is refused; verdicts report what would have been. */
  | 'log-only';

/**
 * Which setup this deployment is behind.
 *
 * Token verification is identical either way; the mode only surfaces upstream
 * identity.
 */
export type AuthMode =
  /** Lane authenticates the human itself. */
  | {mode: 'lane'}
  /** Authentication is delegated upstream; `upstream` names the adapter. */
  | {mode: 'federated'; upstream: 'authkit' | (string & {})};

/**
 * What the gate decided about one call.
 *
 * Carries {@link Identity} and never `VerifiedClaims`: the latter holds the raw
 * bearer, and handing that to a logging callback is how tokens reach logs.
 */
export type GateEvent = {
  decision: 'allowed' | 'blocked' | 'would-have-blocked';
  tool: string;
  identity: Identity;
  /** The connection's scopes, or `[]` when there is no connection. */
  scopes: string[];
};

/** Everything `createLaneMcpAuth` needs. */
export type LaneMcpAuthConfig = {
  /** This server's public MCP URL: the `aud` of its tokens and the `resource`
   *  its metadata names. */
  resource: string;
  /**
   * The audience an incoming bearer is verified against. Defaults to Lane's
   * canonical resource, which is **not** this server's `resource`.
   *
   * See "Why the audience is Lane's, not yours" in the README before changing it.
   */
  canonicalResource?: string;
  /** Defaults to `lane`. */
  auth?: AuthMode;
  /** Lane's authorization server. Defaults to production. */
  issuer?: string;
  /** Extra issuers to accept during a migration. The challenge always
   *  advertises `issuer`, so re-discovery walks clients forward. */
  additionalIssuers?: string[];
  connections: ConnectionStore;
  exchanger: TokenExchanger;
  enforcement?: EnforcementMode;
  /**
   * Called for every gate decision. Required in practice for `'log-only'`,
   * which otherwise decides in silence.
   *
   * Fire and forget: it is not awaited, and a throw is swallowed, so a broken
   * log sink cannot fail a tool call.
   */
  onGateEvent?: (event: GateEvent) => void;
  /** Custom verification. Defaults to remote JWKS off the issuer. */
  verifyToken?: (token: string) => Promise<VerifiedClaims>;
  /** Clock override, in milliseconds since epoch. Test seam. */
  now?: () => number;
};

/** Scopes that gate what the step-up may record. */
export const PERSONALIZATION_SCOPE = {
  /** The per-connection task summary the step-up tool accepts. */
  connection: 'personalization:connection',
} as const;

/** The reserved tool. Never declare it yourself or forward it upstream. */
export const STEP_UP_TOOL = 'lane_register_session';

/** Cap on the model-authored task summary. Long enough to be useful, short
 *  enough not to be a smuggling channel. */
export const PROMPT_MAX_CHARS = 600;
