/**
 * @fileoverview The `lane_session_info` report: what Lane knows about one
 * verified caller. Framework-agnostic — adapters register the tool, this
 * module builds its answer.
 */
import {SESSION_INFO_TOOL, STEP_UP_TOOL, type VerifiedClaims} from './types.js';
import type {LaneMcpAuth} from './index.js';

/** Arguments the session-info tool accepts. */
export type SessionArgs = {
  /** Report whether this connection carries a named scope. */
  probe_scope?: string;
};

/** What `lane_session_info` returns, as data. All timestamps are ISO strings. */
export type SessionReport = {
  connected: boolean;
  /** What the caller should do next. Present in both states: an agent reads
   *  this far more reliably than it infers from a boolean. */
  next_step: string;
  identity: {
    /** Pairwise: stable at this server, different at every other one. */
    customer_id: string;
    agent_id: string;
    credential_id: string;
    issuer: string;
    /** When the HUMAN last authenticated. A token refresh does not move it. */
    human_authenticated_at: string | null;
  };
  session: {
    scopes: string[];
    /** `null` means "not recorded", never "recorded as blank". */
    task: string | null;
    task_recorded: boolean;
    connected_at: string | null;
    expires_at: string | null;
  } | null;
  scope_probe?: {scope: string; granted: boolean};
};

function isoFromSeconds(seconds: number | undefined): string | null {
  return seconds === undefined ? null : new Date(seconds * 1000).toISOString();
}

function isoFromMillis(millis: number | undefined): string | null {
  return millis === undefined ? null : new Date(millis).toISOString();
}

/** The tool's `tools/list` description. */
export function sessionInfoDescription(): string {
  return (
    'What Lane knows about this session: who is calling, whether they have ' +
    'completed the step-up, and what that connection is allowed to do. Works ' +
    'before the step-up — call it to confirm an auth integration worked.'
  );
}

/**
 * Build the report for one verified caller.
 *
 * `connected: false` with an identity still reported means the bearer verified
 * but no connection is recorded — the caller should run the step-up tool.
 */
export async function describeSession(
  auth: LaneMcpAuth,
  claims: VerifiedClaims,
  args: SessionArgs = {}
): Promise<SessionReport> {
  const identity = auth.identity(claims);
  const session = await auth.session(claims);

  const report: SessionReport = {
    connected: session !== null,
    next_step:
      session === null
        ? `No session yet. Call \`${STEP_UP_TOOL}\` first; every other tool on ` +
          'this server is refused until you do.'
        : 'Session established. Every tool on this server is callable.',
    identity: {
      customer_id: identity.customerId,
      agent_id: identity.agentId,
      credential_id: identity.credentialId,
      issuer: identity.issuer,
      human_authenticated_at: isoFromSeconds(identity.authenticatedAt),
    },
    session:
      session === null
        ? null
        : {
            scopes: session.scopes,
            // `in`, not truthiness: the key is absent entirely when consent did
            // not allow recording model-authored text.
            task: 'task' in session && session.task !== undefined ? session.task : null,
            task_recorded: 'task' in session,
            connected_at: isoFromMillis(session.connectedAt),
            expires_at: isoFromSeconds(session.expiresAt),
          },
  };

  if (args.probe_scope !== undefined && args.probe_scope !== '') {
    report.scope_probe = {
      scope: args.probe_scope,
      granted: await auth.hasScope(claims, args.probe_scope),
    };
  }

  return report;
}

export {SESSION_INFO_TOOL};
