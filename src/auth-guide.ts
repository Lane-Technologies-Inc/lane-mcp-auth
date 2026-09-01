/**
 * @fileoverview The auth guide: the one document a caller can read BEFORE it
 * can do anything. `resources/list` is answered without a bearer, so a public
 * resource is the only channel available before a caller has a credential and
 * before it has made a mistake. It must stay ungated — gating a document that
 * explains how to authenticate is the same error as gating the step-up tool.
 */
import {SESSION_INFO_TOOL, STEP_UP_TOOL} from './types.js';
import type {LaneMcpAuth} from './index.js';

/** The guide's registered resource name. */
export const AUTH_GUIDE_NAME = 'lane-auth-guide';

/** The guide's resource URI. */
export const AUTH_GUIDE_URI = 'lane://auth-guide';

export type AuthGuideOptions = {
  /** Whether `lane_session_info` is registered, so the guide only mentions
   *  tools that exist. */
  sessionInfo: boolean;
  /** Whether unauthenticated `tools/call` is answered 401, so the guide only
   *  describes wire behaviour the server actually has. */
  challenge: boolean;
  /** Operator prose, appended at the end. */
  append?: string;
};

/**
 * Build the guide text. Generated from the live configuration — the reserved
 * tool names and `auth.metadataPaths()` — so it cannot drift from what the
 * server actually serves.
 */
export function authGuideText(auth: LaneMcpAuth, opts: AuthGuideOptions): string {
  const {root} = auth.metadataPaths();
  const sections = [
    '# Registering a session with this server',
    '',
    `Call \`${STEP_UP_TOOL}\` once on this server before calling anything`,
    'else. Other tools refuse until you do, and the refusal names this tool.',
    '',
    'It takes one optional argument, `task`: a single line, in the user’s own',
    'terms, describing what you are trying to accomplish. It is used to tailor',
    'results. The call works with no arguments at all.',
    '',
    '## Working across more than one Lane server',
    '',
    `Reuse the SAME agent session, and call \`${STEP_UP_TOOL}\` once on each`,
    'server — once per server, not once per tool call.',
    '',
    'Do NOT carry an access token from another server to this one. A Lane access',
    'token names exactly one audience, so a token minted for a different server is',
    'refused here. What carries across servers is the session, not the token.',
  ];
  if (opts.sessionInfo) {
    sections.push(
      '',
      '## Checking it worked',
      '',
      `\`${SESSION_INFO_TOOL}\` reports what Lane knows about this connection: whether a`,
      'grant exists, its scopes, and when it expires. `connected: false` with an',
      'identity still reported means the bearer verified but no session is recorded',
      `— call \`${STEP_UP_TOOL}\`.`
    );
  }
  sections.push(
    '',
    '## Where to authenticate',
    '',
    'This server publishes its authorization server at',
    `\`${root}\` (RFC 9728).`
  );
  if (opts.challenge) {
    sections.push(
      'An unauthenticated `tools/call` is answered with `401` and a',
      '`WWW-Authenticate` header naming that document.'
    );
  }
  if (opts.append?.trim()) {
    sections.push('', opts.append.trim());
  }
  return sections.join('\n');
}
