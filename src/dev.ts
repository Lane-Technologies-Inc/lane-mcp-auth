/**
 * @fileoverview A LOCAL-ONLY auth seam, so a human can walk the whole flow with
 * curl: substitutes the `verifyToken` test seam and a stub exchanger so both
 * "no session yet" and "session exists" are reachable without a Lane-minted
 * token or a confidential client.
 *
 * It makes ANY bearer valid, so it must be armed explicitly
 * (`LANE_MCP_DEV_AUTH=1`) and refuses to arm when `NODE_ENV=production`. It is
 * deliberately NOT wired into `withLaneAuth`: a dev bypass reachable from the
 * production entrypoint's options would be a footgun. The gate itself is
 * untouched — a dev token still has no connection until it steps up.
 */
import {createHash} from 'node:crypto';

import {PERSONALIZATION_SCOPE} from './types.js';
import type {ExchangedToken, TokenExchanger, VerifiedClaims} from './types.js';

/** The env var that arms the seam. Set it to `1`, and never on a deployment. */
export const DEV_AUTH_ENV = 'LANE_MCP_DEV_AUTH';

/** Scopes Lane can issue to a merchant audience. */
export const LANE_SCOPES = ['offline_access', 'openid', 'profile', 'email', 'phone'] as const;

// Plus the consent scope, or `personalized` could never be true through the stub.
const GRANTABLE: readonly string[] = [...LANE_SCOPES, PERSONALIZATION_SCOPE.connection];

/** What {@link createDevAuthSeam} returns: plug both into `createLaneMcpAuth`. */
export type DevAuthSeam = {
  verifyToken: (token: string) => Promise<VerifiedClaims>;
  exchanger: TokenExchanger;
};

export type DevAuthOptions = {
  issuer: string;
  /** What the stub exchange "grants". Filtered to names Lane actually issues —
   *  a scope Lane does not issue is permanently false in a real deployment, and
   *  a seam that pretended otherwise would be a liar. Default `openid email`. */
  scopes?: string[];
  /** Clock override, milliseconds since epoch. Test seam. */
  now?: () => number;
};

// Deterministic, so the same bearer is the same caller across restarts.
function digest(input: string, length: number): string {
  return createHash('sha256').update(input).digest('hex').slice(0, length);
}

/** Build the seam. Check {@link devAuthStatus} first; this constructor does not
 *  read the environment itself. */
export function createDevAuthSeam(opts: DevAuthOptions): DevAuthSeam {
  const now = opts.now ?? (() => Date.now());
  const granted = (opts.scopes ?? ['openid', 'email']).filter((s) => GRANTABLE.includes(s));

  return {
    verifyToken(token: string): Promise<VerifiedClaims> {
      if (token.trim() === '') return Promise.reject(new Error('empty bearer'));
      const seconds = Math.floor(now() / 1000);
      return Promise.resolve({
        // Derived from the bearer, so two dev tokens are two callers — which is
        // what makes the (sub, jti) keying of the connection store observable.
        sub: `dev-${digest(`sub:${token}`, 16)}`,
        jti: `dev-${digest(`jti:${token}`, 16)}`,
        clientId: 'mcpc_dev_local',
        authenticatedAt: seconds,
        // Empty before a step-up in the real protocol too; authority lives in
        // the connection, never here.
        scopes: [],
        token,
        exp: seconds + 3600,
        iss: opts.issuer,
      });
    },
    exchanger: {
      exchange(): Promise<ExchangedToken> {
        return Promise.resolve({
          accessToken: `dev-exchanged-${digest(String(now()), 12)}`,
          scopes: granted,
          expiresIn: 3600,
        });
      },
    },
  };
}

/** Whether the seam may be armed, and why not when it may not. Refuses under
 *  `NODE_ENV=production` regardless of the env var. */
export function devAuthStatus(env: Record<string, string | undefined>): {
  armed: boolean;
  reason: string;
} {
  if (env[DEV_AUTH_ENV] !== '1') {
    return {armed: false, reason: `${DEV_AUTH_ENV} is not set to 1`};
  }
  if (env.NODE_ENV === 'production') {
    return {
      armed: false,
      reason: `${DEV_AUTH_ENV}=1 was REFUSED because NODE_ENV=production`,
    };
  }
  return {armed: true, reason: 'armed'};
}
