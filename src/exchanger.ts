import type {ExchangedToken, TokenExchanger} from './types.js';

/** Milliseconds before an exchange is abandoned. A step-up is in the request
 *  path, so a hung authorization server must fail rather than hold the call. */
const DEFAULT_TIMEOUT_MS = 10_000;

/** Everything {@link createTokenExchanger} needs. */
export type TokenExchangerConfig = {
  /** Your confidential client. Lane refuses the exchange grant to a public
   *  client, which would otherwise make the step-up decorative. */
  clientId: string;
  clientSecret: string;
  /** Defaults to `${issuer}/token`. */
  tokenEndpoint?: string;
  /** Lane's authorization server, used to derive `tokenEndpoint`. */
  issuer?: string;
  timeoutMs?: number;
  /** Test seam. */
  fetchImpl?: typeof fetch;
};

/**
 * The RFC 8693 exchange, implemented.
 *
 * Deliberately no `scope` parameter: the authorization server ignores one and
 * returns what the user consented to, and sending it would imply a resource
 * server can shape the grant it is subject to.
 */
export function createTokenExchanger(config: TokenExchangerConfig): TokenExchanger {
  const {clientId, clientSecret} = config;
  if (!clientId || !clientSecret) {
    throw new Error(
      'createTokenExchanger: clientId and clientSecret are required -- the ' +
        'exchange grant refuses a public client'
    );
  }

  const issuer = (config.issuer ?? 'https://auth.getonlane.com/auth/mcp').replace(/\/+$/, '');
  const endpoint = config.tokenEndpoint ?? `${issuer}/token`;
  const doFetch = config.fetchImpl ?? fetch;
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return {
    async exchange({subjectToken, resource}) {
      const body = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
        subject_token: subjectToken,
        subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
        resource,
      });

      let res: Response;
      try {
        res = await doFetch(endpoint, {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            // client_secret_basic. RFC 6749 §2.3.1 requires servers to support
            // it, and it keeps the secret out of the body where a middlebox is
            // likelier to log it.
            authorization: `Basic ${btoa(
              `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`
            )}`,
          },
          body,
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        // The message never carries the request: it contained both a bearer and
        // a client secret.
        throw new Error(
          `token exchange could not reach ${endpoint}: ${(err as Error).name}`
        );
      }

      if (!res.ok) {
        // The OAuth error CODE is safe and is the only useful part; the body may
        // echo parameters back.
        let code = '';
        try {
          code = ((await res.json()) as {error?: string}).error ?? '';
        } catch {
          /* not JSON */
        }
        throw new Error(
          `token exchange refused: ${res.status}${code ? ` ${code}` : ''}`
        );
      }

      const payload = (await res.json()) as {
        access_token?: unknown;
        scope?: unknown;
        expires_in?: unknown;
      };
      if (typeof payload.access_token !== 'string' || payload.access_token === '') {
        throw new Error('token exchange returned no access_token');
      }

      const out: ExchangedToken = {
        accessToken: payload.access_token,
        // What was GRANTED. An absent `scope` means none, not "everything" --
        // defaulting the other way would turn a stripped grant into a full one.
        scopes:
          typeof payload.scope === 'string'
            ? payload.scope.split(/\s+/).filter(Boolean)
            : [],
      };
      if (typeof payload.expires_in === 'number') out.expiresIn = payload.expires_in;
      return out;
    },
  };
}
