/**
 * The middleware's contract, with the two failure classes tested hardest.
 *
 * Tokens are real: signed with a real key and verified through the real jose
 * path, with only the key set injected. What passes here is what a Lane-minted
 * token would.
 */
import {describe, expect, it, vi} from 'vitest';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  jwtVerify,
  type JWK,
  type JWTVerifyGetKey,
} from 'jose';

import {
  PERSONALIZATION_SCOPE,
  PROMPT_MAX_CHARS,
  STEP_UP_TOOL,
  createLaneMcpAuth,
  createTokenExchanger,
  metadataPaths,
  stepUpToolDefinition,
  type ConnectionKey,
  type ConnectionRecord,
  type ConnectionStore,
  type EnforcementMode,
  type GateEvent,
  type LaneMcpAuthConfig,
} from './index.js';

const ISS = 'https://auth.getonlane.com/auth/mcp';
const RESOURCE = 'https://acme.example/mcp';

function memoryConnections(): ConnectionStore & {rows: Map<string, ConnectionRecord>} {
  const rows = new Map<string, ConnectionRecord>();
  const k = (key: ConnectionKey) => `${key.sub}::${key.jti}`;
  return {
    rows,
    async get(key) {
      return rows.get(k(key)) ?? null;
    },
    async put(key, value) {
      const record = {...value, createdAt: 1_700_000_000_000};
      rows.set(k(key), record);
      return record;
    },
  };
}

async function keys() {
  const {publicKey, privateKey} = await generateKeyPair('RS256');
  const jwk = (await exportJWK(publicKey)) as JWK;
  jwk.kid = 'k1';
  jwk.alg = 'RS256';
  return {privateKey, jwks: createLocalJWKSet({keys: [jwk]})};
}

const token = (
  privateKey: CryptoKey,
  over: Record<string, unknown> = {},
  header: Record<string, string> = {}
) => {
  const {sub, jti, iss, aud, scope, ...rest} = {
    sub: 'user_1',
    jti: 'tok_1',
    client_id: 'agent-1',
    iss: ISS,
    aud: RESOURCE,
    scope: '',
    ...over,
  } as Record<string, unknown>;
  return new SignJWT({jti: jti as string, ...(scope ? {scope} : {}), ...rest})
    .setProtectedHeader({alg: 'RS256', kid: 'k1', typ: 'at+jwt', ...header})
    .setSubject(String(sub ?? ''))
    .setIssuer(String(iss))
    .setAudience(String(aud))
    .setExpirationTime('5m')
    .sign(privateKey);
};

async function build(
  over: Partial<LaneMcpAuthConfig> = {},
  granted: string[] = []
) {
  const {privateKey, jwks} = await keys();
  const connections = memoryConnections();
  // The AS is authoritative at exchange time: whatever it returns here IS the
  // caller's authority, regardless of what the incoming token said.
  const exchanger = {
    exchange: vi.fn(async () => ({
      accessToken: 'lane_exchanged_token',
      scopes: granted,
      expiresIn: 3600,
    })),
  };
  const auth = createLaneMcpAuth({
    resource: RESOURCE,
    issuer: ISS,
    connections,
    exchanger,
    // Real verification, injected key set.
    verifyToken: async (t) => {
      const {jwtVerify} = await import('jose');
      const {payload, protectedHeader} = await jwtVerify(t, jwks, {
        issuer: ISS,
        audience: RESOURCE,
      });
      if (protectedHeader.typ !== 'at+jwt') throw new Error('typ');
      const sub = String(payload.sub ?? '');
      const jti = String(payload.jti ?? '');
      if (!sub || !jti) throw new Error('token is missing sub or jti');
      const scope = typeof payload.scope === 'string' ? payload.scope : '';
      return {
        sub,
        jti,
        clientId: 'agent-1',
        token: t,
        scopes: scope ? scope.split(' ') : [],
        exp: Number(payload.exp ?? 0),
        iss: ISS,
      };
    },
    ...over,
  });
  return {auth, connections, privateKey, exchanger};
}

const claims = (over: Partial<{sub: string; jti: string; scopes: string[]}> = {}) => ({
  sub: 'user_1',
  jti: 'tok_1', clientId: 'agent-1',
  token: 'step-down-token',
  scopes: [] as string[],
  exp: 0,
  iss: ISS,
  ...over,
});

describe('discovery', () => {
  it('serves the document at both the root and the derived path', () => {
    expect(metadataPaths(RESOURCE)).toEqual({
      root: '/.well-known/oauth-protected-resource',
      derived: '/.well-known/oauth-protected-resource/mcp',
    });
  });

  it('names this resource and Lane as its authorization server', async () => {
    const {auth} = await build();
    const doc = JSON.parse(auth.protectedResourceDocument());
    expect(doc.resource).toBe(RESOURCE);
    expect(doc.authorization_servers).toEqual([ISS]);
  });

  it('challenges with the derived metadata url', async () => {
    const {auth} = await build();
    expect(auth.challenge()).toBe(
      'Bearer resource_metadata="https://acme.example/.well-known/oauth-protected-resource/mcp"'
    );
  });
});

// ── THE INVARIANT ───────────────────────────────────────────────────────────
describe('the two failure classes never blur', () => {
  it('a MISSING token is unauthenticated — 401 territory', async () => {
    const {auth} = await build();
    const out = await auth.authenticate(undefined);
    expect(out.kind).toBe('unauthenticated');
    expect(out.kind === 'unauthenticated' && out.challenge).toContain('resource_metadata=');
  });

  it('a BAD token is unauthenticated, and says nothing about which check failed', async () => {
    const {auth, privateKey} = await build();
    const wrongAud = await token(privateKey, {aud: 'https://elsewhere.example/mcp'});
    const bad = await auth.authenticate('not.a.token');
    const wrong = await auth.authenticate(wrongAud);
    expect(bad).toEqual(wrong);
  });

  it('a VALID token with NO connection is NOT an auth failure', async () => {
    // The whole point. If this ever returned `unauthenticated`, a client would
    // silently refresh a token that was never the problem, and a user would be
    // told to re-login to fix something logging in cannot fix.
    const {auth, privateKey} = await build();
    const good = await auth.authenticate(await token(privateKey));
    expect(good.kind).toBe('ok');

    const verdict = await auth.authorizeCall('search', claims());
    expect(verdict.kind).toBe('step-up-required');
    expect(verdict.kind === 'step-up-required' && verdict.message).toContain(STEP_UP_TOOL);
  });

  it('the step-up message tells the agent exactly what to do', async () => {
    // Instructive errors are the steering mechanism; a bare "forbidden" would
    // leave the agent with nowhere to go.
    const {auth} = await build();
    const verdict = await auth.authorizeCall('search', claims());
    const msg = verdict.kind === 'step-up-required' ? verdict.message : '';
    expect(msg).toMatch(/call/i);
    expect(msg).toMatch(/retry/i);
  });
});

describe('the gate', () => {
  it('never gates the step-up tool itself — that would be a deadlock', async () => {
    const {auth} = await build();
    expect((await auth.authorizeCall(STEP_UP_TOOL, claims())).kind).toBe('allow');
  });

  it('allows everything once the connection exists', async () => {
    const {auth} = await build();
    await auth.completeStepUp({}, claims());
    expect((await auth.authorizeCall('search', claims())).kind).toBe('allow');
  });

  it('binds the connection to the CREDENTIAL, not just the user', async () => {
    // A different `jti` is a different credential — possibly issued to another
    // client entirely. One step-up must not cover all of them.
    const {auth} = await build();
    await auth.completeStepUp({}, claims({jti: 'tok_1'}));
    expect((await auth.authorizeCall('search', claims({jti: 'tok_2'}))).kind).toBe(
      'step-up-required'
    );
  });

  it('log-only refuses nothing but reports what it would have refused', async () => {
    // This is what makes "install it on Friday" a safe sentence.
    const {auth} = await build({enforcement: 'log-only'});
    const verdict = await auth.authorizeCall('search', claims());
    expect(verdict.kind).toBe('allow');
    expect(verdict).toMatchObject({wouldHaveBlocked: true});
  });

  it('an allowlist gates only the named tools', async () => {
    const {auth} = await build({enforcement: {allow: ['pay']}});
    expect((await auth.authorizeCall('pay', claims())).kind).toBe('step-up-required');
    expect((await auth.authorizeCall('search', claims())).kind).toBe('allow');
  });
});

describe('consent is mechanical', () => {
  it('records the task summary when the EXCHANGE granted the scope', async () => {
    // Consent reads from what the AS granted at the exchange, never from what
    // the incoming token asserted — the token is step-down and asserts nothing.
    const {auth, connections} = await build({}, [PERSONALIZATION_SCOPE.connection]);
    const out = await auth.completeStepUp({task: 'book a table for four'}, claims());
    expect(out.personalized).toBe(true);
    expect([...connections.rows.values()][0]!.prompt).toBe('book a table for four');
  });

  it('WITHOUT the scope the step-up still succeeds and records nothing', async () => {
    // Declined must not cost the user their access — it collapses to bare
    // registration, it does not fail.
    const {auth, connections} = await build();
    const out = await auth.completeStepUp({task: 'book a table'}, claims({scopes: []}));
    expect(out.ok).toBe(true);
    expect(out.personalized).toBe(false);
    expect([...connections.rows.values()][0]!.prompt).toBeUndefined();
    // …and the caller is still let through.
    expect((await auth.authorizeCall('search', claims())).kind).toBe('allow');
  });

  it('caps and strips model-authored text', async () => {
    const {auth, connections} = await build({}, [PERSONALIZATION_SCOPE.connection]);
    const hostile = 'x'.repeat(PROMPT_MAX_CHARS + 200) + ' \u001b[31m';
    await auth.completeStepUp({task: hostile}, claims());
    const stored = [...connections.rows.values()][0]!.prompt!;
    expect(stored.length).toBeLessThanOrEqual(PROMPT_MAX_CHARS);
    expect(stored).not.toContain('\u001b');
  });

  it('ignores a non-string task rather than trusting it', async () => {
    const {auth, connections} = await build({}, [PERSONALIZATION_SCOPE.connection]);
    await auth.completeStepUp({task: {evil: true} as never}, claims());
    expect([...connections.rows.values()][0]!.prompt).toBeUndefined();
  });
});

describe('tool merge', () => {
  it('appends the reserved tool on the final page only', async () => {
    const {auth} = await build();
    const upstream = [{name: 'search', description: 'd', inputSchema: {}}];
    expect(auth.mergeTools(upstream, {nextCursor: 'p2'}).map((t) => t.name)).toEqual(['search']);
    expect(auth.mergeTools(upstream).map((t) => t.name)).toEqual(['search', STEP_UP_TOOL]);
  });

  it('does not double-append if it is already there', async () => {
    const {auth} = await build();
    const merged = auth.mergeTools([stepUpToolDefinition()]);
    expect(merged.filter((t) => t.name === STEP_UP_TOOL)).toHaveLength(1);
  });

  it('keeps the injected surface to one tool with no required fields', async () => {
    // Context budget is taken from the operator's real surface on every request.
    const def = stepUpToolDefinition();
    const schema = def.inputSchema as {properties: Record<string, unknown>; required: string[]};
    expect(Object.keys(schema.properties)).toHaveLength(1);
    expect(schema.required).toEqual([]);
  });

  it('appends the instruction without clobbering the operator’s own', async () => {
    const {auth} = await build();
    expect(auth.decorateInstructions('Acme tools.')).toContain('Acme tools.');
    expect(auth.decorateInstructions('Acme tools.')).toContain(STEP_UP_TOOL);
    expect(auth.decorateInstructions(undefined)).toContain(STEP_UP_TOOL);
  });

  it('is idempotent — re-decorating does not stack sentences', async () => {
    const {auth} = await build();
    const once = auth.decorateInstructions('Acme tools.');
    expect(auth.decorateInstructions(once)).toBe(once);
  });
});

describe('migration window', () => {
  it('accepts a legacy issuer while advertising only the new one', async () => {
    // Tokens already in clients' stores keep working; the document walks
    // everyone onto Lane. Emptying the list is what retires the old AS.
    const legacyIss = 'https://acme.authkit.app';
    const verifyToken = vi.fn(async () => ({
      sub: 'u',
      jti: 'j', clientId: 'agent-1',
      token: 'legacy-token',
      scopes: [],
      exp: 0,
      iss: legacyIss,
    }));
    const {auth} = await build({additionalIssuers: [legacyIss], verifyToken});
    const out = await auth.authenticate('legacy-token');
    expect(out.kind).toBe('ok');
    expect(JSON.parse(auth.protectedResourceDocument()).authorization_servers).toEqual([ISS]);
  });
});

// ── THE STEP-UP EXCHANGE ────────────────────────────────────────────────────
describe('authority comes from the exchange, not the token', () => {
  it('exchanges the step-down token, server-side, at the step-up', async () => {
    const {auth, exchanger} = await build({}, ['read']);
    await auth.completeStepUp({}, claims());
    expect(exchanger.exchange).toHaveBeenCalledWith({
      subjectToken: 'step-down-token',
      resource: RESOURCE,
    });
  });

  it('NEVER returns the exchanged token to the caller', async () => {
    // A client cannot install a new bearer (C3), so a token handed back could
    // only travel onward as a tool argument — a credential in model context.
    const {auth} = await build({}, ['read']);
    const out = await auth.completeStepUp({}, claims());
    expect(JSON.stringify(out)).not.toContain('lane_exchanged_token');
    expect(out.scopes).toEqual(['read']);
  });

  it('stores the granted authority, and it is what effectiveScopes reports', async () => {
    const {auth} = await build({}, ['read', 'write']);
    expect(await auth.effectiveScopes(claims())).toEqual([]);
    await auth.completeStepUp({}, claims());
    expect(await auth.effectiveScopes(claims())).toEqual(['read', 'write']);
    expect(await auth.hasScope(claims(), 'write')).toBe(true);
  });

  it('grants NOTHING from the token, even if the token carries scopes', async () => {
    // The audit that must exist. A token arriving with scopes set means
    // something upstream is not minting step-down tokens; it must not become
    // authority here regardless.
    const {auth} = await build({}, []);
    const withScopes = claims({scopes: ['write', 'admin']});
    expect(await auth.effectiveScopes(withScopes)).toEqual([]);
    await auth.completeStepUp({}, withScopes);
    // Still nothing: the exchange granted nothing, so nothing is granted.
    expect(await auth.effectiveScopes(withScopes)).toEqual([]);
  });

  it('records when the granted authority expires', async () => {
    const {auth, connections} = await build({now: () => 1_000_000}, ['read']);
    await auth.completeStepUp({}, claims());
    expect([...connections.rows.values()][0]!.expiresAt).toBe(1000 + 3600);
  });
});

describe('which audience an incoming bearer is verified against', () => {
  /**
   * LANE'S CANONICAL ONE, deliberately.
   *
   * A step-down token therefore authenticates at any server running this
   * middleware. That is a trade, made knowingly: the token carries no scopes
   * and no authority, every tool is refused until the step-up, and pinning this
   * server's own resource instead would accept only tokens the AS's exchange
   * grant refuses -- so no connection could ever be established.
   *
   * What it relocates is per-merchant consent, which now rests entirely on the
   * step-up. These tests pin the verification; the consent question is not
   * theirs to answer.
   *
   * The rest of this file injects `verifyToken`, so these are the only tests
   * here that exercise verification at all.
   */
  const CANONICAL = 'https://app-mcp.example.test';
  const MERCHANT = 'https://acme.example.test/mcp';
  const ISSUER = 'https://auth.example.test/auth/mcp';

  const mint = async (aud: string) => {
    const {privateKey, publicKey} = await generateKeyPair('RS256', {extractable: true});
    const jwk = (await exportJWK(publicKey)) as JWK;
    jwk.kid = 'k1';
    jwk.alg = 'RS256';
    const token = await new SignJWT({scope: '', jti: 'j1'})
      .setProtectedHeader({alg: 'RS256', kid: 'k1', typ: 'at+jwt'})
      .setSubject('user-1')
      .setIssuer(ISSUER)
      .setAudience(aud)
      .setExpirationTime('5m')
      .sign(privateKey);
    return {token, jwks: createLocalJWKSet({keys: [jwk]})};
  };

  const authFor = (jwks: JWTVerifyGetKey, audience: string) =>
    createLaneMcpAuth({
      resource: MERCHANT,
      canonicalResource: CANONICAL,
      issuer: ISSUER,
      connections: memoryConnections(),
      exchanger: {
        async exchange() {
          return {accessToken: 'exchanged', scopes: ['mcp']};
        },
      },
      verifyToken: async (token: string) => {
        const {payload} = await jwtVerify(token, jwks, {issuer: ISSUER, audience});
        return {
          clientId: String(payload.client_id ?? 'agent-1'),
          sub: String(payload.sub),
          jti: String(payload.jti),
          scopes: [],
          token,
          exp: Number(payload.exp),
          iss: ISSUER,
        };
      },
    });

  it('accepts the step-down token a caller actually holds', async () => {
    const {token, jwks} = await mint(CANONICAL);
    expect((await authFor(jwks, CANONICAL).authenticate(token)).kind).toBe('ok');
  });

  it('grants NOTHING on the strength of it — every tool is still refused', async () => {
    // This is what makes the audience trade survivable. A token that
    // authenticates anywhere would be alarming if it also authorized anything.
    const {token, jwks} = await mint(CANONICAL);
    const auth = authFor(jwks, CANONICAL);
    const outcome = await auth.authenticate(token);
    if (outcome.kind !== 'ok') throw new Error('expected ok');
    const verdict = await auth.authorizeCall('anything', outcome.claims);
    expect(verdict.kind).not.toBe('allow');
    expect(await auth.effectiveScopes(outcome.claims)).toEqual([]);
  });

  it('still refuses a token from another issuer', async () => {
    // Widening the audience does not widen the issuer: a token minted by
    // anything but Lane is refused, which is the boundary that did not move.
    const {token, jwks} = await mint(CANONICAL);
    const wrongIssuer = createLaneMcpAuth({
      resource: MERCHANT,
      canonicalResource: CANONICAL,
      issuer: 'https://elsewhere.example.test/auth/mcp',
      connections: memoryConnections(),
      exchanger: {
        async exchange() {
          return {accessToken: 'x', scopes: []};
        },
      },
      verifyToken: async (t: string) => {
        const {payload} = await jwtVerify(t, jwks, {
          issuer: 'https://elsewhere.example.test/auth/mcp',
          audience: CANONICAL,
        });
        return {
          clientId: String(payload.client_id ?? 'agent-1'),
          sub: String(payload.sub),
          jti: String(payload.jti),
          scopes: [],
          token: t,
          exp: Number(payload.exp),
          iss: ISSUER,
        };
      },
    });
    expect((await wrongIssuer.authenticate(token)).kind).not.toBe('ok');
  });
});

describe('identity and session', () => {
  const claims = {
    sub: 'user-1',
    jti: 'tok-1',
    clientId: 'agent-1',
    token: 'raw',
    scopes: [],
    exp: 0,
    authenticatedAt: 1700,
    iss: ISS,
  };

  it('reports who is calling before any step-up', async () => {
    // Available from the token alone, so a server can log or route on it
    // without a store round trip.
    const {auth} = await build();
    expect(auth.identity(claims)).toEqual({
      customerId: 'user-1',
      agentId: 'agent-1',
      credentialId: 'tok-1',
      authenticatedAt: 1700,
      issuer: ISS,
    });
  });

  it('separates the credential from the user, so two clients are two of them', async () => {
    // `sub` alone would make one registration cover every credential a person
    // holds -- including one issued to a different agent.
    const {auth} = await build();
    const other = auth.identity({...claims, jti: 'tok-2'});
    expect(other.credentialId).not.toBe(auth.identity(claims).credentialId);
    expect(other.customerId).toBe(auth.identity(claims).customerId);
  });

  it('has no session until the step-up', async () => {
    const {auth} = await build();
    expect(await auth.session(claims)).toBeNull();
  });

  it('reports scopes, task and connection time once connected', async () => {
    const {auth, connections} = await build();
    await connections.put(
      {sub: 'user-1', jti: 'tok-1'},
      {scopes: ['orders:read'], prompt: 'buy a keyboard', expiresAt: 4_000_000_000},
    );
    const session = await auth.session(claims);
    expect(session).toMatchObject({
      scopes: ['orders:read'],
      task: 'buy a keyboard',
      expiresAt: 4_000_000_000,
    });
    expect(session?.identity.agentId).toBe('agent-1');
    expect(typeof session?.connectedAt).toBe('number');
  });

  it('omits the task when consent did not allow recording one', async () => {
    // Declined means declined: no key, rather than an empty string a caller
    // might render.
    const {auth, connections} = await build();
    await connections.put({sub: 'user-1', jti: 'tok-1'}, {scopes: []});
    const session = await auth.session(claims);
    expect(session).not.toHaveProperty('task');
  });
});

describe('createTokenExchanger', () => {
  const call = async (
    respond: (url: string, init: RequestInit) => Response,
    over: Partial<Parameters<typeof createTokenExchanger>[0]> = {},
  ) => {
    const seen: {url: string; init: RequestInit}[] = [];
    const ex = createTokenExchanger({
      clientId: 'rs1',
      clientSecret: 's3cret',
      issuer: 'https://as.example/auth/mcp',
      fetchImpl: (async (url: string, init: RequestInit) => {
        seen.push({url, init});
        return respond(url, init);
      }) as unknown as typeof fetch,
      ...over,
    });
    return {ex, seen};
  };
  const ok = (body: unknown) =>
    new Response(JSON.stringify(body), {status: 200, headers: {'content-type': 'application/json'}});

  it('refuses to exist without a confidential credential', () => {
    // The exchange grant rejects a public client; failing at construction says
    // so where it is fixable, not on the first step-up in production.
    expect(() => createTokenExchanger({clientId: 'rs1', clientSecret: ''})).toThrow(/required/);
  });

  it('posts the exchange to `${issuer}/token` with Basic auth', async () => {
    const {ex, seen} = await call(() => ok({access_token: 'a', scope: 'openid email'}));
    await ex.exchange({subjectToken: 'sub-token', resource: 'https://acme.example/mcp'});

    expect(seen[0]!.url).toBe('https://as.example/auth/mcp/token');
    const headers = seen[0]!.init.headers as Record<string, string>;
    expect(headers.authorization).toMatch(/^Basic /);
    // The body is form-encoded; an AS that reads the header will reject it as
    // JSON, and the comment-cleanup pass dropped this header once unnoticed
    // because nothing asserted it.
    expect(headers['content-type']).toBe('application/x-www-form-urlencoded');
    const body = new URLSearchParams(String(seen[0]!.init.body));
    expect(body.get('grant_type')).toBe('urn:ietf:params:oauth:grant-type:token-exchange');
    expect(body.get('subject_token')).toBe('sub-token');
    expect(body.get('resource')).toBe('https://acme.example/mcp');
  });

  it('sends NO scope, because a resource server does not shape its own grant', async () => {
    const {ex, seen} = await call(() => ok({access_token: 'a', scope: 'openid'}));
    await ex.exchange({subjectToken: 't', resource: 'https://acme.example/mcp'});
    expect(new URLSearchParams(String(seen[0]!.init.body)).has('scope')).toBe(false);
  });

  it('treats an absent scope as NONE, never as everything', async () => {
    const {ex} = await call(() => ok({access_token: 'a'}));
    expect((await ex.exchange({subjectToken: 't', resource: 'r'})).scopes).toEqual([]);
  });

  it('never puts the credential or the bearer in an error', async () => {
    const {ex} = await call(() =>
      new Response(JSON.stringify({error: 'invalid_grant', subject_token: 'LEAKED'}), {
        status: 400,
        headers: {'content-type': 'application/json'},
      }),
    );
    await expect(ex.exchange({subjectToken: 'sub-token', resource: 'r'})).rejects.toThrow(
      /invalid_grant/,
    );
    await expect(ex.exchange({subjectToken: 'sub-token', resource: 'r'})).rejects.not.toThrow(
      /s3cret|sub-token|LEAKED/,
    );
  });

  it('fails rather than hanging the step-up', async () => {
    const {ex} = await call(() => {
      throw Object.assign(new Error('timeout'), {name: 'TimeoutError'});
    });
    await expect(ex.exchange({subjectToken: 't', resource: 'r'})).rejects.toThrow(/TimeoutError/);
  });
});

describe('onGateEvent', () => {
  const setup = async (enforcement: EnforcementMode) => {
    const events: GateEvent[] = [];
    const {auth, connections, privateKey} = await build({
      enforcement,
      onGateEvent: (e) => events.push(e),
    });
    return {auth, connections, events, mintToken: () => token(privateKey)};
  };

  it('reports what log-only WOULD have refused', async () => {
    // Without this the mode decides in silence, and "install it and watch"
    // is not a thing an operator can actually do.
    const {auth, events, mintToken} = await setup('log-only');
    const claims = await auth.authenticate(await mintToken());
    if (claims.kind !== 'ok') throw new Error('expected ok');

    const verdict = await auth.authorizeCall('place_order', claims.claims);
    expect(verdict).toMatchObject({kind: 'allow', wouldHaveBlocked: true});
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({decision: 'would-have-blocked', tool: 'place_order'});
  });

  it('reports a real refusal, and an allow with the scopes behind it', async () => {
    const {auth, connections, events, mintToken} = await setup('gate-all');
    const claims = await auth.authenticate(await mintToken());
    if (claims.kind !== 'ok') throw new Error('expected ok');

    await auth.authorizeCall('place_order', claims.claims);
    expect(events.at(-1)).toMatchObject({decision: 'blocked', scopes: []});

    await connections.put(
      {sub: claims.claims.sub, jti: claims.claims.jti},
      {scopes: ['email']},
    );
    await auth.authorizeCall('place_order', claims.claims);
    expect(events.at(-1)).toMatchObject({decision: 'allowed', scopes: ['email']});
  });

  it('NEVER hands the raw bearer to the sink', async () => {
    // The obvious shape -- passing VerifiedClaims -- puts a live token into
    // whatever the operator logs.
    const {auth, events, mintToken} = await setup('gate-all');
    const token = await mintToken();
    const claims = await auth.authenticate(token);
    if (claims.kind !== 'ok') throw new Error('expected ok');

    await auth.authorizeCall('place_order', claims.claims);
    expect(JSON.stringify(events)).not.toContain(token);
    expect(events[0]!.identity.customerId).toBeTruthy();
  });

  it('does not let a throwing sink fail the call', async () => {
    const {auth, privateKey} = await build({
      onGateEvent: () => {
        throw new Error('log backend down');
      },
    });
    const claims = await auth.authenticate(await token(privateKey));
    if (claims.kind !== 'ok') throw new Error('expected ok');
    await expect(auth.authorizeCall('place_order', claims.claims)).resolves.toMatchObject({
      kind: 'step-up-required',
    });
  });

  it('says nothing about the step-up tool, which is the way OUT of the gate', async () => {
    const {auth, events, mintToken} = await setup('gate-all');
    const claims = await auth.authenticate(await mintToken());
    if (claims.kind !== 'ok') throw new Error('expected ok');
    await auth.authorizeCall(STEP_UP_TOOL, claims.claims);
    expect(events).toHaveLength(0);
  });
});

describe('an expired connection', () => {
  const at = (seconds: number) => () => seconds * 1000;

  it('is refused, not allowed on the strength of the row still existing', async () => {
    // The row survives its grant. Allowing on `if (record)` alone meant a grant
    // the authorization server issued for an hour authorized forever.
    const {auth, connections, privateKey} = await build({now: at(5_000)});
    await connections.put({sub: 'user_1', jti: 'tok_1'}, {scopes: ['email'], expiresAt: 4_000});
    const out = await auth.authenticate(await token(privateKey));
    if (out.kind !== 'ok') throw new Error('expected ok');
    expect(await auth.authorizeCall('anything', out.claims)).toMatchObject({
      kind: 'step-up-required',
    });
  });

  it('carries no scopes, so hasScope cannot outlive the gate', async () => {
    const {auth, connections, privateKey} = await build({now: at(5_000)});
    await connections.put({sub: 'user_1', jti: 'tok_1'}, {scopes: ['email'], expiresAt: 4_000});
    const out = await auth.authenticate(await token(privateKey));
    if (out.kind !== 'ok') throw new Error('expected ok');
    expect(await auth.effectiveScopes(out.claims)).toEqual([]);
    expect(await auth.hasScope(out.claims, 'email')).toBe(false);
    expect(await auth.session(out.claims)).toBeNull();
  });

  it('is still live one second before it expires', async () => {
    const {auth, connections, privateKey} = await build({now: at(3_999)});
    await connections.put({sub: 'user_1', jti: 'tok_1'}, {scopes: ['email'], expiresAt: 4_000});
    const out = await auth.authenticate(await token(privateKey));
    if (out.kind !== 'ok') throw new Error('expected ok');
    expect(await auth.hasScope(out.claims, 'email')).toBe(true);
  });

  it('leaves a connection with NO expiry alone', async () => {
    // Absent means "the store decides", not "expired".
    const {auth, connections, privateKey} = await build({now: at(9_999_999)});
    await connections.put({sub: 'user_1', jti: 'tok_1'}, {scopes: ['email']});
    const out = await auth.authenticate(await token(privateKey));
    if (out.kind !== 'ok') throw new Error('expected ok');
    expect(await auth.hasScope(out.claims, 'email')).toBe(true);
  });
});

describe('the SHIPPED verification path', () => {
  /**
   * Every other test injects `verifyToken`, so the library's own closure -- the
   * real jose verification, the `at+jwt` guard that stops an id_token being
   * replayed as an access token, the sub/jti guard -- was never executed. For a
   * package whose value is "trust this verification", that is the one path most
   * worth running.
   *
   * Reached by mocking only `createRemoteJWKSet`, so the network is replaced
   * and every decision below it is the shipped code.
   */
  const real = async (over: Record<string, unknown> = {}) => {
    const {privateKey, jwks} = await keys();
    vi.resetModules();
    vi.doMock('jose', async () => {
      const actual = await vi.importActual<typeof import('jose')>('jose');
      return {...actual, createRemoteJWKSet: () => jwks};
    });
    const {createLaneMcpAuth: fresh} = await import('./index.js');
    const auth = fresh({
      resource: RESOURCE,
      issuer: ISS,
      connections: memoryConnections(),
      exchanger: {
        async exchange() {
          return {accessToken: 'x', scopes: []};
        },
      },
      ...over,
    } as never);
    return {auth, privateKey};
  };

  it('accepts a properly minted access token', async () => {
    const {auth, privateKey} = await real();
    const out = await auth.authenticate(await token(privateKey));
    expect(out.kind).toBe('ok');
    if (out.kind !== 'ok') return;
    expect(out.claims.sub).toBe('user_1');
    expect(out.claims.clientId).toBe('agent-1');
  });

  it('REFUSES an id_token replayed as an access token', async () => {
    // jose does not check `typ`. Without the explicit guard an id_token from
    // the same issuer, signed by the same key, verifies perfectly.
    const {auth, privateKey} = await real();
    const idToken = await token(privateKey, {}, {typ: 'JWT'});
    expect((await auth.authenticate(idToken)).kind).toBe('unauthenticated');
  });

  it('REFUSES a token missing `jti`, which a connection is keyed on', async () => {
    const {auth, privateKey} = await real();
    expect((await auth.authenticate(await token(privateKey, {jti: ''}))).kind).toBe(
      'unauthenticated',
    );
  });

  it('REFUSES another issuer, even with a valid signature', async () => {
    const {auth, privateKey} = await real();
    expect(
      (await auth.authenticate(await token(privateKey, {iss: 'https://evil.example'}))).kind,
    ).toBe('unauthenticated');
  });

  it('accepts a MIGRATION issuer when one is configured', async () => {
    const {auth, privateKey} = await real({additionalIssuers: ['https://old.example/mcp']});
    const out = await auth.authenticate(
      await token(privateKey, {iss: 'https://old.example/mcp'}),
    );
    expect(out.kind).toBe('ok');
  });
});
