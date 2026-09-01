# `@getonlane/mcp-auth`

OAuth 2.1 resource server and consent gate for an MCP server.

Your server verifies bearer tokens, publishes the discovery documents clients
need, and refuses every tool until the caller holds a recorded, revocable grant.
You route it; the library decides.

```sh
npm install @getonlane/mcp-auth
```

Python, for FastMCP and the Python SDK:

```sh
pip install lane-mcp-auth
```

**Docs** — [overview](https://docs.getonlane.com/sell/mcp-auth/overview) ·
[quickstart](https://docs.getonlane.com/sell/mcp-auth/quickstart) ·
[the gate](https://docs.getonlane.com/sell/mcp-auth/the-gate) ·
[rollout](https://docs.getonlane.com/sell/mcp-auth/rollout) ·
[reference](https://docs.getonlane.com/sell/mcp-auth/reference)

This file is the whole integration in one page. The docs cover the same ground
with more room: why refusals are tool results rather than 401s, how to turn the
gate on in front of live traffic without refusing anyone, and where the
TypeScript and Python APIs deliberately differ.

## A complete integration

Everything below is required. This is the whole thing, in one place, for a
fetch-style server (Hono, Workers, Deno, Bun, Next.js route handlers):

```ts
import {createLaneMcpAuth} from '@getonlane/mcp-auth';

const auth = createLaneMcpAuth({
  resource: 'https://acme.example/mcp',
  connections,
  exchanger,
});

/** Which scope each tool needs. Tools absent from this map need none.
 *  Must be scopes Lane issues — see "Which scopes exist" below. */
const SCOPES: Record<string, string> = {
  read_profile: 'profile',
  email_receipt: 'email',
};   // must be scopes Lane issues -- see "Which scopes exist" 

export async function handler(req: Request): Promise<Response> {
  const {pathname} = new URL(req.url);

  // 1. Discovery. BOTH paths — the challenge advertises the derived one.
  const paths = auth.metadataPaths();
  if (pathname === paths.root || pathname === paths.derived) {
    return new Response(auth.protectedResourceDocument(), {
      headers: {'content-type': 'application/json'},
    });
  }

  // 2. Authenticate BEFORE reading the body.
  const outcome = await auth.authenticate(
    req.headers.get('authorization')?.replace(/^Bearer\s+/i, ''),
  );
  if (outcome.kind !== 'ok') {
    return Response.json({error: 'unauthorized'}, {
      status: 401,
      headers: {'www-authenticate': outcome.challenge},
    });
  }
  const {claims} = outcome;

  const rpc = await req.json();
  const reply = (result: unknown) =>
    Response.json({jsonrpc: '2.0', id: rpc.id ?? null, result});
  const toolError = (text: string) =>
    reply({isError: true, content: [{type: 'text', text}]});

  // 3. Advertise the step-up tool and instruction, or clients cannot find them.
  if (rpc.method === 'initialize') {
    return reply({
      protocolVersion: rpc.params?.protocolVersion ?? '2025-06-18',
      capabilities: {tools: {}},
      serverInfo: {name: 'acme', version: '1.0.0'},
      instructions: auth.decorateInstructions('Acme tools.'),
    });
  }
  if (rpc.method === 'tools/list') {
    return reply({tools: auth.mergeTools(MY_TOOLS)});
  }

  if (rpc.method === 'tools/call') {
    const name = rpc.params?.name ?? '';

    // 4. The step-up tool is handled HERE, never forwarded to your dispatch.
    if (auth.isStepUpTool(name)) {
      return reply({
        content: [{
          type: 'text',
          text: JSON.stringify(
            await auth.completeStepUp(rpc.params?.arguments ?? {}, claims),
          ),
        }],
      });
    }

    // 5. Is there a connection?
    const verdict = await auth.authorizeCall(name, claims);
    if (verdict.kind !== 'allow') return toolError(verdict.message);

    // 6. Does that connection carry the scope? SEPARATE CHECK.
    const need = SCOPES[name];
    if (need && !(await auth.hasScope(claims, need))) {
      return toolError(`insufficient_scope: this connection lacks \`${need}\``);
    }

    return reply(await runMyTool(name, rpc.params?.arguments, claims));
  }

  return reply({});
}
```

**Steps 5 and 6 are independent.** Wiring only step 5 gives you a server where
every tool is reachable by anyone who registered, regardless of what the user
agreed to — and it looks correct, because calls are refused before registration
and allowed after.

## Using the official MCP SDK

### One call for the whole server

If you have an existing server and do not want to touch every tool:

```ts
import {createLaneMcpAuth} from '@getonlane/mcp-auth';
import {enableLaneAuth, toAuthInfo} from '@getonlane/mcp-auth/mcp-sdk';

const auth = createLaneMcpAuth({resource, connections, exchanger});

enableLaneAuth(mcp, auth, {scopes: {place_order: 'email'}});

// ...then register tools exactly as you already do. Every one is gated.
mcp.registerTool('place_order', {description, inputSchema: {}}, placeOrder);
```

Python is the same shape:

```python
from lane_mcp_auth.fastmcp import enable_lane_auth

enable_lane_auth(mcp, auth, scopes={"place_order": "email"})

@mcp.tool()
async def place_order(ctx) -> str: ...
```

**Call it before your tools**, the way `app.use(cors())` goes above the routes.
It wraps the registration function, so what it guards is what is registered
*afterwards* — and a tool registered earlier would be silently ungated, which is
the one outcome worth refusing rather than documenting. If tools already exist
it throws and names them.

Every way your framework lets you declare a tool is covered: `registerTool` and
the older `tool()` on the TypeScript SDK, and `@mcp.tool`, `@mcp.tool()` and
`@mcp.tool("name")` on FastMCP. Scopes are keyed by the name the tool is
**registered** under, which is the explicit one when you pass it.

The scope **map** rather than a decorator per tool is deliberate: the two gate
layers must not be separately rememberable. Declaring authority as data, in one
place, leaves the "wired the connection check, forgot the scope check" state
nowhere to live — there is no second call site to forget.

You still wire the HTTP hop yourself (below): the library cannot know where your
server terminates a request.

### Per-tool, when you want the scope beside the handler

If your server is built on `@modelcontextprotocol/sdk` directly, register
through the adapter instead of routing by hand:

```ts
import {createLaneMcpAuth} from '@getonlane/mcp-auth';
import {
  registerGuardedTool,
  registerStepUpTool,
  toAuthInfo,
} from '@getonlane/mcp-auth/mcp-sdk';

const auth = createLaneMcpAuth({resource, connections, exchanger});

registerStepUpTool(server, auth);

registerGuardedTool(
  server,
  auth,
  {
    name: 'read_orders',
    description: 'Read the customer orders.',
    inputSchema: {},                        // `{}` = no arguments
    // A scope Lane issues. Merchant-namespaced scopes need the host claim --
    // see "Which scopes exist". Omit entirely if a connection is enough.
    scope: 'email',
  },
  async () => ({content: [{type: 'text', text: await readOrders()}]}),
);
```

At the HTTP layer, verify the bearer and hand the SDK an `AuthInfo`:

```ts
const outcome = await auth.authenticate(bearer);
if (outcome.kind !== 'ok') return challenge401(outcome.challenge);
req.auth = toAuthInfo(outcome.claims);   // StreamableHTTPServerTransport reads this
```

**The schema is required, and `{}` is the answer for a tool with no arguments.**
Omitting it is what the SDK reads as "no inputs": it discards whatever the caller
sent *and* changes your handler's arity. Requiring it turns a mistake that
produces a baffling refusal into one the type checker states.

Registration, schema and required scope are one declaration per tool, so a tool
cannot end up guarded-but-unscoped — there is no second call site to forget.

`toAuthInfo` puts the token's own scopes in `AuthInfo.scopes` — empty before the
step-up — and carries the real authority in `extra`, so the SDK's own scope
checks cannot be made to pass on a grant it knows nothing about.

### Three tiers, and registration is the floor

| tier | reached by | declare it |
|---|---|---|
| authenticated only | — | **not registrable.** No variant skips the connection |
| any connected caller | completing the step-up | omit `scope` |
| a specific authority | the step-up granting that scope | `scope: '…'` |

Omitting `scope` means **any connected caller, never anyone**. Registration is
the floor: every tool requires a completed step-up, and dropping the scope
removes only the second check.

There is deliberately no way to register a tool reachable on a bare token. A
session that has not registered has nothing anyone can revoke, so a tool
answering it would be answering something nobody can withdraw — and the point of
exchanging rather than trusting a signed claim is that an exchange can be
refused.

For the catalog-before-consent case, register the tool with no scope. The
step-up costs one tool call and no human, so "look before you consent" is one
round trip rather than an exemption.

> The floor holds under `'gate-all'`, the default. `{allow: [...]}` and
> `'log-only'` suspend it on purpose — they exist so an operator can adopt the
> gate incrementally, and a rollout that refused everything on day one is a
> rollout nobody completes. Both are stages, not destinations.

`guardTool` and `stepUpTool` remain exported for a server that must own its own
registration; `registerGuardedTool` is the supported path.

The SDK subpath needs `zod`, which the SDK itself already requires. The core
package has no such dependency.

### On mcp-use

`mcp-use` sits on the SDK but does not look like it, so it has its own
entrypoint — and a different shape. `withLaneAuth` wraps an ALREADY-BUILT
server, whatever order it was built in, and returns the same instance:

```ts
import {withLaneAuth} from '@getonlane/mcp-auth/mcp-use';

const server = new MCPServer({name, version, instructions});
server.tool({name: 'place_order', schema: {sku: z.string()}}, placeOrder);

withLaneAuth(server, auth, {scopes: {place_order: 'email'}});

// Late registrations are gated too.
server.tool({name: 'search', schema: {q: z.string()}}, search);
```

One call does everything the adapter used to spread over three: it rewrites
every existing tool, prompt and resource handler with the guarded version and
patches the registration methods for late ones; registers the step-up tool,
`lane_session_info` and a public auth-guide resource; appends the step-up
instruction to `initialize`; serves the RFC 9728 document (plus a 404 on other
`/.well-known/*` paths, which mcp-use's SPA catch-all would otherwise answer
`200 text/html` and break OAuth discovery); answers an unauthenticated
`tools/call` with `401 + WWW-Authenticate`; and narrows the anonymous
`tools/list` to the reserved tools. Each piece is one field of the options
object:

```ts
withLaneAuth(server, auth, {
  scopes: {},                        // per-tool scope requirements
  public: {prompts: [], resources: []},  // gate EXEMPTIONS — authorization
  anonymousToolList: 'step-up-only', // 'full' | {include: [...]} — VISIBILITY
  challengeUnauthenticatedCalls: true,
  wellKnown: {notFoundCatchAll: true},   // or false to serve your own
  authGuide: true,                   // or {append: '...'} | false
  sessionInfoTool: true,
});
```

`public` and `anonymousToolList` are different axes and must not be conflated:
`public` exempts a prompt or resource from the CONNECTION GATE (the only good
reason is content that explains how to authenticate), while `anonymousToolList`
only controls what an UNVERIFIED caller sees in `tools/list` — every hidden
tool is still gated at `tools/call`, and any verified caller sees everything.
There is deliberately no `public.tools`.

Two reserved tools come registered: `lane_register_session` (the step-up) and
`lane_session_info`, which reports identity and connection state and is exempt
from the connection gate — it exists precisely for the verified caller who has
not stepped up yet. A server whose own well-known documents live under
`/.well-known/` must register them BEFORE calling `withLaneAuth`, or pass
`wellKnown: {notFoundCatchAll: false}`.

Differences from the raw SDK, all of them mcp-use's shape rather than a choice:

- The tool name lives in the definition object, and the schema key is `schema`,
  not `inputSchema`.
- The caller is found on the request context mcp-use passes each tool, which is
  a Hono context — so the bearer is read and verified there, once per request,
  and cached on that context. mcp-use's own `ctx.auth` is deliberately NOT read:
  it is another OAuth system's result, and Lane's gate verifies Lane's tokens. If
  you have already verified one yourself, put the claims on the context and this
  will use them (`claimsForContext` is exported for guarding by hand).
- A bad token on a tool call comes back as a tool RESULT; the `401` lives at the
  HTTP layer, scoped to `tools/call`, and fires only for a caller the server
  cannot identify at all. A verified caller with no connection never gets a 401,
  because a token refresh cannot fix a missing consent.

For local development there is a separate subpath, `@getonlane/mcp-auth/dev`:
`createDevAuthSeam` substitutes `verifyToken` and the exchanger so the whole
flow works with any bearer on a laptop. It is deliberately not reachable from
`withLaneAuth`'s options, must be armed explicitly (`LANE_MCP_DEV_AUTH=1`), and
refuses to arm when `NODE_ENV=production`.

Built against mcp-use 1.34.x. On a server without `registrations` and
`getServerForSession` — its 2.x line — `withLaneAuth` throws a named
`McpUseSeamMissingError` rather than gating nothing.

## Who is calling

Available from the token alone, before any step-up and without touching your
store:

```ts
const who = auth.identity(claims);
// {
//   customerId:     'a7f3…',   the end user
//   agentId:        'mcpc_…',  the agent acting for them
//   credentialId:   'jti…',    this credential specifically
//   authenticatedAt: 1755…,    when the human last authenticated
//   issuer:         'https://auth.getonlane.com/auth/mcp',
// }
```

Both ids are **opaque and stable at your server only**. `customerId` is the same
person across their sessions with you and a different value at every other
merchant, so two servers cannot join records on it. A user with two clients has
two `credentialId`s and one `customerId`.

`authenticatedAt` is when the human actually authenticated — a token refresh does
not move it — so it is the field to use for a freshness policy on a sensitive
tool.

## What they agreed to

```ts
const session = await auth.session(claims);
if (!session) return toolError('not connected');

session.scopes;        // ['openid', 'email'] — granted at the exchange
session.task;          // the caller's own summary, if consent allowed one
session.connectedAt;   // ms since epoch
session.expiresAt;     // seconds since epoch, if the grant expires
session.identity;      // the same shape as above
```

`session()` returns `null` before the step-up. `task` is **absent** rather than
empty when the user declined to have model-authored text recorded — check with
`in` or optional chaining, not truthiness on an empty string.

For a single check, `hasScope(claims, 'email')` avoids loading the record.

## Which scopes exist

> The three tiers a tool can sit in — and why there is no ungated tier — are in
> [the gate](https://docs.getonlane.com/sell/mcp-auth/the-gate).

**You cannot invent one.** A connection's scopes are exactly what the
authorization server returned from the exchange, and it issues only from a fixed
set:

`mcp` · `offline_access` · `openid` · `profile` · `email` · `phone`

A client asking for anything else has it **silently dropped** at `/authorize` —
`scope=openid email orders:read` grants `openid email`, and a request for only
unknown scopes falls back to `mcp`. So `hasScope(claims, 'orders:read')` is
permanently `false`, and a tool gated on it can never run.

`mcp` is additionally stripped for a merchant audience, so a connection at your
server can hold: `offline_access`, `openid`, `profile`, `email`, `phone`.

That your server cannot widen its own grant is the point — it is the party the
grant is enforced against.

**Tool permissions are namespaced to your host.** The authorization server also
issues `<your-host>/<name>` for the host of your `resource`, and the consent
screen renders `read`, `purchase` and `manage` in the user's words ("Make
purchases at shop.example"). Gate a tool on the full string,
`shop.example/purchase`, never on the bare name: a bare name is dropped at
`/authorize`, so `hasScope` for it is permanently `false`.

**Advertise what a host should ask for.** A client requests the
`scopes_supported` your protected-resource document lists, and the consent
screen offers exactly that. Set `scopesSupported` to Lane's identity scopes
plus every tool permission you gate on; the default names only the identity
scopes, so a tool gated on a permission you did not advertise is refused for
every host.

## The two things you provide

> Walked through step by step, with the `(sub, jti)` keying rule and why it
> matters, in the [quickstart](https://docs.getonlane.com/sell/mcp-auth/quickstart).

### `ConnectionStore`

Where grants live. Injected because it is server-side state that one service
owns — two replicas with in-memory stores give two answers to "is this
credential connected?".

```ts
const connections: ConnectionStore = {
  async get({sub, jti}) {
    return db.connections.findOne({sub, jti});      // strongly consistent read
  },
  async put({sub, jti}, value) {
    const row = {...value, sub, jti, createdAt: Date.now()};
    await db.connections.upsert(row);
    return row;
  },
};
```

Key on **both** `sub` and `jti`. Keying on `sub` alone makes one registration
cover every credential that user ever holds, including one issued to a different
client.

`value.accessToken` may be present and is a live credential — store it encrypted
or drop it if your server never calls Lane on the user's behalf.

### `TokenExchanger`

Use the one that ships:

```ts
import {createTokenExchanger} from '@getonlane/mcp-auth';

const exchanger = createTokenExchanger({
  clientId: process.env.LANE_CLIENT_ID!,
  clientSecret: process.env.LANE_CLIENT_SECRET!,
});
```

It must be a **confidential** client — Lane refuses the exchange to a public one,
and this throws at construction rather than on your first step-up.

It sends no `scope` parameter deliberately: the authorization server returns what
the user consented to, and a resource server does not shape the grant it is
subject to. It times out rather than hanging a tool call, and its errors carry
the OAuth error code but never the bearer or your secret.

Implement `TokenExchanger` yourself only if you need a different transport.

## Configuration

> Every field, both languages, side by side: [reference](https://docs.getonlane.com/sell/mcp-auth/reference).

| option | required | default | notes |
|---|---|---|---|
| `resource` | yes | — | your public MCP URL; the `aud` of your tokens |
| `connections` | yes | — | see above |
| `exchanger` | yes | — | see above |
| `enforcement` | no | `'gate-all'` | `'gate-all'` · `{allow: [...]}` · `'log-only'` |

In Python the same three, with `{"allow": [...]}` accepted as written above and
a plain list (`["place_order"]`) as the shorter equivalent.
| `auth` | no | `{mode: 'lane'}` | `{mode: 'federated', upstream: 'authkit'}` to surface upstream identity |
| `issuer` | no | Lane production | |
| `additionalIssuers` | no | — | accept during a migration; the challenge still advertises `issuer` |
| `scopesSupported` | no | `openid profile email offline_access` | advertised in the protected-resource document; add your `<host>/<name>` tool permissions |
| `canonicalResource` | no | Lane's | what an incoming bearer is verified against — see below |
| `verifyToken` | no | remote JWKS | test seam |

### Rolling out

Start with `'log-only'` plus a sink, or the mode decides in silence:

```ts
createLaneMcpAuth({
  enforcement: 'log-only',
  onGateEvent: (e) => {
    // e.decision: 'allowed' | 'blocked' | 'would-have-blocked'
    log.info({tool: e.tool, decision: e.decision, agent: e.identity.agentId});
  },
  ...
});
```

Watch `would-have-blocked` until it is only callers you expect to be refused.
Then `{allow: ['place_order']}` to bind your write path, then `'gate-all'`.

The event carries `identity`, never the claims — the raw bearer is not handed to
a log sink. A throwing sink cannot fail a tool call, and the step-up tool is not
reported, since it is the way *out* of the gate.

## What a caller sees

| situation | response |
|---|---|
| no or bad token | HTTP 401 + `WWW-Authenticate` |
| valid token, no connection | HTTP 200, tool-result error naming `lane_register_session` |
| connection without the scope | HTTP 200, tool-result error naming the scope |

The middle case is **not** a 401, and that matters: MCP clients read 401 as "my
token is stale", silently refresh, and eventually tell the user to log in again —
which cannot fix a missing consent. Agents follow instructive tool errors
reliably, so that is the channel used to steer them.

## Verifying your integration

In order. Steps 2, 6 and 7 are the ones that catch real mistakes:

1. Call a tool with no bearer → 401 with `WWW-Authenticate`.
2. **Fetch the URL that header names** → the document, not a 404.
3. Call a tool with a valid bearer, before the step-up → refused, naming
   `lane_register_session`.
4. Call `lane_register_session` → succeeds, reports scopes.
5. Call the tool again → succeeds.
6. **Call a tool needing a scope the connection lacks** → refused, naming the
   scope. If this passes, step 6 above is missing.
7. **Call with a malformed body and a bad bearer** → 401, not a parse error.

A suite covering only 1, 3, 4 and 5 passes against a broken server.

## Notes on two design points

**Never authorize on `claims.scopes`.** It is the token's own claim: empty before
the step-up, stale after. Authority lives in the connection because Lane decides
it at exchange time and can refuse an exchange it would previously have allowed.
A signed claim cannot be withdrawn.

**Why the audience is Lane's, not yours.** Incoming bearers are verified against
`canonicalResource` as well as your `resource`, because a client that did not
name a `resource` at `/authorize` holds a token audienced to Lane, and pinning
only yours would reject it. Such a token carries no scopes and authorizes
nothing — but it does mean per-server consent rests on the step-up rather than on
`aud`. A client that names `resource` keeps the stronger binding.

## Standards

RFC 9728 · RFC 8693 · RFC 9068 · RFC 6750 · OAuth 2.1

Integrating with a coding agent: see [AGENTS.md](./AGENTS.md).

## Licence

MIT
