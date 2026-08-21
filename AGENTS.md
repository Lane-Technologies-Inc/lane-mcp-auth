# Integrating `@getonlane/mcp-auth`

Instructions for a coding agent wiring this library into an MCP server. Read all
of it before writing code: the failure modes below are not hypothetical, they are
the ones that have actually happened, and most of them produce a server that
looks like it works.

## What this is

An OAuth 2.1 resource server plus a **connection gate** for an MCP server that
sits behind Lane's authorization server. It verifies bearer tokens, publishes the
RFC 9728 protected-resource document, and refuses every tool until the caller has
completed a **step-up** — an RFC 8693 exchange performed server-side that turns a
scopeless token into recorded authority.

Transport-agnostic on purpose. It hands you strings and verdicts; you own the
routing.

## The integration, in full

Every one of these is required. A server missing any of them is broken in a way
that passes a smoke test.

1. **Serve the protected-resource document at BOTH paths.**
   `metadataPaths()` returns `{root, derived}`. RFC 9728 §3.1 puts the document
   for a resource at `/mcp` under `/.well-known/oauth-protected-resource/mcp`,
   and `challenge()` advertises that derived URL. Serving only the root gives a
   client a challenge pointing at a path you do not answer.

2. **Return `challenge()` verbatim on a 401.** Do not build the
   `WWW-Authenticate` value yourself. If you hand-roll it, it will name a
   different URL than `metadataPaths()` serves — they will agree for a client
   arriving with no bearer and diverge for one arriving with a bad bearer, which
   is the worst possible split because the happy path keeps working.

3. **Authenticate BEFORE you parse the request body.** A body-parse failure must
   not be answerable without a verified bearer.

4. **Gate every tool on `authorizeCall(toolName, claims)`** except the step-up
   tool itself. Gating that one is a deadlock with no exit.

5. **Handle the step-up tool** by calling `completeStepUp(args, claims)` and
   returning its result. Never forward it to your own tool dispatch.

6. **Check scopes separately with `hasScope(claims, scope)`.** See below — this
   is the step most integrations skip.

7. **Advertise the step-up tool and instruction** via `mergeTools()` and
   `decorateInstructions()`, or a client has no way to discover the way out.
   On the official SDK, `registerStepUpTool()` does this for you.

## The two-layer gate, which is the thing to get right

`authorizeCall` answers *"is there a connection?"*. `hasScope` answers *"does
that connection carry this authority?"*. They are independent, and an integrator
who wires only the first gets a server where **every tool is reachable by anyone
who completed the step-up**, regardless of what the user consented to.

That failure is invisible: the gate visibly refuses calls before registration and
visibly allows them after, so it looks correct from the outside.

```ts
const verdict = await auth.authorizeCall(name, claims);
if (verdict.kind !== 'allow') return toolError(verdict.message);

// SEPARATE. Layer one said a connection exists; it said nothing about scopes.
if (SCOPE_FOR[name] && !(await auth.hasScope(claims, SCOPE_FOR[name]))) {
  return toolError(`insufficient_scope: this connection lacks ${SCOPE_FOR[name]}`);
}
```

## Never read authority off the token

`claims.scopes` is the token's own `scope` claim. It is **empty before the
step-up and stale after it**. Authority lives in the connection record, reachable
only through `effectiveScopes()` / `hasScope()`, because the authorization server
decides it at the exchange and can refuse an exchange it would previously have
allowed. A claim cannot be withdrawn; an exchange can.

If you find yourself reading `claims.scopes` to make a decision, you have
reintroduced the problem this library exists to solve.

## What you must inject

- **`ConnectionStore`** — server-side state, one implementation per service.
  Never in-memory in a multi-replica deployment: two replicas would give two
  answers to "is this credential connected?". Keyed on `{sub, jti}`.
- **`TokenExchanger`** — performs the exchange against Lane's `/token`. Must
  authenticate as a **confidential** client; the exchange grant refuses a public
  one, because a caller who could swap their own bearer for a scoped one would
  make the step-up decorative.

## Things that look like bugs and are not

- **A step-down token authorizes nothing.** That is its entire purpose. It exists
  to start a session.
- **The step-up is per credential.** A new token needs a new `lane_register_session`
  even though the user's consent persists. The connection is keyed on `jti`.
- **A 401 names nothing specific.** Every verification failure — bad signature,
  wrong issuer, wrong audience, expired — collapses to one answer. Telling a
  caller which check failed walks them toward a token you would accept.
- **`mergeTools()` is idempotent.** Calling it twice does not duplicate the
  tool.

## Verifying your integration

Do not trust a passing connection test. In order:

1. Call any tool with **no** bearer → 401 carrying `WWW-Authenticate`.
2. Fetch the URL that header names → the document, not a 404.
3. Call a tool with a **valid** bearer, before the step-up → refused, and the
   refusal names `lane_register_session`.
4. Call `lane_register_session` → succeeds, reports scopes.
5. Call the same tool again → succeeds.
6. Call a tool needing a scope the connection does **not** hold → refused,
   naming the scope. **If this passes, step 6 is the one you skipped.**
7. Call a tool with a **malformed body** and a bad bearer → 401, not a
   parse error.

Steps 2, 6 and 7 are the ones that catch the mistakes above. A test suite that
covers 1, 3, 4 and 5 will pass against a broken server.
