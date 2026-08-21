# lane-mcp-auth

OAuth 2.1 resource server and consent gate for an MCP server behind Lane — the
Python distribution of [`@getonlane/mcp-auth`](../README.md).

**Docs** — [overview](https://docs.getonlane.com/sell/mcp-auth/overview) · [quickstart](https://docs.getonlane.com/sell/mcp-auth/quickstart) · [the gate](https://docs.getonlane.com/sell/mcp-auth/the-gate) · [reference](https://docs.getonlane.com/sell/mcp-auth/reference)

```sh
pip install lane-mcp-auth          # core
pip install 'lane-mcp-auth[fastmcp]'   # + the FastMCP helpers
```

Your server verifies bearer tokens, publishes the discovery document clients
need, and refuses every tool until the caller holds a recorded, revocable grant.

```python
from lane_mcp_auth import LaneMcpAuth

auth = LaneMcpAuth(
    resource="https://acme.example/mcp",
    connections=connections,   # yours: this is server-side state
    exchanger=exchanger,
)
```

## The three tiers

| tier | reached by | declared |
|---|---|---|
| authenticated only | — | **not registrable** |
| any connected caller | completing the step-up | no scope |
| a specific authority | the step-up granting it | `scope="…"` |

Registration is the floor. Omitting a scope means *any connected caller*, never
*anyone*: a session that has not registered has nothing anyone can revoke, so a
tool answering it would be answering something nobody can withdraw.

## With FastMCP

```python
from lane_mcp_auth.fastmcp import register_step_up_tool, guarded

register_step_up_tool(mcp, auth)

@mcp.tool()
@guarded(auth, "read_orders", scope="email")
async def read_orders(ctx) -> str:
    return await orders_for(ctx)
```

## Never authorize on the token's scopes

`claims.scopes` is the token's own claim: empty before the step-up, stale after.
Authority lives in the connection and is reachable only through `has_scope()` /
`effective_scopes()`, because Lane decides it at exchange time and can refuse an
exchange it would previously have allowed. A signed claim cannot be withdrawn.

## Parity with the TypeScript

Same invariants, same names where Python idiom allows. The TypeScript package is
the reference implementation; where the two could drift — scope filtering, the
metadata paths, the gate's decision table — see `SCOPE.md` for what is
implemented here and what is not yet.

## Licence

MIT
