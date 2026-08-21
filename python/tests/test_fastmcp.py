"""`enable_lane_auth` must gate every tool, however it was declared.

`FastMCP.tool` is `tool(name_or_fn=None, *, name=None, ...)`, so it is three
decorators wearing one name. Handling only `@mcp.tool()` left `@mcp.tool`
registered with no gate at all and `@mcp.tool("name")` resolving its scope
under `fn.__name__`, which no scope map is keyed by.
"""

from __future__ import annotations

import pytest

from lane_mcp_auth import (
    ConnectionKey,
    ConnectionRecord,
    ExchangedToken,
    LaneMcpAuth,
    VerifiedClaims,
)

fastmcp = pytest.importorskip("fastmcp")
from lane_mcp_auth.fastmcp import enable_lane_auth, guarded


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], ConnectionRecord] = {}

    async def get(self, key: ConnectionKey):
        return self.rows.get((key.sub, key.jti))

    async def put(self, key: ConnectionKey, record: ConnectionRecord):
        self.rows[(key.sub, key.jti)] = record
        return record


class StubExchanger:
    async def exchange(self, *, subject_token: str, resource: str) -> ExchangedToken:
        return ExchangedToken("exchanged", [])


CLAIMS = VerifiedClaims(
    sub="user-1", jti="tok-1", client_id="agent-1", token="raw",
    exp=4_000_000_000, iss="https://auth.getonlane.com/auth/mcp",
)


class Ctx:
    """Stands in for a FastMCP context carrying verified claims."""

    def __init__(self, claims: VerifiedClaims | None = None) -> None:
        self.lane_claims = claims


def build_server(*, connected_scopes: list[str] | None = None):
    store = MemoryStore()
    if connected_scopes is not None:
        store.rows[(CLAIMS.sub, CLAIMS.jti)] = ConnectionRecord(
            scopes=list(connected_scopes), created_at=0
        )
    auth = LaneMcpAuth(
        resource="https://acme.example/mcp",
        connections=store,
        exchanger=StubExchanger(),
    )
    mcp = fastmcp.FastMCP("test")
    enable_lane_auth(mcp, auth, scopes={"place_order": "payments:write"})
    return mcp


async def test_every_decorator_form_is_gated() -> None:
    mcp = build_server()

    @mcp.tool
    async def bare(ctx=None) -> str:
        return "RAN UNGUARDED"

    @mcp.tool()
    async def called(ctx=None) -> str:
        return "RAN UNGUARDED"

    @mcp.tool("place_order")
    async def positional_name(ctx=None) -> str:
        return "RAN UNGUARDED"

    for form, fn in (("@mcp.tool", bare), ("@mcp.tool()", called), ('@mcp.tool("n")', positional_name)):
        result = await fn()
        assert "RAN UNGUARDED" not in str(result), f"{form} bypassed the gate"
        assert "unauthorized" in str(result), f"{form} refused for the wrong reason"


async def test_scope_binds_to_the_registered_name_not_the_function_name() -> None:
    """The scope map is keyed by the REGISTERED name. Reading `fn.__name__`
    instead makes the two disagree, and a scope that never resolves is a scope
    that never refuses -- the caller is connected, so the tool just runs.
    """
    # Connected, but WITHOUT the scope `place_order` demands.
    mcp = build_server(connected_scopes=[])

    @mcp.tool("place_order")
    async def _some_other_handler_name(ctx=None) -> str:
        return "RAN WITHOUT THE SCOPE"

    result = str(await _some_other_handler_name(ctx=Ctx(CLAIMS)))
    assert "RAN WITHOUT THE SCOPE" not in result
    assert "insufficient_scope" in result
    assert "payments:write" in result

    names = {t.name for t in await mcp._list_tools()}
    assert "place_order" in names and "_some_other_handler_name" not in names


async def test_scope_is_satisfied_when_the_connection_carries_it() -> None:
    """The other half: the gate must not refuse a caller that DOES hold it."""
    mcp = build_server(connected_scopes=["payments:write"])

    @mcp.tool("place_order")
    async def _handler(ctx=None) -> str:
        return "ordered"

    assert str(await _handler(ctx=Ctx(CLAIMS))) == "ordered"


def test_declaring_tools_before_the_call_is_refused() -> None:
    """The ordering guard read only FastMCP 2.x's registry, so on 3.x it saw
    no tools and let a late call through -- leaving everything above it open.
    """
    auth = LaneMcpAuth(
        resource="https://acme.example/mcp",
        connections=MemoryStore(),
        exchanger=StubExchanger(),
    )
    mcp = fastmcp.FastMCP("test")

    @mcp.tool
    async def declared_too_early(ctx=None) -> str:
        return "ungated"

    with pytest.raises(RuntimeError, match="declared_too_early"):
        enable_lane_auth(mcp, auth)


async def test_step_up_tool_is_registered_and_not_gated() -> None:
    """Guarding the way out of the gate would make the gate unescapable."""
    mcp = build_server()
    names = {t.name for t in await mcp._list_tools()}
    assert "lane_register_session" in names



@pytest.mark.anyio
async def test_get_claims_seam_finds_a_caller_the_framework_does_not_pass() -> None:
    """Python has had this since it shipped; TypeScript gained it later.

    A framework that calls a tool with the arguments only -- mcp-use is the one
    that forced this -- leaves `claims_from` nothing to read, so the guard sees
    no caller and refuses every call. `get_claims` is the seam that lets an
    adapter supply the caller from a request-scoped store instead.
    """
    store = MemoryStore()
    store.rows[(CLAIMS.sub, CLAIMS.jti)] = ConnectionRecord(scopes=["payments:write"], created_at=0)
    auth = LaneMcpAuth(
        resource="https://acme.example/mcp", connections=store, exchanger=StubExchanger()
    )

    async def handler(sku: str) -> str:
        return f"ORDERED {sku}"

    # No ctx argument at all, the way a framework without `extra` calls it.
    default = guarded(auth, "place_order")(handler)
    assert "unauthorized" in str(await default(sku="x"))

    seamed = guarded(auth, "place_order", get_claims=lambda *a, **k: CLAIMS)(handler)
    assert await seamed(sku="x") == "ORDERED x"

    # The scope layer still applies through the seam.
    scoped = guarded(auth, "place_order", scope="admin:all", get_claims=lambda *a, **k: CLAIMS)(
        handler
    )
    assert "insufficient_scope" in str(await scoped(sku="x"))
