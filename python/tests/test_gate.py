"""The invariants, held identically to the TypeScript."""

from __future__ import annotations

import pytest

from lane_mcp_auth import (
    Allow,
    ConnectionKey,
    ConnectionRecord,
    ExchangedToken,
    LaneMcpAuth,
    StepUpRequired,
    VerifiedClaims,
    metadata_paths,
    sanitize_prompt,
)


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], ConnectionRecord] = {}

    async def get(self, key: ConnectionKey):
        return self.rows.get((key.sub, key.jti))

    async def put(self, key: ConnectionKey, record: ConnectionRecord):
        self.rows[(key.sub, key.jti)] = record
        return record

    async def delete(self, key: ConnectionKey) -> None:
        self.rows.pop((key.sub, key.jti), None)


class StubExchanger:
    def __init__(self, scopes: list[str], expires_in: int | None = None) -> None:
        self.scopes, self.expires_in = scopes, expires_in
        self.seen: list[dict] = []

    async def exchange(self, *, subject_token: str, resource: str) -> ExchangedToken:
        self.seen.append({"subject_token": subject_token, "resource": resource})
        return ExchangedToken("exchanged", list(self.scopes), self.expires_in)


CLAIMS = VerifiedClaims(
    sub="user-1", jti="tok-1", client_id="agent-1", token="raw",
    exp=4_000_000_000, iss="https://auth.getonlane.com/auth/mcp",
)


def build(scopes=None, *, enforcement="gate-all", now=None, expires_in=None):
    store = MemoryStore()
    ex = StubExchanger(scopes or [], expires_in)
    auth = LaneMcpAuth(
        resource="https://acme.example/mcp",
        connections=store,
        exchanger=ex,
        enforcement=enforcement,
        now=now,
    )
    return auth, store, ex


@pytest.mark.asyncio
async def test_registration_is_the_floor():
    """No tool answers a session that has not registered -- scoped or not."""
    auth, _, _ = build()
    assert isinstance(await auth.authorize_call("anything", CLAIMS), StepUpRequired)
    assert isinstance(await auth.authorize_call("no_scope_needed", CLAIMS), StepUpRequired)


@pytest.mark.asyncio
async def test_the_step_up_itself_is_never_gated():
    """It is the way OUT of the gate; gating it is a deadlock with no exit."""
    auth, _, _ = build()
    assert isinstance(await auth.authorize_call("lane_register_session", CLAIMS), Allow)


@pytest.mark.asyncio
async def test_authority_never_comes_from_the_token():
    """The token asserts scopes; they decide nothing."""
    claims = VerifiedClaims(**{**CLAIMS.__dict__, "scopes": ("email", "admin")})
    auth, _, _ = build([])
    await auth.complete_step_up({}, claims)
    assert await auth.effective_scopes(claims) == []
    assert await auth.has_scope(claims, "email") is False


@pytest.mark.asyncio
async def test_an_expired_connection_is_no_connection():
    """In the gate AND in scope resolution, or a scope check outlives the gate."""
    auth, store, _ = build(now=lambda: 5_000_000)
    await store.put(
        ConnectionKey("user-1", "tok-1"),
        ConnectionRecord(scopes=["email"], created_at=0, expires_at=4_000),
    )
    assert isinstance(await auth.authorize_call("t", CLAIMS), StepUpRequired)
    assert await auth.effective_scopes(CLAIMS) == []
    assert await auth.session(CLAIMS) is None


@pytest.mark.asyncio
async def test_the_exchanged_token_is_stored_never_returned():
    auth, store, _ = build(["email"])
    result = await auth.complete_step_up({"task": "hi"}, CLAIMS)
    assert "exchanged" not in str(result)
    assert store.rows[("user-1", "tok-1")].access_token == "exchanged"


@pytest.mark.asyncio
async def test_the_task_is_recorded_only_with_consent():
    """Declined means declined, including for model-authored text."""
    auth, store, _ = build(["email"])
    await auth.complete_step_up({"task": "buy a keyboard"}, CLAIMS)
    assert store.rows[("user-1", "tok-1")].prompt is None

    auth2, store2, _ = build(["personalization:connection"])
    out = await auth2.complete_step_up({"task": "buy a keyboard"}, CLAIMS)
    assert store2.rows[("user-1", "tok-1")].prompt == "buy a keyboard"
    assert out["personalized"] is True


def test_metadata_paths_match_rfc9728():
    root, derived = metadata_paths("https://acme.example/mcp")
    assert root == "/.well-known/oauth-protected-resource"
    assert derived == "/.well-known/oauth-protected-resource/mcp"
    assert metadata_paths("https://acme.example")[1] is None


def test_sanitize_prompt_treats_input_as_hostile():
    assert sanitize_prompt("a\x00b\x1fc") == "a b c"
    assert len(sanitize_prompt("x" * 5000)) == 600
    assert sanitize_prompt(None) is None


# ── Regressions ───────────────────────────────────────────────────────────


def test_enforcement_rejects_a_bare_tool_name() -> None:
    """`tool in "place_order"` is substring matching, so a bare string that
    isn't a mode has to be refused rather than quietly gating by prefix."""
    with pytest.raises(ValueError, match="gate-all"):
        build(enforcement="place_order")


@pytest.mark.parametrize("bad", [True, False])
def test_expires_in_ignores_booleans(bad: bool) -> None:
    """`bool` is an `int`, so `expires_in: true` used to mean a connection
    that expired one second after the step-up created it."""
    from lane_mcp_auth.exchanger import _as_seconds

    assert _as_seconds(bad) is None


def test_types_all_exports_only_its_own_names() -> None:
    """A `dir()`-derived `__all__` re-exported `dataclass`, `Protocol` and
    friends, so `from lane_mcp_auth.types import *` leaked our imports."""
    from lane_mcp_auth import types

    for leaked in ("dataclass", "field", "Protocol", "Literal", "Collection", "Any"):
        assert leaked not in types.__all__
    assert "VerifiedClaims" in types.__all__
    assert len(types.__all__) == len(set(types.__all__))


@pytest.mark.parametrize("header", ["content-type"])
def test_exchange_posts_form_encoded(header: str, monkeypatch) -> None:
    """The body is form-encoded, so the header has to say so. Nothing asserted
    it, and a cleanup pass dropped it once without a test noticing."""
    import asyncio

    from lane_mcp_auth.exchanger import HttpTokenExchanger

    seen: dict = {}

    class FakeResponse:
        status_code = 200

        def json(self):
            return {"access_token": "a", "scope": "openid email"}

    class FakeClient:
        async def post(self, url, *, data=None, headers=None, timeout=None):
            seen["url"], seen["data"], seen["headers"] = url, data, headers
            return FakeResponse()

    ex = HttpTokenExchanger(
        client_id="rs1",
        client_secret="s3cret",
        issuer="https://as.example/auth/mcp",
        client=FakeClient(),
    )
    asyncio.run(ex.exchange(subject_token="sub", resource="https://acme.example/mcp"))

    assert seen["headers"][header] == "application/x-www-form-urlencoded"
    assert seen["headers"]["authorization"].startswith("Basic ")
    assert seen["data"]["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
