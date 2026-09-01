"""The TypeScript suite's invariants, asserted against the Python package.

Grouped and named to match `src/index.test.ts`, so a divergence between the two
implementations shows up as a missing or failing test here rather than as a
difference nobody is looking at. Tokens are real -- signed with a real key and
verified through the real PyJWT path, with only the key set injected -- so what
passes here is what a Lane-minted token would.

The TS `tool merge` block has no counterpart: on FastMCP the reserved tool is
REGISTERED (see `test_fastmcp.py`) rather than merged into a list response.
"""

from __future__ import annotations

import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from lane_mcp_auth import (
    PERSONALIZATION_CONNECTION_SCOPE,
    STEP_UP_TOOL,
    Allow,
    ConnectionKey,
    ConnectionRecord,
    ExchangedToken,
    GateEvent,
    HttpTokenExchanger,
    LaneMcpAuth,
    StepUpRequired,
    VerifiedClaims,
)

ISS = "https://auth.getonlane.com/auth/mcp"
RESOURCE = "https://acme.example/mcp"
CANONICAL = "https://app-mcp.getonlane.com"


# ── harness ───────────────────────────────────────────────────────────────


class MemoryStore:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], ConnectionRecord] = {}

    async def get(self, key: ConnectionKey):
        return self.rows.get((key.sub, key.jti))

    async def put(self, key: ConnectionKey, record: ConnectionRecord):
        self.rows[(key.sub, key.jti)] = record
        return record


class StubExchanger:
    """Records what it was asked, returns what it was told to."""

    def __init__(self, scopes: list[str] | None = None, expires_in: int | None = None) -> None:
        self.scopes = scopes if scopes is not None else []
        self.expires_in = expires_in
        self.seen: list[dict] = []

    async def exchange(self, *, subject_token: str, resource: str) -> ExchangedToken:
        self.seen.append({"subject_token": subject_token, "resource": resource})
        return ExchangedToken("exchanged-token", list(self.scopes), self.expires_in)


CLAIMS = VerifiedClaims(
    sub="user-1",
    jti="tok-1",
    client_id="agent-1",
    token="raw-bearer",
    exp=4_000_000_000,
    iss=ISS,
)


def build(
    *,
    scopes: list[str] | None = None,
    expires_in: int | None = None,
    enforcement="gate-all",
    on_gate_event=None,
    now=None,
    additional_issuers=(),
):
    store = MemoryStore()
    exchanger = StubExchanger(scopes, expires_in)
    auth = LaneMcpAuth(
        resource=RESOURCE,
        connections=store,
        exchanger=exchanger,
        enforcement=enforcement,
        on_gate_event=on_gate_event,
        additional_issuers=additional_issuers,
        now=now,
    )
    return auth, store, exchanger


def connect(store: MemoryStore, *, scopes=(), created_at=0, prompt=None, expires_at=None):
    record = ConnectionRecord(
        scopes=list(scopes), created_at=created_at, prompt=prompt, expires_at=expires_at
    )
    store.rows[(CLAIMS.sub, CLAIMS.jti)] = record
    return record


# ── real tokens, injected key set ─────────────────────────────────────────

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class _FakeSigningKey:
    def __init__(self, key) -> None:
        self.key = key


class _FakeJwks:
    """Stands in for the network JWKS fetch. The signature is still verified."""

    def __init__(self, public_key) -> None:
        self._public_key = public_key

    def get_signing_key_from_jwt(self, _token: str) -> _FakeSigningKey:
        return _FakeSigningKey(self._public_key)


def mint(
    *,
    aud: str = RESOURCE,
    iss: str = ISS,
    typ: str = "at+jwt",
    sub: str = "user-1",
    jti: str | None = "tok-1",
    scope: str | None = None,
    key=_KEY,
) -> str:
    payload = {
        "sub": sub,
        "aud": aud,
        "iss": iss,
        "exp": int(time.time()) + 600,
        "client_id": "agent-1",
    }
    if jti is not None:
        payload["jti"] = jti
    if scope is not None:
        payload["scope"] = scope
    return jwt.encode(payload, key, algorithm="RS256", headers={"typ": typ})


def with_keys(auth: LaneMcpAuth, *issuers: str, key=_KEY) -> LaneMcpAuth:
    for issuer in issuers or (ISS,):
        auth._jwks[issuer] = _FakeJwks(key.public_key())
    return auth



# ── discovery ─────────────────────────────────────────────────────────────


def test_names_this_resource_and_lane_as_its_authorization_server() -> None:
    import json

    auth, _, _ = build()
    doc = json.loads(auth.protected_resource_document())
    assert doc["resource"] == RESOURCE
    assert doc["authorization_servers"] == [ISS]
    assert doc["bearer_methods_supported"] == ["header"]
    assert doc["scopes_supported"] == ["openid", "profile", "email", "offline_access"]


def test_advertises_the_scopes_the_server_names_verbatim() -> None:
    import json

    from lane_mcp_auth.core import LaneMcpAuth

    auth = LaneMcpAuth(
        resource=RESOURCE,
        connections=MemoryStore(),
        exchanger=StubExchanger(None, None),
        scopes_supported=["openid", "email", "shop.example/purchase"],
    )
    doc = json.loads(auth.protected_resource_document())
    assert doc["scopes_supported"] == ["openid", "email", "shop.example/purchase"]


def test_challenges_with_the_derived_metadata_url() -> None:
    auth, _, _ = build()
    challenge = auth.challenge()
    assert challenge.startswith("Bearer resource_metadata=")
    # The ORIGIN of the resource, with the derived path -- not the resource URL.
    assert "https://acme.example/.well-known/oauth-protected-resource/mcp" in challenge


# ── the two failure classes never blur ────────────────────────────────────


def test_a_missing_token_is_unauthenticated() -> None:
    auth, _, _ = build()
    assert auth.authenticate(None) is None
    assert auth.authenticate("") is None


def test_a_bad_token_says_nothing_about_which_check_failed() -> None:
    """One answer for every failure. A caller learning WHICH check failed is a
    caller being walked toward a token this server would accept."""
    auth = with_keys(build()[0])
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for bad in (
        "not-a-jwt",
        mint(iss="https://evil.example"),
        mint(key=other_key),
        mint(aud="https://someone-else.example/mcp"),
    ):
        assert auth.authenticate(bad) is None


async def test_a_valid_token_with_no_connection_is_not_an_auth_failure() -> None:
    auth, _, _ = build()
    verdict = await auth.authorize_call("place_order", CLAIMS)
    assert isinstance(verdict, StepUpRequired)


async def test_the_step_up_message_tells_the_agent_exactly_what_to_do() -> None:
    auth, _, _ = build()
    verdict = await auth.authorize_call("place_order", CLAIMS)
    assert isinstance(verdict, StepUpRequired)
    assert STEP_UP_TOOL in verdict.message


# ── the gate ──────────────────────────────────────────────────────────────


async def test_binds_the_connection_to_the_credential_not_just_the_user() -> None:
    """One step-up must not cover every credential the user ever holds."""
    auth, store, _ = build()
    connect(store, scopes=["email"])

    same_user_other_credential = VerifiedClaims(
        sub=CLAIMS.sub, jti="tok-2", client_id="agent-2", token="raw", exp=CLAIMS.exp, iss=ISS
    )
    assert isinstance(await auth.authorize_call("place_order", CLAIMS), Allow)
    assert isinstance(
        await auth.authorize_call("place_order", same_user_other_credential), StepUpRequired
    )
    assert await auth.effective_scopes(same_user_other_credential) == []


async def test_log_only_refuses_nothing_but_reports_what_it_would_have_refused() -> None:
    seen: list[GateEvent] = []
    auth, _, _ = build(enforcement="log-only", on_gate_event=seen.append)

    verdict = await auth.authorize_call("place_order", CLAIMS)
    assert isinstance(verdict, Allow)
    assert verdict.would_have_blocked is True
    assert [e.decision for e in seen] == ["would-have-blocked"]


async def test_an_allowlist_gates_only_the_named_tools() -> None:
    auth, _, _ = build(enforcement=["place_order"])
    assert isinstance(await auth.authorize_call("place_order", CLAIMS), StepUpRequired)
    # Absent from the list: ungated, which is what a rollout stage means.
    assert isinstance(await auth.authorize_call("search", CLAIMS), Allow)


# ── consent is mechanical ─────────────────────────────────────────────────


async def test_without_the_scope_the_step_up_still_succeeds_and_records_nothing() -> None:
    auth, store, _ = build(scopes=["email"])
    result = await auth.complete_step_up({"task": "buy running shoes"}, CLAIMS)

    assert result["ok"] is True
    assert result["personalized"] is False
    assert store.rows[(CLAIMS.sub, CLAIMS.jti)].prompt is None


async def test_ignores_a_non_string_task_rather_than_trusting_it() -> None:
    auth, store, _ = build(scopes=[PERSONALIZATION_CONNECTION_SCOPE])
    for hostile in ({"nested": "object"}, ["a", "list"], 42, True, None):
        await auth.complete_step_up({"task": hostile}, CLAIMS)
        assert store.rows[(CLAIMS.sub, CLAIMS.jti)].prompt is None


# ── authority comes from the exchange, not the token ──────────────────────


async def test_exchanges_the_step_down_token_server_side_at_the_step_up() -> None:
    auth, _, exchanger = build(scopes=["email"])
    await auth.complete_step_up({}, CLAIMS)

    assert exchanger.seen == [{"subject_token": CLAIMS.token, "resource": RESOURCE}]


async def test_stores_the_granted_authority_and_it_is_what_effective_scopes_reports() -> None:
    auth, _, _ = build(scopes=["email", "orders:read"])
    await auth.complete_step_up({}, CLAIMS)

    assert await auth.effective_scopes(CLAIMS) == ["email", "orders:read"]
    assert await auth.has_scope(CLAIMS, "orders:read") is True
    assert await auth.has_scope(CLAIMS, "payments:write") is False


async def test_records_when_the_granted_authority_expires() -> None:
    fixed_ms = 1_700_000_000_000
    auth, store, _ = build(scopes=["email"], expires_in=3600, now=lambda: fixed_ms)
    await auth.complete_step_up({}, CLAIMS)

    record = store.rows[(CLAIMS.sub, CLAIMS.jti)]
    assert record.expires_at == int(fixed_ms / 1000) + 3600


# ── which audience an incoming bearer is verified against ─────────────────


def test_accepts_the_step_down_token_a_caller_actually_holds() -> None:
    """Lane's own audience, which is what a client gets before it knows to ask
    for this server's."""
    auth = with_keys(build()[0])
    claims = auth.authenticate(mint(aud=CANONICAL))
    assert claims is not None
    assert claims.sub == "user-1"


async def test_grants_nothing_on_the_strength_of_it() -> None:
    auth = with_keys(build()[0])
    claims = auth.authenticate(mint(aud=CANONICAL, scope="email orders:read"))
    assert claims is not None
    # Verified, and still refused: verification is not authorization.
    assert isinstance(await auth.authorize_call("place_order", claims), StepUpRequired)
    assert await auth.effective_scopes(claims) == []


def test_still_refuses_a_token_from_another_issuer() -> None:
    auth = with_keys(build()[0])
    assert auth.authenticate(mint(iss="https://evil.example")) is None


# ── identity and session ──────────────────────────────────────────────────


def test_reports_who_is_calling_before_any_step_up() -> None:
    auth, _, _ = build()
    identity = auth.identity(CLAIMS)
    assert identity.customer_id == CLAIMS.sub
    assert identity.agent_id == CLAIMS.client_id
    assert identity.credential_id == CLAIMS.jti
    assert identity.issuer == ISS


def test_separates_the_credential_from_the_user() -> None:
    auth, _, _ = build()
    other = VerifiedClaims(
        sub=CLAIMS.sub, jti="tok-2", client_id="agent-2", token="raw", exp=CLAIMS.exp, iss=ISS
    )
    a, b = auth.identity(CLAIMS), auth.identity(other)
    assert a.customer_id == b.customer_id
    assert a.credential_id != b.credential_id
    assert a.agent_id != b.agent_id


async def test_has_no_session_until_the_step_up() -> None:
    auth, _, _ = build()
    assert await auth.session(CLAIMS) is None


async def test_reports_scopes_task_and_connection_time_once_connected() -> None:
    auth, store, _ = build()
    connect(store, scopes=["email"], created_at=1_700_000_000_000, prompt="buy shoes")

    session = await auth.session(CLAIMS)
    assert session is not None
    assert session.scopes == ["email"]
    assert session.task == "buy shoes"
    assert session.connected_at == 1_700_000_000_000
    assert session.identity.customer_id == CLAIMS.sub


async def test_omits_the_task_when_consent_did_not_allow_recording_one() -> None:
    auth, store, _ = build()
    connect(store, scopes=["email"], prompt=None)

    session = await auth.session(CLAIMS)
    assert session is not None
    assert session.task is None


# ── HttpTokenExchanger ────────────────────────────────────────────────────


class _Recorder:
    """An httpx-shaped client that records the call and replies as told."""

    def __init__(self, status: int = 200, body: object = None, raises: Exception | None = None):
        self.status, self.body, self.raises = status, body or {}, raises
        self.seen: dict = {}

    async def post(self, url, *, data=None, headers=None, timeout=None):
        self.seen = {"url": url, "data": data, "headers": headers, "timeout": timeout}
        if self.raises:
            raise self.raises
        recorder = self

        class Response:
            status_code = recorder.status

            def json(self):
                return recorder.body

        return Response()


def test_refuses_to_exist_without_a_confidential_credential() -> None:
    with pytest.raises(ValueError, match="required"):
        HttpTokenExchanger(client_id="rs1", client_secret="")


async def test_sends_no_scope_because_a_resource_server_does_not_shape_its_grant() -> None:
    client = _Recorder(body={"access_token": "a", "scope": "openid email"})
    ex = HttpTokenExchanger(
        client_id="rs1", client_secret="s3cret", issuer="https://as.example/auth/mcp", client=client
    )
    await ex.exchange(subject_token="sub", resource=RESOURCE)

    assert "scope" not in client.seen["data"]
    assert client.seen["url"] == "https://as.example/auth/mcp/token"


async def test_treats_an_absent_scope_as_none_never_as_everything() -> None:
    client = _Recorder(body={"access_token": "a"})
    ex = HttpTokenExchanger(client_id="rs1", client_secret="s3cret", client=client)
    granted = await ex.exchange(subject_token="sub", resource=RESOURCE)
    assert granted.scopes == []


async def test_never_puts_the_credential_or_the_bearer_in_an_error() -> None:
    """The request carried both a bearer AND a client secret."""
    for client in (
        _Recorder(status=400, body={"error": "invalid_grant"}),
        _Recorder(raises=OSError("connect failed")),
        _Recorder(body={"no_token": True}),
    ):
        ex = HttpTokenExchanger(
            client_id="rs1", client_secret="sup3r-s3cret", client=client
        )
        with pytest.raises(RuntimeError) as caught:
            await ex.exchange(subject_token="the-users-bearer", resource=RESOURCE)
        message = str(caught.value)
        assert "sup3r-s3cret" not in message
        assert "the-users-bearer" not in message


async def test_fails_rather_than_hanging_the_step_up() -> None:
    client = _Recorder(raises=TimeoutError("timed out"))
    ex = HttpTokenExchanger(client_id="rs1", client_secret="s3cret", client=client, timeout=0.5)
    with pytest.raises(RuntimeError, match="could not reach"):
        await ex.exchange(subject_token="sub", resource=RESOURCE)
    assert client.seen["timeout"] == 0.5


# ── on_gate_event ─────────────────────────────────────────────────────────


async def test_reports_a_real_refusal_and_an_allow_with_the_scopes_behind_it() -> None:
    seen: list[GateEvent] = []
    auth, store, _ = build(on_gate_event=seen.append)

    await auth.authorize_call("place_order", CLAIMS)
    connect(store, scopes=["email"])
    await auth.authorize_call("place_order", CLAIMS)

    assert [e.decision for e in seen] == ["blocked", "allowed"]
    assert seen[0].scopes == []
    assert seen[1].scopes == ["email"]
    assert seen[1].tool == "place_order"


async def test_never_hands_the_raw_bearer_to_the_sink() -> None:
    seen: list[GateEvent] = []
    auth, _, _ = build(on_gate_event=seen.append)
    await auth.authorize_call("place_order", CLAIMS)

    assert CLAIMS.token not in repr(seen[0])
    # It carries an Identity, never the claims that hold the credential.
    assert not hasattr(seen[0].identity, "token")


async def test_does_not_let_a_throwing_sink_fail_the_call() -> None:
    def explode(_event: GateEvent) -> None:
        raise RuntimeError("sink is down")

    auth, store, _ = build(on_gate_event=explode)
    connect(store, scopes=["email"])
    assert isinstance(await auth.authorize_call("place_order", CLAIMS), Allow)


async def test_says_nothing_about_the_step_up_tool() -> None:
    """It is the way OUT of the gate, so it is not a gate decision."""
    seen: list[GateEvent] = []
    auth, _, _ = build(on_gate_event=seen.append)
    await auth.authorize_call(STEP_UP_TOOL, CLAIMS)
    assert seen == []


# ── an expired connection ─────────────────────────────────────────────────


async def test_expired_carries_no_scopes_so_has_scope_cannot_outlive_the_gate() -> None:
    now_ms = 1_700_000_000_000
    auth, store, _ = build(now=lambda: now_ms)
    connect(store, scopes=["email"], expires_at=int(now_ms / 1000) - 1)

    assert await auth.effective_scopes(CLAIMS) == []
    assert await auth.has_scope(CLAIMS, "email") is False
    assert await auth.session(CLAIMS) is None


async def test_is_still_live_one_second_before_it_expires() -> None:
    now_ms = 1_700_000_000_000
    auth, store, _ = build(now=lambda: now_ms)
    connect(store, scopes=["email"], expires_at=int(now_ms / 1000) + 1)

    assert isinstance(await auth.authorize_call("place_order", CLAIMS), Allow)
    assert await auth.effective_scopes(CLAIMS) == ["email"]


async def test_leaves_a_connection_with_no_expiry_alone() -> None:
    auth, store, _ = build(now=lambda: 1_700_000_000_000)
    connect(store, scopes=["email"], expires_at=None)

    assert isinstance(await auth.authorize_call("place_order", CLAIMS), Allow)
    assert await auth.effective_scopes(CLAIMS) == ["email"]


# ── the SHIPPED verification path ─────────────────────────────────────────


def test_accepts_a_properly_minted_access_token() -> None:
    auth = with_keys(build()[0])
    claims = auth.authenticate(mint(scope="email"))
    assert claims is not None
    assert claims.sub == "user-1"
    assert claims.jti == "tok-1"
    assert claims.client_id == "agent-1"
    assert claims.iss == ISS
    assert claims.scopes == ("email",)


def test_refuses_an_id_token_replayed_as_an_access_token() -> None:
    """Same issuer, same signature, wrong `typ`. Without the check an ID token
    verifies here and is accepted as authorization."""
    auth = with_keys(build()[0])
    assert auth.authenticate(mint(typ="JWT")) is None


def test_refuses_a_token_missing_jti_which_a_connection_is_keyed_on() -> None:
    auth = with_keys(build()[0])
    assert auth.authenticate(mint(jti=None)) is None


def test_refuses_another_issuer_even_with_a_valid_signature() -> None:
    auth = with_keys(build()[0], ISS, "https://evil.example")
    assert auth.authenticate(mint(iss="https://evil.example")) is None


def test_accepts_a_migration_issuer_when_one_is_configured() -> None:
    legacy = "https://auth.getonlane.com/mcp"
    auth = with_keys(build(additional_issuers=[legacy])[0], ISS, legacy)

    claims = auth.authenticate(mint(iss=legacy))
    assert claims is not None
    assert claims.iss == legacy
    # ...while advertising only the new one.
    assert f'"{ISS}"' in auth.protected_resource_document()
    assert legacy not in auth.protected_resource_document()


@pytest.mark.parametrize(
    ("tool", "mode", "gated"),
    [
        # `log` and `gate` are substrings of the mode names. A membership test
        # against the mode STRING would answer by accident.
        ("log", "gate-all", True),
        ("gate", "gate-all", True),
        ("log", "log-only", False),
        ("gate", "log-only", False),
        ("all", "gate-all", True),
    ],
)
async def test_a_mode_is_never_treated_as_an_allowlist(tool: str, mode: str, gated: bool) -> None:
    """TypeScript cannot hit this: its allowlist is `{allow: [...]}`, which a
    mode string cannot be mistaken for. Python takes a plain collection, so the
    two have to be told apart by type rather than by falling through."""
    auth, _, _ = build(enforcement=mode)
    verdict = await auth.authorize_call(tool, CLAIMS)
    assert isinstance(verdict, StepUpRequired) is gated


async def test_the_typescript_allowlist_shape_reads_the_same_in_python() -> None:
    """`{'allow': [...]}` is what the README documents. `frozenset(mapping)`
    takes the KEYS, so without explicit handling this config gated a tool named
    `allow` and left `place_order` wide open -- silent, and permissive."""
    auth, _, _ = build(enforcement={"allow": ["place_order"]})

    assert isinstance(await auth.authorize_call("place_order", CLAIMS), StepUpRequired)
    assert isinstance(await auth.authorize_call("search", CLAIMS), Allow)
    # The key is not a tool name.
    assert isinstance(await auth.authorize_call("allow", CLAIMS), Allow)


def test_a_malformed_allowlist_mapping_is_refused_at_construction() -> None:
    for bad in ({"allow": "place_order"}, {"allow": None}, {"tools": ["place_order"]}):
        with pytest.raises(ValueError, match="allow"):
            build(enforcement=bad)
