"""The gate. Port of `src/index.ts`; same invariants."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from typing import Any
from urllib.parse import urlparse

import jwt
from jwt import PyJWKClient

from .types import (
    PERSONALIZATION_CONNECTION_SCOPE,
    PROMPT_MAX_CHARS,
    STEP_UP_TOOL,
    Allow,
    ConnectionKey,
    ConnectionRecord,
    ConnectionStore,
    EnforcementMode,
    GateEvent,
    Identity,
    Session,
    StepUpRequired,
    TokenExchanger,
    Verdict,
    VerifiedClaims,
)

DEFAULT_ISSUER = "https://auth.getonlane.com/auth/mcp"
DEFAULT_CANONICAL_RESOURCE = "https://app-mcp.getonlane.com"
ACCESS_TOKEN_TYP = "at+jwt"
# What the protected-resource document advertises when the server names no
# `scopes_supported`. Without it an SDK client sends no `scope` and the consent
# screen offers nothing to choose. No `phone`: web clients may not hold it.
DEFAULT_SCOPES_SUPPORTED: tuple[str, ...] = ("openid", "profile", "email", "offline_access")


def metadata_paths(resource: str) -> tuple[str, str | None]:
    """Both paths a client may look for the RFC 9728 metadata at.

    The challenge advertises the DERIVED path when there is one, so a server
    that publishes only the root hands clients a URL it does not answer.

    Returns:
        The root path, and the path derived from `resource`'s own path, or None
        when the resource has no path.
    """
    path = urlparse(resource).path.rstrip("/")
    root = "/.well-known/oauth-protected-resource"
    return root, (f"{root}{path}" if path else None)


def sanitize_prompt(raw: Any) -> str | None:
    """Cap and de-fang model-authored text.

    Returns:
        The cleaned summary, or None if `raw` was not a usable string.
    """
    if not isinstance(raw, str):
        return None
    cleaned = "".join(" " if ord(c) < 0x20 or ord(c) == 0x7F else c for c in raw).strip()
    return cleaned[:PROMPT_MAX_CHARS] or None


def step_up_required_message() -> str:
    """What a gated tool call answers with. This text IS the steering mechanism."""
    return (
        f"Login incomplete — call `{STEP_UP_TOOL}` with a brief summary of your "
        "task, then retry. Every other tool is refused until you do."
    )


def _normalize_enforcement(mode: EnforcementMode) -> str | frozenset[str]:
    """Reject a bare string that is not a mode, and freeze a collection.

    `tool in mode` is substring matching when `mode` is a string, so
    `enforcement="place_order"` would gate every tool whose name is a
    substring of it -- silently, and in the permissive direction.
    """
    if isinstance(mode, str):
        if mode not in ("gate-all", "log-only"):
            raise ValueError(
                f"enforcement must be 'gate-all', 'log-only', an allowlist, or "
                f"{{'allow': [...]}} -- not {mode!r}. Pass [{mode!r}] to gate one tool."
            )
        return mode
    # `{"allow": [...]}`, the TypeScript shape, so the same config reads the
    # same in both. Handled explicitly because `frozenset(mapping)` silently
    # takes the KEYS -- an operator copying the documented form would gate a
    # tool named "allow" and leave the real ones open.
    if isinstance(mode, Mapping):
        allow = mode.get("allow")
        if isinstance(allow, str) or not isinstance(allow, Collection):
            raise ValueError(  # noqa: TRY004 -- matches the bare-string case above
                "enforcement mapping must be {'allow': [tool names]}; "
                f"got {{'allow': {allow!r}}}"
            )
        return frozenset(allow)
    return frozenset(mode)


class LaneMcpAuth:
    """OAuth resource server + connection gate.

    See the README for the three tiers. Registration is the floor: a caller with
    a valid bearer and no connection reaches nothing.
    """

    def __init__(
        self,
        *,
        resource: str,
        connections: ConnectionStore,
        exchanger: TokenExchanger,
        issuer: str = DEFAULT_ISSUER,
        canonical_resource: str = DEFAULT_CANONICAL_RESOURCE,
        additional_issuers: Sequence[str] = (),
        enforcement: EnforcementMode = "gate-all",
        on_gate_event: Callable[[GateEvent], None] | None = None,
        verify_token: Callable[[str], VerifiedClaims] | None = None,
        now: Callable[[], float] | None = None,
        scopes_supported: Sequence[str] = DEFAULT_SCOPES_SUPPORTED,
    ) -> None:
        self._resource = resource
        self._scopes_supported = list(scopes_supported)
        self._connections = connections
        self._exchanger = exchanger
        self._issuer = issuer
        self._canonical = canonical_resource
        self._issuers = [issuer, *additional_issuers]
        self._enforcement = _normalize_enforcement(enforcement)
        self._on_gate_event = on_gate_event
        self._verify_token = verify_token
        # Milliseconds since epoch, matching `ConnectionRecord.created_at`.
        self._now = now or (lambda: time.time() * 1000)
        self._jwks: dict[str, PyJWKClient] = {}

    # ── discovery ──────────────────────────────────────────────────────────
    def protected_resource_document(self) -> str:
        """The RFC 9728 document, serialized."""
        return json.dumps(
            {
                "resource": self._resource,
                "authorization_servers": [self._issuer],
                "bearer_methods_supported": ["header"],
                "scopes_supported": self._scopes_supported,
            },
            indent=2,
        )

    def metadata_paths(self) -> tuple[str, str | None]:
        """Where to serve the metadata document. See `metadata_paths`."""
        return metadata_paths(self._resource)

    def challenge(self) -> str:
        """The `WWW-Authenticate` value for a 401 (RFC 9728 §5.1)."""
        root, derived = self.metadata_paths()
        origin = "{u.scheme}://{u.netloc}".format(u=urlparse(self._resource))
        return f'Bearer resource_metadata="{origin}{derived or root}"'

    # ── authentication ─────────────────────────────────────────────────────
    def _keys(self, issuer: str) -> PyJWKClient:
        if issuer not in self._jwks:
            self._jwks[issuer] = PyJWKClient(f"{issuer}/jwks")
        return self._jwks[issuer]

    def authenticate(self, bearer: str | None) -> VerifiedClaims | None:
        """Verify a bearer. TOKEN problems only -- returns None, never raises.

        Every failure collapses to one answer, deliberately: naming which check
        failed -- signature, issuer, audience, expiry -- walks a caller toward a
        token this server would accept.
        """
        if not bearer:
            return None
        if self._verify_token is not None:
            try:
                return self._verify_token(bearer)
            except Exception:  # noqa: BLE001
                return None

        for issuer in self._issuers:
            try:
                signing = self._keys(issuer).get_signing_key_from_jwt(bearer)
                header = jwt.get_unverified_header(bearer)
                payload = jwt.decode(
                    bearer,
                    signing.key,
                    algorithms=["RS256"],
                    issuer=issuer,
                    # Either audience: Lane's own, or this server's. A client
                    # holding one or the other cannot be told which to get.
                    audience=[self._canonical, self._resource],
                )
                # jwt does not check `typ`; without this an ID TOKEN from the
                # same issuer verifies here and is accepted as an access token.
                if header.get("typ") != ACCESS_TOKEN_TYP:
                    continue
                sub, jti = payload.get("sub", ""), payload.get("jti", "")
                # Without `jti` a connection could only be keyed on the user, so
                # one step-up would cover every credential they ever hold.
                if not sub or not jti:
                    continue
                scope = payload.get("scope") or ""
                return VerifiedClaims(
                    sub=sub,
                    jti=jti,
                    client_id=payload.get("client_id", ""),
                    token=bearer,
                    exp=int(payload.get("exp", 0)),
                    iss=issuer,
                    scopes=tuple(s for s in scope.split() if s),
                    authenticated_at=payload.get("auth_time"),
                )
            except Exception:  # noqa: BLE001, S112
                continue
        return None

    # ── the gate ───────────────────────────────────────────────────────────
    def _live(self, record: ConnectionRecord | None) -> ConnectionRecord | None:
        """An expired connection is no connection.

        Enforced here so every reader gets it -- the gate AND scope resolution,
        or a scope check would outlive the gate that guards it.
        """
        if record is None:
            return None
        if record.expires_at is not None and self._now() / 1000 >= record.expires_at:
            return None
        return record

    def _gated(self, tool: str) -> bool:
        """Whether `tool` requires a connection.

        A sequence names the tools that STILL require one, so a tool absent from
        it is ungated -- fail-open, because that mode is a rollout stage.
        """
        # Exhaustive on TYPE, not on value. `_normalize_enforcement` leaves a
        # mode as a str and freezes an allowlist, so a mode can never fall
        # through to the membership test -- `tool in "log-only"` is substring
        # matching, which would gate by accident and in the permissive
        # direction. TypeScript has no such path: its allowlist is `{allow:
        # [...]}`, a shape a mode cannot be confused with.
        if isinstance(self._enforcement, str):
            return self._enforcement == "gate-all"
        return tool in self._enforcement

    def _emit(self, decision: str, tool: str, claims: VerifiedClaims, scopes: list[str]) -> None:
        if self._on_gate_event is None:
            return
        try:
            self._on_gate_event(
                GateEvent(decision=decision, tool=tool, identity=self.identity(claims), scopes=scopes)  # type: ignore[arg-type]
            )
        # A log sink must never be able to fail a tool call.
        except Exception:  # noqa: BLE001, S110
            pass

    async def authorize_call(self, tool: str, claims: VerifiedClaims) -> Verdict:
        """May this verified caller invoke `tool`? CONNECTION problems only."""
        # The step-up is how a caller ESCAPES the gate; gating it is a deadlock.
        if tool == STEP_UP_TOOL:
            return Allow()
        # Expired reads as absent: the caller is told to step up again, which is
        # the honest answer and the one that can succeed.
        record = self._live(await self._connections.get(ConnectionKey(claims.sub, claims.jti)))
        if record is not None:
            self._emit("allowed", tool, claims, record.scopes)
            return Allow()
        if not self._gated(tool):
            would = self._enforcement == "log-only"
            self._emit("would-have-blocked" if would else "allowed", tool, claims, [])
            return Allow(would_have_blocked=would)
        self._emit("blocked", tool, claims, [])
        return StepUpRequired(step_up_required_message())

    # ── authority ──────────────────────────────────────────────────────────
    async def effective_scopes(self, claims: VerifiedClaims) -> list[str]:
        """The authority this caller actually has.

        Never `claims.scopes`: a step-down token carries none before the step-up
        and stale ones after it.
        """
        record = self._live(await self._connections.get(ConnectionKey(claims.sub, claims.jti)))
        return list(record.scopes) if record else []

    async def has_scope(self, claims: VerifiedClaims, scope: str) -> bool:
        """Convenience over `effective_scopes` for a single check."""
        return scope in await self.effective_scopes(claims)

    def identity(self, claims: VerifiedClaims) -> Identity:
        """Who is calling. Available as soon as the token verifies."""
        return Identity(
            customer_id=claims.sub,
            agent_id=claims.client_id,
            credential_id=claims.jti,
            issuer=claims.iss,
            authenticated_at=claims.authenticated_at,
        )

    async def session(self, claims: VerifiedClaims) -> Session | None:
        """The caller's connection, or None before the step-up."""
        record = self._live(await self._connections.get(ConnectionKey(claims.sub, claims.jti)))
        if record is None:
            return None
        return Session(
            identity=self.identity(claims),
            scopes=list(record.scopes),
            connected_at=record.created_at,
            task=record.prompt,
            expires_at=record.expires_at,
        )

    # ── the step-up ────────────────────────────────────────────────────────
    async def complete_step_up(self, args: dict[str, Any], claims: VerifiedClaims) -> dict[str, Any]:
        """Run the RFC 8693 exchange and record the connection.

        The result is STORED, never returned: a client cannot install a new
        bearer, so a token handed back could only travel onward as a tool
        argument -- a credential in model context.

        Returns:
            `ok`, whether a task summary was recorded, and the granted scopes.
            Never the token.
        """
        granted = await self._exchanger.exchange(
            subject_token=claims.token, resource=self._resource
        )
        # Consent is mechanical and reads from what was just GRANTED. Without the
        # scope the step-up still succeeds; nothing model-authored is recorded.
        consented = PERSONALIZATION_CONNECTION_SCOPE in granted.scopes
        prompt = sanitize_prompt(args.get("task")) if consented else None
        record = ConnectionRecord(
            scopes=list(granted.scopes),
            created_at=int(self._now()),
            prompt=prompt,
            access_token=granted.access_token,
            expires_at=(
                int(self._now() / 1000) + granted.expires_in if granted.expires_in else None
            ),
        )
        await self._connections.put(ConnectionKey(claims.sub, claims.jti), record)
        return {"ok": True, "personalized": prompt is not None, "scopes": list(granted.scopes)}

    def is_step_up_tool(self, name: str) -> bool:
        """True when this is the reserved name -- handle locally, never forward."""
        return name == STEP_UP_TOOL
