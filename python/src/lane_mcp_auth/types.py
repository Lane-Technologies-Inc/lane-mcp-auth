"""Types an operator configures and receives back.

Refusals come in two kinds on purpose: a token problem is a 401, a missing
connection is a normal tool-result error. The README explains why.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Literal, Protocol

#: The reserved tool. Never declare it yourself or forward it upstream.
STEP_UP_TOOL = "lane_register_session"

#: Cap on the model-authored task summary. Long enough to be useful, short
#: enough not to be a smuggling channel.
PROMPT_MAX_CHARS = 600

#: Scope gating what the step-up may record.
PERSONALIZATION_CONNECTION_SCOPE = "personalization:connection"

#: The MCP tool annotation key that carries a tool's required Lane authority
#: tags, co-located with the tool. Mirrors ``LANE_TAGS_ANNOTATION`` in the TS
#: package. Declared with the ``@requires(...)`` decorator; the gate refuses the
#: tool unless the caller's connection carries every listed tag. A self-invented
#: tag is never in a connection, so it fails closed -- the fixed vocabulary is
#: Lane policy (see the mcp-auth guide), not something this library encodes.
LANE_TAGS_ANNOTATION = "lane/tags"


@dataclass(frozen=True)
class VerifiedClaims:
    """What a verified bearer proved. Identity and authority, never a profile."""

    sub: str
    """The end user, opaque here."""
    jti: str
    """Token id. Scopes a connection to one credential, not to the user."""
    client_id: str
    """The agent, per RFC 9068."""
    token: str
    """The raw bearer, presented as the exchange's subject_token. Never log it."""
    exp: int
    iss: str
    scopes: tuple[str, ...] = ()
    """The token's OWN scope claim -- empty until the step-up. Not authority."""
    authenticated_at: int | None = None
    """When the user last authenticated. A refresh does not move it."""


@dataclass(frozen=True)
class ConnectionKey:
    """Identifies one connection.

    Both fields, so a connection covers one credential rather than every
    credential its user holds.
    """

    sub: str
    jti: str


@dataclass
class ConnectionRecord:
    """A stored connection: what the step-up granted, and when."""

    scopes: list[str]
    created_at: int
    """Milliseconds since epoch."""
    prompt: str | None = None
    access_token: str | None = None
    """A live credential. Store it encrypted, or drop it."""
    expires_at: int | None = None
    """Seconds since epoch."""


@dataclass(frozen=True)
class Identity:
    """Who is calling. Both ids are opaque and stable at YOUR server only."""

    customer_id: str
    agent_id: str
    credential_id: str
    issuer: str
    authenticated_at: int | None = None


@dataclass(frozen=True)
class Session:
    """What a connected caller may do, and when they agreed to it."""

    identity: Identity
    scopes: list[str]
    connected_at: int
    task: str | None = None
    expires_at: int | None = None


@dataclass(frozen=True)
class ExchangedToken:
    """The result of a successful exchange."""

    access_token: str
    scopes: list[str] = field(default_factory=list)
    """What was granted, not what was asked for."""
    expires_in: int | None = None


class ConnectionStore(Protocol):
    """Where connections live.

    A Protocol because this is server-side state one service owns: two replicas
    with in-memory stores would give two answers.
    """

    async def get(self, key: ConnectionKey) -> ConnectionRecord | None: ...

    async def put(self, key: ConnectionKey, record: ConnectionRecord) -> ConnectionRecord: ...

    async def delete(self, key: ConnectionKey) -> None:
        """Withdraw a connection. Optional; raise NotImplementedError if unsupported."""
        raise NotImplementedError


class TokenExchanger(Protocol):
    """Performs the RFC 8693 exchange at the step-up.

    Server-side only: the exchanged token is stored, never returned, so it
    cannot reach model context.
    """

    async def exchange(self, *, subject_token: str, resource: str) -> ExchangedToken: ...


GateDecision = Literal["allowed", "blocked", "would-have-blocked"]


@dataclass(frozen=True)
class GateEvent:
    """What the gate decided about one call.

    Carries Identity and never VerifiedClaims: the latter holds the raw bearer,
    and handing that to a logging callback is how tokens reach logs.
    """

    decision: GateDecision
    tool: str
    identity: Identity
    scopes: list[str]


@dataclass(frozen=True)
class Allow:
    """The call proceeds. `would_have_blocked` reports what `log-only` suppressed."""

    would_have_blocked: bool = False


@dataclass(frozen=True)
class StepUpRequired:
    """The call is refused. `message` is returned as a tool result, never a 401."""

    message: str


Verdict = Allow | StepUpRequired

#: `'gate-all'` | `'log-only'` | a sequence naming the tools that ARE gated.
#: Either a mode, or the explicit set of tools to gate. A bare string other
#: than the two modes is rejected at construction -- `tool in "place_order"`
#: matches substrings, so a typo would silently gate the wrong tools.
EnforcementMode = Literal["gate-all", "log-only"] | Collection[str] | Mapping[str, Collection[str]]

__all__ = [
    "LANE_TAGS_ANNOTATION",
    "PERSONALIZATION_CONNECTION_SCOPE",
    "PROMPT_MAX_CHARS",
    "STEP_UP_TOOL",
    "Allow",
    "ConnectionKey",
    "ConnectionRecord",
    "ConnectionStore",
    "EnforcementMode",
    "ExchangedToken",
    "GateDecision",
    "GateEvent",
    "Identity",
    "Session",
    "StepUpRequired",
    "TokenExchanger",
    "Verdict",
    "VerifiedClaims",
]
