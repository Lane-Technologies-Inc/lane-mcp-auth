"""FastMCP helpers. Mirrors `@getonlane/mcp-auth/mcp-sdk`.

Imported only when you use them: the core does not depend on FastMCP, so a
server on the raw Python SDK -- or on neither -- pays nothing for these.
"""

from __future__ import annotations

import functools
import json
import warnings
from collections.abc import Awaitable, Callable
from typing import Any

from .core import LaneMcpAuth
from .types import STEP_UP_TOOL, Allow, VerifiedClaims

#: Where the HTTP layer stashes verified claims for a request. Set it once,
#: where you verify the bearer; every guarded tool reads it from there.
CLAIMS_ATTR = "lane_claims"


def claims_from(ctx: Any) -> VerifiedClaims | None:
    """Recover the claims the HTTP layer attached, or None."""
    for holder in (ctx, getattr(ctx, "request_context", None), getattr(ctx, "state", None)):
        if holder is None:
            continue
        found = getattr(holder, CLAIMS_ATTR, None)
        if isinstance(found, VerifiedClaims):
            return found
        if isinstance(holder, dict) and isinstance(holder.get(CLAIMS_ATTR), VerifiedClaims):
            return holder[CLAIMS_ATTR]
    return None


def _refuse(message: str) -> str:
    return message


def guarded(
    auth: LaneMcpAuth,
    tool_name: str,
    *,
    scope: str | None = None,
    get_claims: Callable[..., VerifiedClaims | None] | None = None,
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Wrap a tool in BOTH layers of the gate.

    The scope is declared here, beside the tool, rather than checked separately
    in the body -- `authorize_call` asks whether a connection exists and
    `has_scope` asks whether it carries this authority, and wiring only the
    first gives a server where every tool is reachable by anyone who registered.

    Refusals are returned as tool RESULTS, never raised: an MCP client reads a
    transport error as "my token is stale" and refreshes a token that was never
    the problem.

    Args:
        scope: Extra authority this tool needs. Absent means "any connected
          caller", never "anyone".
        get_claims: Override how claims are found, for a server that does not
          pass a FastMCP `ctx`.
    """
    resolve = get_claims or (lambda *a, **k: claims_from(_first_ctx(a, k)))

    def decorate(fn: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            claims = resolve(*args, **kwargs)
            if claims is None:
                return _refuse("unauthorized: no verified caller on this request")
            verdict = await auth.authorize_call(tool_name, claims)
            if not isinstance(verdict, Allow):
                return _refuse(verdict.message)
            if scope is not None and not await auth.has_scope(claims, scope):
                return _refuse(f"insufficient_scope: this connection lacks `{scope}`")
            return await fn(*args, **kwargs)

        return wrapper

    return decorate


def _first_ctx(args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    """The argument that looks like a FastMCP `ctx`, or the first one."""
    if "ctx" in kwargs:
        return kwargs["ctx"]
    for a in args:
        if hasattr(a, "request_context") or hasattr(a, CLAIMS_ATTR):
            return a
    return args[0] if args else None


def register_step_up_tool(mcp: Any, auth: LaneMcpAuth) -> None:
    """Register the step-up tool.

    Call it once. Without it a caller has no way out of the gate, which is a
    server where every tool is permanently refused.
    """

    @mcp.tool(
        name=STEP_UP_TOOL,
        description=(
            "Complete authentication for this session. Call this first; every "
            "other tool is refused until you do. Optionally pass a short "
            "summary of your task."
        ),
    )
    async def _step_up(ctx: Any = None, task: str | None = None) -> str:
        claims = claims_from(ctx)
        if claims is None:
            return _refuse("unauthorized: no verified caller on this request")
        result = await auth.complete_step_up({"task": task}, claims)
        return json.dumps(result, indent=2)


def enable_lane_auth(
    mcp: Any,
    auth: LaneMcpAuth,
    *,
    scopes: dict[str, str] | None = None,
) -> None:
    """Gate an entire server in one call.

        enable_lane_auth(mcp, auth, scopes={"place_order": "email"})
        # ...then declare tools normally. Every one is gated, whether you
        # write `@mcp.tool`, `@mcp.tool()` or `@mcp.tool("name")`.

    Call it BEFORE your tools, the way `app.add_middleware(...)` goes above the
    routes. It wraps `mcp.tool`, so what it guards is what is declared
    afterwards; a tool declared earlier would be silently ungated. If any tools
    already exist it raises and names them.

    Args:
        scopes: Extra authority per tool, by tool name. A tool absent from the
          map is reachable by any CONNECTED caller, never by anyone.

    Raises:
        RuntimeError: If tools are already declared on `mcp`.
    """
    existing = _existing_tool_names(mcp)
    if existing:
        raise RuntimeError(
            "enable_lane_auth must be called BEFORE declaring tools; these are "
            f"already declared and would be left ungated: {', '.join(existing)}. "
            "Move the call above them."
        )

    scope_map = scopes or {}
    original = mcp.tool

    def wrap(fn: Callable[..., Awaitable[Any]], name: str) -> Any:
        # Lane's own tool is registered below, already wrapped. Guarding it here
        # would gate the way out of the gate.
        if name == STEP_UP_TOOL:
            return fn
        return guarded(auth, name, scope=scope_map.get(name))(fn)

    def patched(*t_args: Any, **t_kwargs: Any) -> Any:
        """Cover all three shapes of `FastMCP.tool`.

        Its signature is `tool(name_or_fn=None, *, name=None, ...)`, so
        `@mcp.tool`, `@mcp.tool()` and `@mcp.tool("name")` are all valid and
        behave differently. Handling only the middle one left the bare form
        registered COMPLETELY UNGATED -- FastMCP registers immediately and
        returns the tool rather than a decorator, so a wrapper applied to the
        return value never runs -- and left the positional-name form resolving
        its scope under `fn.__name__`, so the scope layer silently never
        applied. Both defeat the guarantee this function exists to make.
        """
        # Bare `@mcp.tool`: the first positional IS the function, and FastMCP
        # registers it on the spot. Wrap before handing it over.
        if t_args and callable(t_args[0]) and not isinstance(t_args[0], str):
            fn = t_args[0]
            name = t_kwargs.get("name") or getattr(fn, "__name__", "")
            return original(wrap(fn, name), *t_args[1:], **t_kwargs)

        # `@mcp.tool()` or `@mcp.tool("name")`. The name may be positional, and
        # reading only the keyword is what made the scope map miss.
        positional = t_args[0] if t_args and isinstance(t_args[0], str) else None
        decorator = original(*t_args, **t_kwargs)

        def apply(fn: Callable[..., Awaitable[Any]]) -> Any:
            name = positional or t_kwargs.get("name") or getattr(fn, "__name__", "")
            return decorator(wrap(fn, name))

        return apply

    mcp.tool = patched
    register_step_up_tool(mcp, auth)


def _existing_tool_names(mcp: Any) -> list[str]:
    """Tools already declared on `mcp`.

    The registry moved between FastMCP majors -- 2.x keeps a name-keyed dict on
    `_tool_manager`, 3.x keeps `tool:<name>@<version>` keys on
    `_local_provider._components` -- and reading only one shape made this
    return `[]` on the other, which silently disarmed the ordering check that
    is the only thing standing between a late call and an ungated tool.

    Warns rather than raises on a shape it does not recognise: guessing wrong
    would refuse to start a server that is correctly configured.
    """
    # FastMCP 3.x
    components = getattr(getattr(mcp, "_local_provider", None), "_components", None)
    if isinstance(components, dict):
        names = []
        for key in components:
            if not isinstance(key, str) or not key.startswith("tool:"):
                continue
            name = key[len("tool:") :].split("@", 1)[0]
            if name != STEP_UP_TOOL:
                names.append(name)
        return names

    # FastMCP 2.x
    for attr in ("_tools", "tools", "_tool_manager"):
        holder = getattr(mcp, attr, None)
        if isinstance(holder, dict):
            return [n for n in holder if n != STEP_UP_TOOL]
        inner = getattr(holder, "_tools", None)
        if isinstance(inner, dict):
            return [n for n in inner if n != STEP_UP_TOOL]

    warnings.warn(
        "lane-mcp-auth cannot read this FastMCP build's tool registry, so it "
        "cannot verify that enable_lane_auth was called before your tools. "
        "Any tool declared above the call is NOT gated.",
        RuntimeWarning,
        stacklevel=3,
    )
    return []
