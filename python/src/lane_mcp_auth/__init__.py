"""OAuth 2.1 resource server and consent gate for an MCP server behind Lane."""

from .core import LaneMcpAuth, metadata_paths, sanitize_prompt
from .exchanger import HttpTokenExchanger
from .types import (
    LANE_TAGS_ANNOTATION,
    PERSONALIZATION_CONNECTION_SCOPE,
    PROMPT_MAX_CHARS,
    STEP_UP_TOOL,
    Allow,
    ConnectionKey,
    ConnectionRecord,
    ConnectionStore,
    ExchangedToken,
    GateEvent,
    Identity,
    Session,
    StepUpRequired,
    TokenExchanger,
    VerifiedClaims,
)

__all__ = [
    "LANE_TAGS_ANNOTATION",
    "PERSONALIZATION_CONNECTION_SCOPE",
    "PROMPT_MAX_CHARS",
    "STEP_UP_TOOL",
    "Allow",
    "ConnectionKey",
    "ConnectionRecord",
    "ConnectionStore",
    "ExchangedToken",
    "GateEvent",
    "HttpTokenExchanger",
    "Identity",
    "LaneMcpAuth",
    "Session",
    "StepUpRequired",
    "TokenExchanger",
    "VerifiedClaims",
    "metadata_paths",
    "sanitize_prompt",
]
__version__ = "0.1.0"
