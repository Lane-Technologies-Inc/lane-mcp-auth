"""The RFC 8693 exchange, implemented.

It is the most security-sensitive call in the flow: it presents the caller's
bearer and this server's client secret, and what comes back becomes the
caller's whole authority.
"""

from __future__ import annotations

import base64
from urllib.parse import quote

import httpx

from .types import ExchangedToken

DEFAULT_TIMEOUT_SECONDS = 10.0


def _as_seconds(value: object) -> int | None:
    """`bool` is an `int` in Python, so a naive isinstance lets `true` through
    as a 1-second lifetime -- a connection that expires right after the
    step-up that created it."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value > 0 else None


class HttpTokenExchanger:
    """Exchanges a caller's bearer for a scoped token at Lane's token endpoint."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        issuer: str = "https://auth.getonlane.com/auth/mcp",
        token_endpoint: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        """Configure the exchange.

        Args:
            client_id: Your CONFIDENTIAL client. Lane refuses the exchange grant
              to a public one, which would make the step-up decorative.
            timeout: Seconds before an exchange is abandoned. A step-up is in
              the request path, so a hung server must fail rather than hold the
              call.

        Raises:
            ValueError: If either credential is missing.
        """
        if not client_id or not client_secret:
            raise ValueError(
                "client_id and client_secret are required -- the exchange grant "
                "refuses a public client"
            )
        self._endpoint = token_endpoint or f"{issuer.rstrip('/')}/token"
        self._auth = base64.b64encode(
            f"{quote(client_id)}:{quote(client_secret)}".encode()
        ).decode()
        self._timeout = timeout
        self._client = client

    async def exchange(self, *, subject_token: str, resource: str) -> ExchangedToken:
        """Exchange `subject_token` for a token scoped to `resource`.

        Raises:
            RuntimeError: If the endpoint is unreachable, refuses the exchange,
              or answers without an access token. The message never carries the
              request or the response body.
        """
        body = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "resource": resource,
            # Deliberately no `scope`: the authorization server returns what the
            # user consented to, and a resource server does not shape the grant
            # it is subject to.
        }
        headers = {
            # client_secret_basic. RFC 6749 §2.3.1 requires servers to support
            # it, and it keeps the secret out of the body.
            "authorization": f"Basic {self._auth}",
            "content-type": "application/x-www-form-urlencoded",
        }
        try:
            if self._client is not None:
                res = await self._client.post(
                    self._endpoint, data=body, headers=headers, timeout=self._timeout
                )
            else:
                async with httpx.AsyncClient(timeout=self._timeout) as client:
                    res = await client.post(self._endpoint, data=body, headers=headers)
        except Exception as err:  # noqa: BLE001
            # The message never carries the request: it held a bearer AND a
            # client secret.
            raise RuntimeError(
                f"token exchange could not reach {self._endpoint}: {type(err).__name__}"
            ) from None

        if res.status_code >= 400:
            code = ""
            try:
                code = res.json().get("error", "")
            # A non-JSON body is not worth reporting: the status is already the
            # answer, and the body may echo the request back.
            except Exception:  # noqa: BLE001, S110
                pass
            # The OAuth error CODE is the only safe part.
            raise RuntimeError(
                f"token exchange refused: {res.status_code}{f' {code}' if code else ''}"
            )

        payload = res.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("token exchange returned no access_token")
        scope = payload.get("scope")
        return ExchangedToken(
            access_token=token,
            # An absent scope means NONE, never everything -- defaulting the
            # other way turns a stripped grant into a full one.
            scopes=[s for s in scope.split()] if isinstance(scope, str) else [],
            expires_in=_as_seconds(payload.get("expires_in")),
        )
