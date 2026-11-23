"""Singleton Letta client factory."""

import httpx
from letta_client import Letta

from nabla.config import get_settings
from nabla.log import get_logger

_client: Letta | None = None

# Long timeout — agent tool chains can take minutes
DEFAULT_TIMEOUT = httpx.Timeout(300.0, connect=10.0)

logger = get_logger("client")

AUTH_MESSAGE = (
    "LettaLocal requires authentication. Set NABLA_LETTA_API_KEY "
    "(it must equal LETTA_SERVER_PASSWORD)."
)


class _AuthDiagnosisTransport(httpx.BaseTransport):
    """Single choke point for Letta 401s (migration review, smaller item).

    LettaLocal v0.16.38 runs secure mode by default: every route except
    /v1/health and /v1/ready requires "Authorization: Bearer <password>".
    A bare 401 from a CLI run outside compose wastes a debugging cycle.

    The SDK wraps every transport exception in APIConnectionError, so
    raising here would be swallowed into an undiagnosed connection
    error. Instead the transport REWRITES the 401 response body with the
    actionable diagnosis: the SDK raises APIStatusError with the message
    "Error code: 401 - <body>", so the diagnosis reaches the operator
    verbatim in the exception text. Status code stays 401 for callers
    that check it. Zero call-site changes.
    """

    def __init__(self, inner: httpx.BaseTransport):
        self._inner = inner

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        response = self._inner.handle_request(request)
        if response.status_code == 401:
            return httpx.Response(
                401,
                json={"detail": AUTH_MESSAGE},
                request=request,
            )
        return response


def get_client() -> Letta:
    """Return a shared Letta client instance (created once)."""
    global _client
    if _client is None:
        settings = get_settings()
        logger.info("Creating Letta client (base_url=%s)", settings.letta_base_url)
        kwargs = {
            "base_url": settings.letta_base_url,
            "timeout": DEFAULT_TIMEOUT,
        }
        if settings.letta_api_key:
            # M-1: the letta-client kwarg is `api_key` — it sends
            # "Authorization: Bearer <key>" (witnessed on the wire, W2).
            # The previous `token=` kwarg does not exist on
            # letta-client 1.10.3: TypeError on every construction once
            # a key was set; the branch never executed while the key
            # defaulted empty.
            kwargs["api_key"] = settings.letta_api_key
            logger.info("Using Letta API key authentication")
        _client = Letta(
            http_client=httpx.Client(
                transport=_AuthDiagnosisTransport(httpx.HTTPTransport()),
                timeout=DEFAULT_TIMEOUT,
            ),
            **kwargs,
        )
    return _client


def reset_client() -> None:
    """Reset the singleton (useful for testing)."""
    global _client
    _client = None
