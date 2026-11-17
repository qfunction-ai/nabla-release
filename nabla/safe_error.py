"""Safe error message generation — prevents information disclosure.

Returns generic messages to clients while logging the real error
server-side. ValueError messages are passed through since they
typically contain user-actionable validation details.
"""

from nabla.log import get_logger

logger = get_logger("safe_error")


def safe_error(e: Exception, context: str = "Operation") -> str:
    """Return a safe error message for client responses.

    Logs the real exception at ERROR level and returns a generic
    message that doesn't leak internal details (file paths, service
    names, connection strings, stack traces).

    ValueError is treated as user-actionable — its message is
    passed through since it typically contains validation feedback.

    Args:
        e: The exception that occurred.
        context: Short description of the operation (e.g., "Bootstrap",
            "Export", "Chat stream"). Used in the generic message.

    Returns:
        Safe error string suitable for HTTP response bodies.
    """
    # Log the real error server-side
    logger.error("%s failed: %s", context, e, exc_info=True)

    # ValueError messages are user-actionable (validation, bad input)
    if isinstance(e, ValueError):
        return str(e)[:200]

    # All other exceptions get generic messages
    return f"{context} failed — check server logs for details"
