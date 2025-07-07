from __future__ import annotations

import logging
from typing import Any, Mapping

from .session_manager import SessionManager
from .vendored.requests import Response

logger = logging.getLogger(__name__)


class HttpClient:
    """HTTP client that uses SessionManager for connection pooling and adapter management."""

    def __init__(self, session_manager: SessionManager):
        """Initialize HttpClient with a SessionManager.

        Args:
            session_manager: SessionManager instance to use for all requests
        """
        self.session_manager = session_manager

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs: Any,
    ) -> Response:
        """Make an HTTP request using the configured SessionManager.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Optional HTTP headers
            timeout_sec: Request timeout in seconds
            use_pooling: Whether to use connection pooling (overrides session_manager setting)
            **kwargs: Additional arguments passed to requests.Session.request

        Returns:
            Response object from the request
        """
        mgr = (
            self.session_manager
            if use_pooling is None
            else self.session_manager.clone(use_pooling=use_pooling)
        )

        with mgr.use_session(url) as session:
            return session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=timeout_sec,
                **kwargs,
            )


# Convenience function for backwards compatibility and simple usage
def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout_sec: int | None = 3,
    session_manager: SessionManager | None = None,
    use_pooling: bool | None = None,
    **kwargs: Any,
) -> Response:
    """Convenience function for making HTTP requests.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        headers: Optional HTTP headers
        timeout_sec: Request timeout in seconds
        session_manager: SessionManager instance to use (required)
        use_pooling: Whether to use connection pooling (overrides session_manager setting)
        **kwargs: Additional arguments passed to requests.Session.request

    Returns:
        Response object from the request

    Raises:
        ValueError: If session_manager is None
    """
    if session_manager is None:
        raise ValueError(
            "session_manager is required - no default session manager available"
        )

    client = HttpClient(session_manager)
    return client.request(
        method=method,
        url=url,
        headers=headers,
        timeout_sec=timeout_sec,
        use_pooling=use_pooling,
        **kwargs,
    )
