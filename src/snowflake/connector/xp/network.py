"""XP Network Layer.

This module provides a network implementation for Snowflake's Execution Platform (XP)
that replaces HTTP communication with direct XP API calls.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from ..network import SnowflakeRestfulJsonEncoder

if TYPE_CHECKING:
    from ..connection import SnowflakeConnection

logger = logging.getLogger(__name__)


class XPRestful:
    """XP-specific REST API implementation using direct XP calls instead of HTTP."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        protocol: str = "http",
        inject_client_pause: int = 0,
        connection: SnowflakeConnection | None = None,
        session_manager=None,
    ) -> None:
        """Initialize XP REST client.

        Most parameters are kept for compatibility but are not used in XP context.
        """
        self._host = host
        self._port = port
        self._protocol = protocol
        self._inject_client_pause = inject_client_pause
        self._connection = connection
        self._session_manager = session_manager

        # Import XP modules
        try:
            import _snowflake

            self._snowflake = _snowflake
        except ImportError as e:
            raise RuntimeError(
                "XPRestful can only be used within Snowflake XP environment"
            ) from e

    @property
    def token(self) -> str | None:
        """Token property for compatibility."""
        return getattr(self, "_token", None)

    @property
    def external_session_id(self) -> str | None:
        """External session ID for compatibility."""
        return getattr(self, "_external_session_id", None)

    @property
    def master_token(self) -> str | None:
        """Master token for compatibility."""
        return getattr(self, "_master_token", None)

    @property
    def master_validity_in_seconds(self) -> int:
        """Master token validity for compatibility."""
        return getattr(self, "_master_validity_in_seconds", 0)

    @property
    def id_token(self):
        """ID token for compatibility."""
        return getattr(self, "_id_token", None)

    @id_token.setter
    def id_token(self, value) -> None:
        self._id_token = value

    @property
    def mfa_token(self) -> str | None:
        """MFA token for compatibility."""
        return getattr(self, "_mfa_token", None)

    @mfa_token.setter
    def mfa_token(self, value: str) -> None:
        self._mfa_token = value

    @property
    def server_url(self) -> str:
        """Server URL for compatibility."""
        return f"{self._protocol}://{self._host}:{self._port}"

    @property
    def session_manager(self):
        """Session manager for compatibility."""
        return self._session_manager

    @property
    def sessions_map(self) -> dict:
        """Sessions map for compatibility."""
        return {}

    def close(self) -> None:
        """Close the REST client."""
        if hasattr(self, "_token"):
            del self._token
        if hasattr(self, "_master_token"):
            del self._master_token
        if hasattr(self, "_id_token"):
            del self._id_token
        if hasattr(self, "_mfa_token"):
            del self._mfa_token

    def update_tokens(
        self,
        session_token,
        master_token,
        master_validity_in_seconds=None,
        id_token=None,
        mfa_token=None,
    ) -> None:
        """Update tokens (no-op in XP context)."""
        self._token = session_token
        self._master_token = master_token
        self._id_token = id_token
        self._mfa_token = mfa_token
        self._master_validity_in_seconds = master_validity_in_seconds

    def set_pat_and_external_session(
        self,
        personal_access_token,
        external_session_id,
    ) -> None:
        """Set PAT and external session (no-op in XP context)."""
        self._personal_access_token = personal_access_token
        self._token = personal_access_token
        self._external_session_id = external_session_id

    def request(
        self,
        url,
        body=None,
        method: str = "post",
        client: str = "sfsql",
        timeout: int | None = None,
        _no_results: bool = False,
        _include_retry_params: bool = False,
        _no_retry: bool = False,
    ):
        """Execute request via XP APIs instead of HTTP."""
        if body is None:
            body = {}

        if method == "post":
            return self._post_request(
                url,
                {},
                json.dumps(body, cls=SnowflakeRestfulJsonEncoder),
                timeout=timeout,
                _no_results=_no_results,
            )
        else:
            return self._get_request(url, {}, timeout=timeout)

    def _post_request(
        self,
        url,
        headers,
        body,
        token=None,
        external_session_id: str | None = None,
        timeout: int | None = None,
        socket_timeout: int | None = None,
        _no_results: bool = False,
        no_retry: bool = False,
        _include_retry_params: bool = False,
    ):
        """Execute POST request via XP APIs."""
        try:
            body_dict = json.loads(body) if body else {}

            # Extract SQL from body for query execution
            if "sqlText" in body_dict:
                sql = body_dict["sqlText"]
                bindings = body_dict.get("bindings")
                is_describe_only = body_dict.get("describeOnly", False)

                # Execute via XP API
                result = self._snowflake.execute_sql(
                    sql,
                    is_describe_only=is_describe_only,
                    stmt_params=body_dict.get("parameters"),
                    binding_params=bindings,
                    _no_results=_no_results,
                )

                # Convert to expected format
                return self._format_query_response(result)

            # For other endpoints, return success response
            return {"success": True, "data": {}}

        except Exception as e:
            logger.error(f"XP request failed: {e}", exc_info=True)
            return {
                "success": False,
                "message": str(e),
                "code": -1,
                "data": {},
            }

    def _get_request(
        self,
        url: str,
        headers: dict[str, str],
        token: str = None,
        external_session_id: str = None,
        timeout: int | None = None,
        is_fetch_query_status: bool = False,
    ) -> dict[str, Any]:
        """Execute GET request via XP APIs."""
        try:
            # Handle query status requests
            if "/queries/" in url and "/result" in url:
                # Extract query ID from URL
                query_id = url.split("/queries/")[1].split("/")[0]
                result = self._snowflake.get_query_result(query_id)
                return self._format_query_response(result)

            # For other GET requests, return success
            return {"success": True, "data": {}}

        except Exception as e:
            logger.error(f"XP GET request failed: {e}", exc_info=True)
            return {
                "success": False,
                "message": str(e),
                "code": -1,
                "data": {},
            }

    def _heartbeat(self) -> Any | dict[Any, Any] | None:
        """Heartbeat (no-op in XP context)."""
        # XP doesn't need heartbeat
        return {"success": True}

    def delete_session(self, retry: bool = False) -> None:
        """Delete session (no-op in XP context)."""
        # XP sessions are managed by the platform

    def _renew_session(self):
        """Renew session (no-op in XP context)."""
        # XP doesn't need session renewal
        return {"success": True, "data": {}}

    def _format_query_response(self, result: Any) -> dict[str, Any]:
        """Format XP query result to match expected HTTP response format."""
        # This is a simplified formatter - in practice, this would need to
        # properly map XP result format to HTTP response format
        if isinstance(result, dict):
            return {
                "success": True,
                "data": result,
                "message": None,
                "code": None,
            }
        else:
            return {
                "success": True,
                "data": {"result": result},
                "message": None,
                "code": None,
            }

    def fetch(
        self,
        method: str,
        full_url: str,
        headers: dict[str, Any],
        data: dict[str, Any] | None = None,
        timeout: int | None = None,
        **kwargs,
    ) -> dict[Any, Any]:
        """Fetch via XP APIs instead of HTTP."""
        if method == "post":
            return self._post_request(
                full_url,
                headers,
                data,
                timeout=timeout,
                **kwargs,
            )
        else:
            return self._get_request(
                full_url,
                headers,
                timeout=timeout,
                **kwargs,
            )

    def use_session(self, url: str | bytes):
        """Use session (no-op context manager for XP)."""
        from contextlib import nullcontext

        return nullcontext(self)

    def use_requests_session(self, url: str | bytes):
        """Use requests session (no-op context manager for XP)."""
        return self.use_session(url)
