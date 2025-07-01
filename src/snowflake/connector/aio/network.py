"""
Async Network Layer - aiohttp-based HTTP client for Snowflake.

This module provides AsyncSnowflakeRestful that replaces the sync requests-based
HTTP client with aiohttp while reusing all business logic from the sync network layer.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

try:
    import aiohttp
except ImportError:
    raise ImportError(
        "aiohttp is required for async functionality. "
        "Install with: pip install snowflake-connector-python[aio]"
    )

from .. import SnowflakeConnection
from ..auth import AuthByDefault
from ..constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_USER_AGENT,
)
from ..network import (
    SnowflakeRestfulJsonEncoder, 
    KEY_PAIR_AUTHENTICATOR,
    CONTENT_TYPE_APPLICATION_JSON,
    PYTHON_CONNECTOR_USER_AGENT,
)
from .auth import AsyncAuthByDefault, AsyncAuthByKeyPair


class AsyncSnowflakeRestful:
    """
    Async REST client for Snowflake that composes sync networking logic.
    
    Async version of: snowflake.connector.network.SnowflakeRestful
    
    This class wraps the sync SnowflakeRestful to provide async HTTP transport
    via aiohttp while reusing all authentication, retry, and business logic.
    """
    
    def __init__(self, sync_connection: SnowflakeConnection) -> None:
        """
        Initialize async REST client by composing sync connection.
        
        Async version of: SnowflakeRestful.__init__()
        
        Args:
            sync_connection: Sync SnowflakeConnection to wrap
        """
        self._sync_connection = sync_connection
        self._session: Optional[aiohttp.ClientSession] = None
        self._base_url = f"{sync_connection._protocol}://{sync_connection._host}:{sync_connection._port}"
        
    async def authenticate(self) -> None:
        """
        Perform async authentication to establish session.
        
        Async version of: SnowflakeRestful authentication flow
        References: SnowflakeConnection.connect() and auth modules
        
        This reuses the sync authentication logic but replaces HTTP calls with aiohttp.
        """
        if self._session is None:
            # Create aiohttp session with appropriate settings
            timeout = aiohttp.ClientTimeout(
                total=self._sync_connection.login_timeout,
                connect=self._sync_connection.login_timeout
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=aiohttp.TCPConnector(limit=10, limit_per_host=10)
            )
            
        # Determine authentication method and create appropriate async authenticator
        auth_instance = await self._create_async_authenticator()
        
        # Prepare authentication (generate JWT token for keypair, etc.)
        await auth_instance.prepare(
            account=self._sync_connection.account,
            user=self._sync_connection.user
        )
        
        # Build base authentication request
        auth_data = self._build_auth_request_data()
        
        # Let authenticator update the request body with auth-specific data
        auth_instance.update_body(auth_data)
        
        # Perform async login request
        await self._perform_login_request(auth_data)
        
    async def _create_async_authenticator(self):
        """
        Create appropriate async authenticator based on connection parameters.
        
        Returns:
            Async authenticator instance
        """
        # Check if keypair authentication is configured
        if (self._sync_connection._private_key or 
            self._sync_connection._private_key_file or 
            self._sync_connection._authenticator == KEY_PAIR_AUTHENTICATOR):
            
            # Determine private key source
            private_key = self._sync_connection._private_key
            if self._sync_connection._private_key_file and not private_key:
                # Import here to avoid circular imports
                from ..connection import _get_private_bytes_from_file
                private_key = _get_private_bytes_from_file(
                    self._sync_connection._private_key_file,
                    self._sync_connection._private_key_file_pwd,
                )
            
            return AsyncAuthByKeyPair(private_key=private_key)
        
        # Default to basic authentication for now
        # TODO: Add support for other auth types (OAuth, SAML, etc.)
        return AsyncAuthByDefault(password=self._sync_connection._password)
        
    def _build_auth_request_data(self) -> dict:
        """
        Build base authentication request data.
        
        Delegates to sync connection logic where possible.
        
        Returns:
            Base auth request dictionary
        """
        return {
            "data": {
                "ACCOUNT_NAME": self._sync_connection.account,
                "LOGIN_NAME": self._sync_connection.user,
                "CLIENT_APP_ID": "PythonConnector",
                "CLIENT_APP_VERSION": "1.0.0",  # TODO: Get from sync connection
                # Authenticator-specific fields will be added by auth instance
            }
        }
        
    async def _perform_login_request(self, auth_data: dict) -> None:
        """
        Perform the actual login HTTP request.
        
        Args:
            auth_data: Authentication data dictionary
            
        Raises:
            Exception: If authentication fails
        """
        url = f"{self._base_url}/session/v1/login-request"
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        
        async with self._session.post(
            url,
            json=auth_data,
            headers=headers
        ) as response:
            response.raise_for_status()
            auth_result = await response.json()
            
            # Process auth response using sync connection logic
            if auth_result.get("success"):
                data = auth_result.get("data", {})
                # Store tokens in sync connection (it manages token state)
                self._sync_connection._token = data.get("token")
                self._sync_connection._master_token = data.get("masterToken")
                self._sync_connection._session_id = data.get("sessionId")
            else:
                raise Exception(f"Authentication failed: {auth_result.get('message', 'Unknown error')}")
                
    async def cmd_query(
        self,
        sql: str,
        sequence_counter: int,
        request_id: uuid.UUID,
        binding_params: Optional[Any] = None,
        binding_stage: Optional[str] = None,
        is_file_transfer: bool = False,
        statement_params: Optional[dict[str, str]] = None,
        is_internal: bool = False,
        describe_only: bool = False,
        _no_results: bool = False,
        _update_current_object: bool = True,
        _no_retry: bool = False,
        timeout: Optional[int] = None,
        dataframe_ast: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Execute query via async HTTP request.
        
        Async version of: SnowflakeConnection.cmd_query()
        
        This reuses the sync connection's query building logic but replaces
        the HTTP transport with aiohttp.
        """
        if not self._session:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
            
        # Build query request using sync connection logic
        # Import here to avoid circular imports
        from ..time_util import get_time_millis
        
        data = {
            "sqlText": sql,
            "asyncExec": _no_results,
            "sequenceId": sequence_counter,
            "querySubmissionTime": get_time_millis(),
        }
        
        if dataframe_ast is not None:
            data["dataframeAst"] = dataframe_ast
        if statement_params:
            data["parameters"] = statement_params
        if is_internal:
            data["isInternal"] = is_internal
        if describe_only:
            data["describeOnly"] = describe_only
        if binding_stage:
            data["bindStage"] = binding_stage
        if binding_params:
            data["bindings"] = binding_params
            
        if not _no_results:
            # Add query context for sync queries
            query_context = self._sync_connection.get_query_context()
            data["queryContextDTO"] = query_context
            
        # Prepare headers with auth token
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: "application/snowflake",
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
            "Authorization": f"Snowflake Token=\"{self._sync_connection._token}\"",
        }
        
        # Execute async query request
        url = f"{self._base_url}/queries/v1/query-request"
        
        # Set timeout from sync connection if provided
        if timeout is None:
            timeout = self._sync_connection.network_timeout
            
        async with self._session.post(
            url,
            json=data,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            response.raise_for_status()
            result = await response.json()
            
            # Process result using sync connection logic if needed
            if not result.get("success"):
                raise Exception(f"Query failed: {result.get('message', 'Unknown error')}")
                
            return result
            
    async def close(self) -> None:
        """Close async HTTP session."""
        if self._session:
            await self._session.close()
            self._session = None