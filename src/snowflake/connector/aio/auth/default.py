"""
Async Default Authentication for Snowflake.

This module provides AsyncAuthByDefault that wraps the synchronous
AuthByDefault to provide async-compatible authentication.
"""

from __future__ import annotations

from typing import Any

from ...auth.default import AuthByDefault


class AsyncAuthByDefault:
    """
    Async default (username/password) authentication.
    
    Async version of: snowflake.connector.auth.default.AuthByDefault
    
    This class wraps the synchronous AuthByDefault to provide async-compatible
    authentication while automatically inheriting all validation and 
    processing logic from the base library.
    """
    
    def __init__(self, password: str | None = None, **kwargs: Any) -> None:
        """
        Initialize async default auth by composing sync auth.
        
        Async version of: AuthByDefault.__init__()
        
        Args:
            password: User password
            **kwargs: Additional arguments passed to sync auth
        """
        # Compose sync auth for all business logic
        self._sync_auth = AuthByDefault(password=password, **kwargs)
        
    async def prepare(
        self,
        *,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> str:
        """
        Prepare authentication data.
        
        Async version of: AuthByDefault.prepare()
        
        This method is not actually I/O bound but is made async for interface
        consistency.
        
        Args:
            account: Snowflake account identifier
            user: Username
            **kwargs: Additional arguments
            
        Returns:
            Empty string (no token for basic auth)
        """
        # Delegate to sync auth - basic auth preparation is not I/O bound
        return self._sync_auth.prepare(account=account, user=user, **kwargs)
        
    def update_body(self, body: dict[Any, Any]) -> None:
        """
        Update request body with authentication data.
        
        Delegates to: AuthByDefault.update_body()
        
        Args:
            body: Request body dictionary to update
        """
        self._sync_auth.update_body(body)
        
    def assertion_content(self) -> str:
        """
        Get assertion content (empty for basic auth).
        
        Delegates to: AuthByDefault.assertion_content()
        
        Returns:
            Empty string
        """
        return self._sync_auth.assertion_content()
        
    def reset_secrets(self) -> None:
        """
        Reset stored secrets.
        
        Delegates to: AuthByDefault.reset_secrets()
        """
        self._sync_auth.reset_secrets()
        
    @property
    def type_(self):
        """
        Get authentication type.
        
        Delegates to: AuthByDefault.type_
        """
        return self._sync_auth.type_