"""
Async Private Key Authentication for Snowflake.

This module provides AsyncAuthByKeyPair that wraps the synchronous
AuthByKeyPair to provide async-compatible authentication while reusing
all the JWT generation and private key processing logic.
"""

from __future__ import annotations

from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ...auth.keypair import AuthByKeyPair


class AsyncAuthByKeyPair:
    """
    Async private key authentication that composes sync keypair auth.
    
    Async version of: snowflake.connector.auth.keypair.AuthByKeyPair
    
    This class wraps the synchronous AuthByKeyPair to provide async-compatible
    authentication while automatically inheriting all JWT generation, private key
    processing, and security logic from the base library.
    """
    
    def __init__(
        self,
        private_key: bytes | str | RSAPrivateKey,
        lifetime_in_seconds: int = AuthByKeyPair.LIFETIME,
        **kwargs: Any,
    ) -> None:
        """
        Initialize async keypair auth by composing sync auth.
        
        Async version of: AuthByKeyPair.__init__()
        
        Args:
            private_key: a byte array of der formats of private key, or an
                object that implements the `RSAPrivateKey` interface.
            lifetime_in_seconds: number of seconds the JWT token will be valid
            **kwargs: Additional arguments passed to sync auth
        """
        # Compose sync auth for all business logic
        self._sync_auth = AuthByKeyPair(
            private_key=private_key,
            lifetime_in_seconds=lifetime_in_seconds,
            **kwargs
        )
        
    async def prepare(
        self,
        *,
        account: str,
        user: str,
        **kwargs: Any,
    ) -> str:
        """
        Prepare JWT token for authentication.
        
        Async version of: AuthByKeyPair.prepare()
        
        This method is not actually I/O bound but is made async for interface
        consistency. All JWT generation logic is delegated to the sync auth.
        
        Args:
            account: Snowflake account identifier
            user: Username
            **kwargs: Additional arguments
            
        Returns:
            Generated JWT token
        """
        # Delegate to sync auth - JWT generation is CPU-bound, not I/O bound
        return self._sync_auth.prepare(account=account, user=user, **kwargs)
        
    def update_body(self, body: dict[Any, Any]) -> None:
        """
        Update request body with authentication data.
        
        Delegates to: AuthByKeyPair.update_body()
        
        Args:
            body: Request body dictionary to update
        """
        self._sync_auth.update_body(body)
        
    def assertion_content(self) -> str:
        """
        Get the JWT token content.
        
        Delegates to: AuthByKeyPair.assertion_content()
        
        Returns:
            JWT token string
        """
        return self._sync_auth.assertion_content()
        
    def reset_secrets(self) -> None:
        """
        Reset stored secrets.
        
        Delegates to: AuthByKeyPair.reset_secrets()
        """
        self._sync_auth.reset_secrets()
        
    @property
    def type_(self):
        """
        Get authentication type.
        
        Delegates to: AuthByKeyPair.type_
        """
        return self._sync_auth.type_
        
    @property
    def socket_timeout(self) -> int:
        """
        Get socket timeout for auth requests.
        
        Delegates to: AuthByKeyPair._socket_timeout
        """
        return self._sync_auth._socket_timeout
        
    def should_retry(self, count: int) -> bool:
        """
        Check if authentication should be retried.
        
        Delegates to: AuthByKeyPair.should_retry()
        
        Args:
            count: Current retry count
            
        Returns:
            True if should retry, False otherwise
        """
        return self._sync_auth.should_retry(count)
        
    async def handle_timeout(
        self,
        *,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
        **kwargs: Any,
    ) -> None:
        """
        Handle authentication timeout.
        
        Async version of: AuthByKeyPair.handle_timeout()
        
        Args:
            authenticator: Authenticator type
            service_name: Service name
            account: Snowflake account
            user: Username
            password: Password (not used for keypair auth)
            **kwargs: Additional arguments
        """
        # Delegate to sync auth - timeout handling is not I/O bound
        self._sync_auth.handle_timeout(
            authenticator=authenticator,
            service_name=service_name,
            account=account,
            user=user,
            password=password,
            **kwargs
        )
        
    def can_handle_exception(self, op) -> bool:
        """
        Check if this auth can handle the given exception.
        
        Delegates to: AuthByKeyPair.can_handle_exception()
        
        Args:
            op: OperationalError to check
            
        Returns:
            True if can handle, False otherwise
        """
        return self._sync_auth.can_handle_exception(op)
        
    @staticmethod
    def calculate_public_key_fingerprint(private_key):
        """
        Calculate public key fingerprint.
        
        Delegates to: AuthByKeyPair.calculate_public_key_fingerprint()
        
        Args:
            private_key: Private key to calculate fingerprint for
            
        Returns:
            Public key fingerprint string
        """
        return AuthByKeyPair.calculate_public_key_fingerprint(private_key)