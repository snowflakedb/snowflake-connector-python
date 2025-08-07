#!/usr/bin/env python

from __future__ import annotations

from logging import getLogger
from typing import Any

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ...auth.keypair import AuthByKeyPair as AuthByKeyPairSync
from ._by_plugin import AuthByPlugin as AuthByPluginAsync

logger = getLogger(__name__)


class AuthByKeyPair(AuthByPluginAsync, AuthByKeyPairSync):
    def __init__(
        self,
        private_key: bytes | str | RSAPrivateKey,
        lifetime_in_seconds: int = AuthByKeyPairSync.LIFETIME,
        **kwargs,
    ) -> None:
        AuthByKeyPairSync.__init__(self, private_key, lifetime_in_seconds, **kwargs)

    async def reset_secrets(self) -> None:
        AuthByKeyPairSync.reset_secrets(self)

    async def prepare(self, **kwargs: Any) -> None:
        AuthByKeyPairSync.prepare(self, **kwargs)

    async def reauthenticate(self, **kwargs: Any) -> dict[str, bool]:
        return AuthByKeyPairSync.reauthenticate(self, **kwargs)

    async def update_body(self, body: dict[Any, Any]) -> None:
        """Sets the private key if available."""
        AuthByKeyPairSync.update_body(self, body)

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
        logger.debug("Invoking base timeout handler")
        await AuthByPluginAsync.handle_timeout(
            self,
            authenticator=authenticator,
            service_name=service_name,
            account=account,
            user=user,
            password=password,
            delete_params=False,
        )

        logger.debug("Base timeout handler passed, preparing new token before retrying")
        await self.prepare(account=account, user=user)
