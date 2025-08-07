from __future__ import annotations

import asyncio
import logging
from abc import abstractmethod
from typing import TYPE_CHECKING, Any, Iterator

from ... import DatabaseError, Error, OperationalError
from ...auth import AuthByPlugin as AuthByPluginSync
from ...errorcode import ER_FAILED_TO_CONNECT_TO_DB
from ...sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED

if TYPE_CHECKING:
    from .. import SnowflakeConnection

logger = logging.getLogger(__name__)


class AuthByPlugin(AuthByPluginSync):
    def __init__(
        self,
        timeout: int | None = None,
        backoff_generator: Iterator | None = None,
        **kwargs,
    ) -> None:
        super().__init__(timeout, backoff_generator, **kwargs)

    @abstractmethod
    async def prepare(
        self,
        *,
        conn: SnowflakeConnection,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str | None,
        **kwargs: Any,
    ) -> str | None:
        raise NotImplementedError

    @abstractmethod
    async def update_body(self, body: dict[Any, Any]) -> None:
        """Update the body of the authentication request."""
        raise NotImplementedError

    @abstractmethod
    async def reset_secrets(self) -> None:
        """Reset secret members."""
        raise NotImplementedError

    @abstractmethod
    async def reauthenticate(
        self,
        *,
        conn: SnowflakeConnection,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Re-perform authentication.

        The difference between this and authentication is that secrets will be removed
        from memory by the time this gets called.
        """
        raise NotImplementedError

    async def _handle_failure(
        self,
        *,
        conn: SnowflakeConnection,
        ret: dict[Any, Any],
        **kwargs: Any,
    ) -> None:
        """Handles a failure when an issue happens while connecting to Snowflake.

        If the user returns from this function execution will continue. The argument
        data can be manipulated from within this function and so recovery is possible
        from here.
        """
        Error.errorhandler_wrapper(
            conn,
            None,
            DatabaseError,
            {
                "msg": "Failed to connect to DB: {host}:{port}, {message}".format(
                    host=conn._rest._host,
                    port=conn._rest._port,
                    message=ret["message"],
                ),
                "errno": int(ret.get("code", -1)),
                "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            },
        )

    async def handle_timeout(
        self,
        *,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str,
        **kwargs: Any,
    ) -> None:
        """Default timeout handler.

        This will trigger if the authenticator
        hasn't implemented one. By default we retry on timeouts and use
        jitter to deduce the time to sleep before retrying. The sleep
        time ranges between 1 and 16 seconds.
        """

        # Some authenticators may not want to delete the parameters to this function
        # Currently, the only authenticator where this is the case is AuthByKeyPair
        if kwargs.pop("delete_params", True):
            del authenticator, service_name, account, user, password

        logger.debug("Default timeout handler invoked for authenticator")
        if not self._retry_ctx.should_retry:
            error = OperationalError(
                msg=f"Could not connect to Snowflake backend after {self._retry_ctx.current_retry_count + 1} attempt(s)."
                "Aborting",
                errno=ER_FAILED_TO_CONNECT_TO_DB,
            )
            raise error
        else:
            logger.debug(
                f"Hit connection timeout, attempt number {self._retry_ctx.current_retry_count + 1}."
                " Will retry in a bit..."
            )
            await asyncio.sleep(float(self._retry_ctx.current_sleep_time))
            self._retry_ctx.increment()
