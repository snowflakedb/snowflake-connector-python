#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import time
from os import getenv

from .errorcode import ER_FAILED_TO_CONNECT_TO_DB
from .errors import DatabaseError, Error, OperationalError
from .sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from .time_util import DecorrelateJitterBackoff

logger = logging.getLogger(__name__)

DEFAULT_MAX_CON_RETRY_ATTEMPTS = 1


class AuthRetryCtx:
    def __init__(self) -> None:
        self._current_retry_count = 0
        self._max_retry_attempts = int(
            getenv("MAX_CON_RETRY_ATTEMPTS", DEFAULT_MAX_CON_RETRY_ATTEMPTS)
        )
        self._backoff = DecorrelateJitterBackoff(1, 16)
        self._current_sleep_time = 1

    def get_current_retry_count(self) -> int:
        return self._current_retry_count

    def increment_retry(self) -> None:
        self._current_retry_count += 1

    def should_retry(self) -> bool:
        """Decides whether to retry connection.

        Default value for max retry is 1 because
        Python requests module already tries twice
        by default. Unlike JWT where we need to refresh
        token every 10 seconds, general authenticators
        wait for 60 seconds before connection timeout
        per attempt totaling a 240 sec wait time for a non
        JWT based authenticator which is more than enough.
        This can be changed ofcourse using MAX_CNXN_RETRY_ATTEMPTS
        env variable.
        """
        return self._current_retry_count < self._max_retry_attempts

    def next_sleep_duration(self) -> int:
        self._current_sleep_time = self._backoff.next_sleep(
            self._current_retry_count, self._current_sleep_time
        )
        logger.debug(f"Sleeping for {self._current_sleep_time} seconds")
        return self._current_sleep_time

    def reset(self):
        self._current_retry_count = 0
        self._current_sleep_time = 1


class AuthByPlugin:
    """External Authenticator interface."""

    def __init__(self) -> None:
        self._retry_ctx = AuthRetryCtx()

    @property
    def assertion_content(self):
        raise NotImplementedError

    def update_body(self, body):
        raise NotImplementedError

    def authenticate(self, authenticator, service_name, account, user, password):
        raise NotImplementedError

    def handle_failure(self, ret):
        """Handles a failure when connecting to Snowflake."""
        Error.errorhandler_wrapper(
            self._rest._connection,
            None,
            DatabaseError,
            {
                "msg": ("Failed to connect to DB: {host}:{port}, " "{message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    message=ret["message"],
                ),
                "errno": int(ret.get("code", -1)),
                "sqlstate": SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            },
        )

    def handle_timeout(
        self,
        authenticator: str,
        service_name: str | None,
        account: str,
        user: str,
        password: str,
    ) -> None:
        """Default timeout handler.

        This will trigger if the authenticator
        hasn't implemented one. By default we retry on timeouts and use
        jitter to deduce the time to sleep before retrying. The sleep
        time ranges between 1 and 16 seconds.
        """

        del authenticator, service_name, account, user, password
        logger.debug("Default timeout handler invoked for authenticator")
        if not self._retry_ctx.should_retry():
            self._retry_ctx.reset()
            raise OperationalError(
                msg=f"Could not connect to Snowflake backend after {self._retry_ctx.get_current_retry_count()} attempt(s)."
                "Aborting",
                errno=ER_FAILED_TO_CONNECT_TO_DB,
            )
        else:
            logger.debug(
                f"Hit connection timeout, attempt number {self._retry_ctx.get_current_retry_count()}."
                " Will retry in a bit..."
            )
            self._retry_ctx.increment_retry()
            time.sleep(self._retry_ctx.next_sleep_duration())
