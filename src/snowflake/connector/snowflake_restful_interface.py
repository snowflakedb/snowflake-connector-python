#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .connection import SnowflakeConnection
    from .vendored.requests import Session


class SnowflakeRestfulInterface(ABC):
    """Snowflake Restful Interface

    Defines all the interfaces that we expose in the Snowflake restful classes. Both the client side restful class and
    the server side one shall conform to this interface. And whenever we introduce a new public method, it should be
    defined in this interface, and implemented in both restful classes.
    """

    @property
    @abstractmethod
    def token(self) -> str | None:
        pass

    @property
    @abstractmethod
    def master_token(self) -> str | None:
        pass

    @property
    @abstractmethod
    def master_validity_in_seconds(self) -> int:
        pass

    @master_validity_in_seconds.setter
    @abstractmethod
    def master_validity_in_seconds(self, value) -> None:
        pass

    @property
    @abstractmethod
    def id_token(self):
        pass

    @id_token.setter
    @abstractmethod
    def id_token(self, value) -> None:
        pass

    @property
    @abstractmethod
    def mfa_token(self) -> str | None:
        pass

    @mfa_token.setter
    @abstractmethod
    def mfa_token(self, value: str) -> None:
        pass

    @property
    @abstractmethod
    def server_url(self) -> str:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
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
        pass

    @abstractmethod
    def update_tokens(
        self,
        session_token,
        master_token,
        master_validity_in_seconds=None,
        id_token=None,
        mfa_token=None,
    ) -> None:
        """Updates session and master tokens and optionally temporary credential."""
        pass

    @abstractmethod
    def delete_session(self, retry: bool = False) -> None:
        """Deletes the session."""
        pass

    @abstractmethod
    def fetch(
        self,
        method: str,
        full_url: str,
        headers: dict[str, Any],
        data: dict[str, Any] | None = None,
        timeout: int | None = None,
        **kwargs,
    ) -> dict[Any, Any]:
        """Carry out API request with session management."""
        pass

    @staticmethod
    @abstractmethod
    def add_request_guid(full_url: str) -> str:
        """Adds request_guid parameter for HTTP request tracing."""
        pass

    @abstractmethod
    def log_and_handle_http_error_with_cause(
        self,
        e: Exception,
        full_url: str,
        method: str,
        retry_timeout: int,
        retry_count: int,
        conn: SnowflakeConnection,
        timed_out: bool = True,
    ) -> None:
        pass

    @abstractmethod
    def handle_invalid_certificate_error(self, conn, full_url, cause) -> None:
        pass

    @abstractmethod
    def make_requests_session(self) -> Session:
        pass
