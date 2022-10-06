#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import typing
from abc import ABC, abstractmethod

if typing.TYPE_CHECKING:
    from snowflake.connector import SnowflakeConnection


class ReauthByPlugin(ABC):
    def __init__(self, conn: SnowflakeConnection | None = None) -> None:
        self.conn = conn

    @abstractmethod
    def reauthenticate(self) -> dict[str, bool]:
        raise NotImplementedError
