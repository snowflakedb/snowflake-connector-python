#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#
from abc import ABC, abstractmethod
from typing import Dict, Optional


class ReauthByPlugin(ABC):
    def __init__(self, conn: Optional["SnowflakeConnection"] = None) -> None:
        self.conn = conn

    @abstractmethod
    def reauthenticate(self) -> Dict[str, bool]:
        raise NotImplementedError
