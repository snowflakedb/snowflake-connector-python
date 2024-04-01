#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations


class PythonConnectorConfig:
    def __init__(self, connection_parameters):
        self.connection_parameters = connection_parameters

    def parse_config_file(self, conn: dict[str, str]):
        pass
