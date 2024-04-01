#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from typing import Dict


class PythonConnectorConfig:

    def __init__(self, connection_parameters):
        self.connection_parameters = connection_parameters

    def parse_config_file(self, conn: Dict):
        pass
