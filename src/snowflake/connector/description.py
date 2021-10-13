#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

"""Various constants."""

import platform
import sys

from .version import VERSION

SNOWFLAKE_CONNECTOR_VERSION = ".".join(str(v) for v in VERSION[0:3])
PYTHON_VERSION = ".".join(str(v) for v in sys.version_info[:3])
OPERATING_SYSTEM = platform.system()
PLATFORM = platform.platform()
IMPLEMENTATION = platform.python_implementation()
COMPILER = platform.python_compiler()

CLIENT_NAME = "PythonConnector"  # don't change!
CLIENT_VERSION = ".".join([str(v) for v in VERSION[:3]])
