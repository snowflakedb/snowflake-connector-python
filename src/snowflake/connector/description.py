#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

"""Various constants."""

from __future__ import annotations

import platform
import re
import sys

from .version import VERSION

SNOWFLAKE_CONNECTOR_VERSION = ".".join(str(v) for v in VERSION[0:3])
PYTHON_VERSION = ".".join(str(v) for v in sys.version_info[:3])
OPERATING_SYSTEM = platform.system()
PLATFORM = platform.platform()
IMPLEMENTATION = platform.python_implementation()
COMPILER = platform.python_compiler()

CLIENT_NAME = "PythonConnector"  # don't change!

# This is a short-term workaround for the backend to enable client side features for preview version, e.g. 3.1.0a1
CLIENT_VERSION = (
    ".".join([str(v) for v in VERSION[:3]])
    if str(VERSION[2]).isdigit()
    else f"{str(VERSION[0])}.{str(VERSION[1])}.{re.split('[ab]', str(VERSION[2]))[0]}"
)
