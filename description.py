#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
"""
Various constants
"""

import platform
import sys

from .compat import TO_UNICODE
from .version import VERSION

SNOWFLAKE_CONNECTOR_VERSION = u'.'.join(TO_UNICODE(v) for v in VERSION[0:3])
PYTHON_VERSION = u'.'.join(TO_UNICODE(v) for v in sys.version_info[:3])
OPERATING_SYSTEM = platform.system()
PLATFORM = platform.platform()
IMPLEMENTATION = platform.python_implementation()
COMPILER = platform.python_compiler()

CLIENT_NAME = u"PythonConnector"  # don't change!
CLIENT_VERSION = u'.'.join([TO_UNICODE(v) for v in VERSION[:3]])
