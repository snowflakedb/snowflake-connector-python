#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import sys


log = logging.getLogger(__name__)


def _relevant_path(path: str) -> str | None:
    pos = path.rfind("snowflake/connector/")
    if pos != -1:
        return path[pos + 20:]
    return None


def _trace(frame, event, arg):
    if event == "call":
        rel_path = _relevant_path(frame.f_back.f_code.co_filename)
        if rel_path:
            log.debug(
                f"EXT-NTWRK-LOG:%s:%d:%s",
                rel_path,
                frame.f_back.f_lineno,
                frame.f_code.co_qualname,
            )


def enable_extended_networking_logging():
    log.debug("Enable EXT-NTWRK-LOG")
    sys.settrace(_trace)


def disable_extended_networking_logging():
    log.debug("Disable EXT-NTWRK-LOG")
    sys.settrace(None)
