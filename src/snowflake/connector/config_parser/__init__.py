#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from tomlkit import parse

from ..constants import config_file
from .parser import ConfigParser

CONFIG_PARSER = ConfigParser(
    name="CONFIG_PARSER",
    file_path=config_file,
)
CONFIG_PARSER.add_option(
    name="connections",
    parse_str=parse,
)

__all__ = [
    "ConfigParser",
    "CONFIG_PARSER",
]
