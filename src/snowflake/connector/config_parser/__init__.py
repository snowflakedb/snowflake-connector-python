#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from pathlib import Path
from shutil import copyfile

from tomlkit import parse

from ..constants import config_file
from .parser import ConfigParser

if not config_file.exists():
    # Create default config file
    default_config = Path(__file__).absolute().parent / "default_config.toml"
    copyfile(default_config, config_file)

CONFIG_PARSER = ConfigParser(
    name="CONFIG_PARSER",
    file_path=config_file,
)
CONFIG_PARSER.add_option(
    name="connections",
    _type=parse,
)

__all__ = [
    "ConfigParser",
    "CONFIG_PARSER",
]
