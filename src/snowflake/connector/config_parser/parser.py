#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from functools import wraps
from pathlib import Path
from typing import Callable, Literal, TypeVar

import tomlkit
from tomlkit import TOMLDocument
from tomlkit.items import Table

from ..errors import ConfigParserError, ConfigSourceError

_T = TypeVar("_T")

LOGGER = logging.getLogger(__name__)


class ConfigOption:
    def __init__(
        self,
        name: str,
        _root_parser: ConfigParser,
        _nest_path: list[str],
        _type: Callable[[str], _T] | None = None,
        choices: Iterable[_T] | None = None,
        env_name: str | None | Literal[False] = None,
    ) -> None:
        """Create a config option that can read values from different locations.

        Args:
            name: The name of the ConfigOption
            env_name: Environmental variable value should be read from, if not supplied, we'll construct this
            type: A function that can turn str to the desired type, useful for reading value from environmental variable
        """
        self.name = name
        self.type = _type
        self.choices = choices
        self._nest_path = _nest_path + [name]
        self._root_parser: ConfigParser = _root_parser
        self.env_name = env_name

    def get(self):
        """Retrieve a value of option."""
        source = "environment variable"
        loaded_env, value = self._get_env()
        if not loaded_env:
            source = "configuration file"
            value = self._get_config()
        if self.choices and value not in self.choices:
            raise ConfigSourceError(
                f"The value of {self.option_name} read from "
                f"{source} is not part of {self.choices}"
            )
        return value

    @property
    def option_name(self) -> str:
        return ".".join(self._nest_path[1:])

    @property
    def option_env_name(self) -> str:
        pieces = map(lambda e: e.upper(), self._nest_path[1:])
        return f"SF{'_' + '_'.join(pieces)}"

    def _get_env(self) -> tuple[bool, str | _T | None]:
        if self.env_name is False:
            return False, None
        if self.env_name is not None:
            env_name = self.env_name
        else:
            # Generate environment name if it wasn't not explicitly supplied,
            #  and isn't disabled
            env_name = self.option_env_name
        if env_name not in os.environ:
            return False, None
        env_var = os.environ.get(env_name, None)
        loaded_var: _T | None | str = env_var
        if env_var and self.type is not None:
            loaded_var = self.type(env_var)
        if isinstance(loaded_var, (Table, TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return True, loaded_var.value
        return True, loaded_var

    def _get_config(self):
        e = self._root_parser._conf_file_cache
        for k in self._nest_path[1:]:
            e = e[k]
        if isinstance(e, (Table, TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return e.value
        return e


class ConfigParser:
    def __init__(
        self,
        *,
        name: str,
        file_path: Path | None = None,
    ):
        self.name = name
        self.file_path = file_path
        # Objects holding subparsers and options
        self._options: dict[str, ConfigOption] = dict()
        self._sub_parsers: dict[str, ConfigParser] = dict()
        # Dictionary to cache read in config file
        self._conf_file_cache: TOMLDocument | None = None
        # Information necessary to be able to nest elements
        #  and add options in O(1)
        self._root_parser: ConfigParser = self
        self._nest_path = [name]

    def read_config(
        self,
    ) -> None:
        """Read and parse config file."""
        if self.file_path is None:
            raise ConfigParserError(
                "ConfigParser is trying to read config file, but it doesn't have one"
            )
        LOGGER.debug(f"reading configuration file from {str(self.file_path)}")
        try:
            self._conf_file_cache = tomlkit.parse(self.file_path.read_text())
        except Exception as e:
            raise ConfigSourceError(
                f"An unknown error happened while loading '{str(self.file_path)}"
                f"', please see the error: {e}"
            )

    @wraps(ConfigOption.__init__)
    def add_option(
        self,
        *args,
        **kwargs,
    ) -> None:
        kwargs["_root_parser"] = self._root_parser
        kwargs["_nest_path"] = self._nest_path
        new_option = ConfigOption(
            *args,
            **kwargs,
        )
        self._check_child_conflict(new_option.name)
        self._options[new_option.name] = new_option

    def _check_child_conflict(self, name: str) -> None:
        if name in (self._options.keys() | self._sub_parsers.keys()):
            raise ConfigParserError(
                f"'{name}' subparser, or option conflicts with a child element of '{self.name}'"
            )

    def add_subparser(self, other: ConfigParser) -> None:
        self._check_child_conflict(other.name)
        self._sub_parsers[other.name] = other

        def _root_setter_helper(node: ConfigParser):
            # Deal with ConfigParsers
            node._root_parser = self._root_parser
            node._nest_path = self._nest_path + node._nest_path
            for sub_parser in node._sub_parsers.values():
                _root_setter_helper(sub_parser)
            # Deal with ConfigOptions
            for option in node._options.values():
                option._root_parser = self._root_parser
                option._nest_path = self._nest_path + option._nest_path

        _root_setter_helper(other)

    def __getitem__(self, item: str) -> ConfigOption | ConfigParser:
        if self._conf_file_cache is None and (
            self.file_path is not None
            and self.file_path.exists()
            and self.file_path.is_file()
        ):
            self.read_config()
        if item in self._options:
            return self._options[item].get()
        if item not in self._sub_parsers:
            raise ConfigSourceError(
                "No ConfigParser, or ConfigOption can be found"
                f" with the name '{item}'"
            )
        return self._sub_parsers[item]
