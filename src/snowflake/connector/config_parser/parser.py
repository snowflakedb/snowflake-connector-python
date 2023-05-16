#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Callable, Literal, TypeVar

import tomlkit
from tomlkit import TOMLDocument
from tomlkit.items import Table

from ..errors import ConfigParserError, ConfigSourceError

_T = TypeVar("_T")

LOGGER = logging.getLogger(__name__)


class ConfigOption:
    """ConfigOption represents a flag/setting.

    The class knows how to read the value out of all sources and implements
    order of precedence between them.

    Attributes:
        name: Name of this ConfigOption.
        parse_str: A function that can turn str to the desired type, useful
          for reading value from environmental variable.
        choices: An iterable of all possible values that are allowed for
          this option.
        env_name: Environmental variable value should be read from, if not
          supplied, we'll construct this. False disables reading from
          environmental variable, None uses the auto generated variable name
          and explicitly provided string overwrites the default one.
        _root_parser: Reference to the root parser. Used to efficiently
          refer to cached config file. Is supplied by the parent
          ConfigParser.
        _nest_path: The names of the ConfigParsers that this option is
          nested in. Used be able to efficiently resolve where to grab
          value out of configuration file and construct environment
          variable name. This is supplied by the parent ConfigParser.
    """

    def __init__(
        self,
        *,
        name: str,
        _root_parser: ConfigParser,
        _nest_path: list[str],
        parse_str: Callable[[str], _T] | None = None,
        choices: Iterable[Any] | None = None,
        env_name: str | None | Literal[False] = None,
    ) -> None:
        """Create a config option that can read values from different locations.

        Args:
            name: Name to assign to this ConfigOption.
            parse_str: String parser function for this ConfigOption.
            choices: List of possible values for this ConfigOption.
            env_name: Environmental variable name value should be read from.
            _root_parser: Reference to the root parser. Should be supplied by
              the parent ConfigParser.
            _nest_path: The names of the ConfigParsers that this option is
              nested in. This is supplied by the parent ConfigParser.
        """
        self.name = name
        self.parse_str = parse_str
        self.choices = choices
        self._nest_path = _nest_path + [name]
        self._root_parser: ConfigParser = _root_parser
        self.env_name = env_name

    def get(self) -> Any:
        """Retrieve a value of option.

        This function implements order of precedence between different sources.
        """
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
        """User-friendly name of the config option. Includes self._nest_path."""
        return ".".join(self._nest_path[1:])

    @property
    def default_env_name(self) -> str:
        """The default environmental variable name for this option."""
        pieces = map(lambda e: e.upper(), self._nest_path[1:])
        return f"SNOWFLAKE_{'_'.join(pieces)}"

    def _get_env(self) -> tuple[bool, str | _T | None]:
        """Get value from environment variable if possible.

        Returns whether it was able to load the data and the loaded value
        itself.
        """
        if self.env_name is False:
            return False, None
        if self.env_name is not None:
            env_name = self.env_name
        else:
            # Generate environment name if it was not explicitly supplied,
            #  and isn't disabled
            env_name = self.default_env_name
        if env_name not in os.environ:
            return False, None
        env_var = os.environ.get(env_name, None)
        loaded_var: _T | None | str = env_var
        if env_var and self.parse_str is not None:
            loaded_var = self.parse_str(env_var)
        if isinstance(loaded_var, (Table, TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return True, loaded_var.value
        return True, loaded_var

    def _get_config(self) -> Any:
        """Get value from the cached config file."""
        e = self._root_parser.conf_file_cache
        if e is None:
            raise ConfigParserError(
                f"Root parser '{self._root_parser.name}' is missing file_path",
            )
        for k in self._nest_path[1:]:
            e = e[k]
        if isinstance(e, (Table, TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return e.value
        return e


class ConfigParser:
    """Read TOML configuration file with managed multi-source precedence.

     This class is updatable at run-time, allowing other libraries to add their
     options own configuration options and sub-parsers. Sub-parsers allow
     options groups to exist, e.g. the group "snowflake.cli.output" could have
     2 options in it: debug (boolean flag) and format (a string like "json", or
     "csv").

    When a ConfigParser tries to retrieve ConfigOptions' value the _root_parser
    will read and cache the TOML file from the file it's pointing at, afterwards
    updating the read cache can be forced by calling read_config.

    Attributes:
        name: The name of the ConfigParser. Used for nesting and emitting
          useful error messages.
        file_path: Path to the file where this and all child ConfigParsers
          should read their values out of. Can be omitted for all child
          parsers.
        conf_file_cache: Cache to store what we read from the TOML file.
        _sub_parsers: List of ConfigParsers that are nested under us.
        _options: List of ConfigOptions that are our children.
        _root_parser: Reference to root parser. Used to efficiently propagate to
          child options.
        _nest_path: The names of the ConfigParsers that this parser is nested
          under. Used to efficiently propagate to child options.
    """

    def __init__(
        self,
        *,
        name: str,
        file_path: Path | None = None,
    ):
        """Create a new ConfigParser.

        Args:
            name: Name of this ConfigParser.
            file_path: File this parser should read values from. Can be omitted
              for all child parsers.
        """
        self.name = name
        self.file_path = file_path
        # Objects holding subparsers and options
        self._options: dict[str, ConfigOption] = dict()
        self._sub_parsers: dict[str, ConfigParser] = dict()
        # Dictionary to cache read in config file
        self.conf_file_cache: TOMLDocument | None = None
        # Information necessary to be able to nest elements
        #  and add options in O(1)
        self._root_parser: ConfigParser = self
        self._nest_path = [name]

    def read_config(
        self,
    ) -> None:
        """Read and cache config file."""
        if self.file_path is None:
            raise ConfigParserError(
                "ConfigParser is trying to read config file, but it doesn't have one"
            )
        LOGGER.debug(f"reading configuration file from {str(self.file_path)}")
        try:
            self.conf_file_cache = tomlkit.parse(self.file_path.read_text())
        except Exception as e:
            raise ConfigSourceError(
                f"An unknown error happened while loading '{str(self.file_path)}"
                f"', please see the error: {e}"
            )

    def add_option(
        self,
        *,
        option_cls: type[ConfigOption] = ConfigOption,
        **kwargs,
    ) -> None:
        """Add an ConfigOption to this ConfigParser.

        Args:
            option_cls: The class that should be instantiated. This is class
              should be a child class of ConfigOption. Mainly useful for cases
              where the default ConfigOption needs to be extended, for example
              if a new configuration option source needs to be supported.
        """
        kwargs["_root_parser"] = self._root_parser
        kwargs["_nest_path"] = self._nest_path
        new_option = option_cls(
            **kwargs,
        )
        self._check_child_conflict(new_option.name)
        self._options[new_option.name] = new_option

    def _check_child_conflict(self, name: str) -> None:
        """Check if a sub-parser, or ConfigOption conflicts with given name.

        Args:
            name: Name to check against children.
        """
        if name in (self._options.keys() | self._sub_parsers.keys()):
            raise ConfigParserError(
                f"'{name}' subparser, or option conflicts with a child element of '{self.name}'"
            )

    def add_subparser(self, new_child: ConfigParser) -> None:
        """Nest another ConfigParser under this one.

        This function recursively updates _nest_path and _root_parser of all
        children under new_child.

        Args:
            new_child: The ConfigParser to be nested under the current one.
        Notes:
            We currently don't support re-nesting a ConfigParser. Only nest a
            parser under another one once.
        """
        self._check_child_conflict(new_child.name)
        self._sub_parsers[new_child.name] = new_child

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

        _root_setter_helper(new_child)

    def __getitem__(self, name: str) -> ConfigOption | ConfigParser:
        """Get either sub-parser, or option in this parser with name.

        If option is retrieved, we call get() on it to return its value instead.

        Args:
            name: Name to retrieve.
        """
        if self.conf_file_cache is None and (
            self.file_path is not None
            and self.file_path.exists()
            and self.file_path.is_file()
        ):
            self.read_config()
        if name in self._options:
            return self._options[name].get()
        if name not in self._sub_parsers:
            raise ConfigSourceError(
                "No ConfigParser, or ConfigOption can be found"
                f" with the name '{name}'"
            )
        return self._sub_parsers[name]
