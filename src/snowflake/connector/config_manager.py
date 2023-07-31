#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import itertools
import logging
import os
import stat
from collections.abc import Iterable
from operator import methodcaller
from pathlib import Path
from typing import Any, Callable, Literal, NamedTuple, TypeVar
from warnings import warn

import tomlkit
from tomlkit.items import Table

from snowflake.connector.constants import CONFIG_FILE, CONNECTIONS_FILE
from snowflake.connector.errors import (
    ConfigManagerError,
    ConfigSourceError,
    MissingConfigOptionError,
)

_T = TypeVar("_T")

LOGGER = logging.getLogger(__name__)
READABLE_BY_OTHERS = stat.S_IRGRP | stat.S_IROTH


class ConfigSliceOptions(NamedTuple):
    """Class that defines settings individual configuration files."""

    check_permissions: bool = True
    only_in_slice: bool = False


class ConfigSlice(NamedTuple):
    path: Path
    options: ConfigSliceOptions
    section: str


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
        _root_manager: Reference to the root parser. Used to efficiently
          refer to cached config file. Is supplied by the parent
          ConfigManager.
        _nest_path: The names of the ConfigManagers that this option is
          nested in. Used be able to efficiently resolve where to grab
          value out of configuration file and construct environment
          variable name. This is supplied by the parent ConfigManager.
    """

    def __init__(
        self,
        *,
        name: str,
        parse_str: Callable[[str], _T] | None = None,
        choices: Iterable[Any] | None = None,
        env_name: str | None | Literal[False] = None,
        _root_manager: ConfigManager | None = None,
        _nest_path: list[str] | None,
    ) -> None:
        """Create a config option that can read values from different locations.

        Args:
            name: Name to assign to this ConfigOption.
            parse_str: String parser function for this ConfigOption.
            choices: List of possible values for this ConfigOption.
            env_name: Environmental variable name value should be read from.
            _root_manager: Reference to the root parser. Should be supplied by
              the parent ConfigManager.
            _nest_path: The names of the ConfigManagers that this option is
              nested in. This is supplied by the parent ConfigManager.
        """
        if _root_manager is None:
            raise TypeError("_root_manager cannot be None")
        if _nest_path is None:
            raise TypeError("_nest_path cannot be None")
        self.name = name
        self.parse_str = parse_str
        self.choices = choices
        self._nest_path = _nest_path + [name]
        self._root_manager: ConfigManager = _root_manager
        self.env_name = env_name

    def value(self) -> Any:
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
        pieces = map(methodcaller("upper"), self._nest_path[1:])
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
        env_var = os.environ.get(env_name)
        if env_var is None:
            return False, None
        loaded_var: str | _T | None = env_var
        if env_var and self.parse_str is not None:
            loaded_var = self.parse_str(env_var)
        if isinstance(loaded_var, (Table, tomlkit.TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return True, loaded_var.value
        return True, loaded_var

    def _get_config(self) -> Any:
        """Get value from the cached config file."""
        if (
            self._root_manager.conf_file_cache is None
            and self._root_manager.file_path is not None
        ):
            self._root_manager.read_config()
        e = self._root_manager.conf_file_cache
        if e is None:
            raise ConfigManagerError(
                f"Root parser '{self._root_manager.name}' is missing file_path",
            )
        for k in self._nest_path[1:]:
            try:
                e = e[k]
            except tomlkit.exceptions.NonExistentKey:
                raise MissingConfigOptionError(  # TOOO: maybe a child Exception for missing option?
                    f"Configuration option '{self.option_name}' is not defined anywhere, "
                    "have you forgotten to set it in a configuration file, "
                    "or environmental variable?"
                )

        if isinstance(e, (Table, tomlkit.TOMLDocument)):
            # If we got a TOML table we probably want it in dictionary form
            return e.value
        return e


class ConfigManager:
    """Read TOML configuration file with managed multi-source precedence.

     This class is updatable at run-time, allowing other libraries to add their
    own configuration options and sub-parsers. Sub-parsers allow
     options groups to exist, e.g. the group "snowflake.cli.output" could have
     2 options in it: debug (boolean flag) and format (a string like "json", or
     "csv").

    When a ConfigManager tries to retrieve ConfigOptions' value the _root_manager
    will read and cache the TOML file from the file it's pointing at, afterwards
    updating the read cache can be forced by calling read_config.

    Attributes:
        name: The name of the ConfigManager. Used for nesting and emitting
          useful error messages.
        file_path: Path to the file where this and all child ConfigManagers
          should read their values out of. Can be omitted for all child
          parsers.
        conf_file_cache: Cache to store what we read from the TOML file.
        _sub_parsers: List of ConfigManagers that are nested under us.
        _options: List of ConfigOptions that are our children.
        _root_manager: Reference to root parser. Used to efficiently propagate to
          child options.
        _nest_path: The names of the ConfigManagers that this parser is nested
          under. Used to efficiently propagate to child options.
    """

    def __init__(
        self,
        *,
        name: str,
        file_path: Path | None = None,
        _slices: list[ConfigSlice] | None = None,
    ):
        """Create a new ConfigManager.

        Args:
            name: Name of this ConfigManager.
            file_path: File this parser should read values from. Can be omitted
              for all child parsers.
        """
        if _slices is None:
            _slices = list()
        self.name = name
        self.file_path = file_path
        self._slices = _slices
        # Objects holding subparsers and options
        self._options: dict[str, ConfigOption] = dict()
        self._sub_parsers: dict[str, ConfigManager] = dict()
        # Dictionary to cache read in config file
        self.conf_file_cache: tomlkit.TOMLDocument | None = None
        # Information necessary to be able to nest elements
        #  and add options in O(1)
        self._root_manager: ConfigManager = self
        self._nest_path = [name]

    def read_config(
        self,
    ) -> None:
        """Read and cache config file.

        This function should be called if the ConfigManager's cache is outdated.
        Maybe in the case when we want to replace the file_path assigned to a
        ConfigManager, or if one's doing development and are interactively
        adding new options to their configuration files.
        """
        if self.file_path is None:
            raise ConfigManagerError(
                "ConfigManager is trying to read config file, but it doesn't "
                "have one"
            )
        read_config_file = tomlkit.TOMLDocument()

        # Read in all of the config slices
        for filep, sliceoptions, section in itertools.chain(
            ((self.file_path, ConfigSliceOptions(), None),),
            self._slices,
        ):
            if sliceoptions.only_in_slice:
                del read_config_file[section]
            if not filep.exists():
                continue
            if (
                sliceoptions.check_permissions  # Skip checking if this file couldn't hold sensitive information
                # Same check as openssh does for permissions
                #  https://github.com/openssh/openssh-portable/blob/2709809fd616a0991dc18e3a58dea10fb383c3f0/readconf.c#LL2264C1-L2264C1
                and filep.stat().st_mode & READABLE_BY_OTHERS != 0
                or (
                    # Windows doesn't have getuid, skip checking
                    hasattr(os, "getuid")
                    and filep.stat().st_uid != 0
                    and filep.stat().st_uid != os.getuid()
                )
            ):
                warn(f"Bad owner or permissions on {str(filep)}")
            LOGGER.debug(f"reading configuration file from {str(filep)}")
            try:
                read_config_piece = tomlkit.parse(filep.read_text())
            except Exception as e:
                raise ConfigSourceError(
                    "An unknown error happened while loading " f"'{str(filep)}'"
                ) from e
            if section is None:
                read_config_file = read_config_piece
            else:
                read_config_file[section] = read_config_piece
        self.conf_file_cache = read_config_file

    def add_option(
        self,
        *,
        option_cls: type[ConfigOption] = ConfigOption,
        **kwargs,
    ) -> None:
        """Add an ConfigOption to this ConfigManager.

        Args:
            option_cls: The class that should be instantiated. This is class
              should be a child class of ConfigOption. Mainly useful for cases
              where the default ConfigOption needs to be extended, for example
              if a new configuration option source needs to be supported.
        """
        kwargs["_root_manager"] = self._root_manager
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
            raise ConfigManagerError(
                f"'{name}' subparser, or option conflicts with a child element of '{self.name}'"
            )

    def add_subparser(self, new_child: ConfigManager) -> None:
        """Nest another ConfigManager under this one.

        This function recursively updates _nest_path and _root_manager of all
        children under new_child.

        Args:
            new_child: The ConfigManager to be nested under the current one.
        Notes:
            We currently don't support re-nesting a ConfigManager. Only nest a
            parser under another one once.
        """
        self._check_child_conflict(new_child.name)
        self._sub_parsers[new_child.name] = new_child

        def _root_setter_helper(node: ConfigManager):
            # Deal with ConfigManagers
            node._root_manager = self._root_manager
            node._nest_path = self._nest_path + node._nest_path
            for sub_parser in node._sub_parsers.values():
                _root_setter_helper(sub_parser)
            # Deal with ConfigOptions
            for option in node._options.values():
                option._root_manager = self._root_manager
                option._nest_path = self._nest_path + option._nest_path

        _root_setter_helper(new_child)

    def __getitem__(self, name: str) -> ConfigOption | ConfigManager:
        """Get either sub-parser, or option in this parser with name.

        If option is retrieved, we call get() on it to return its value instead.

        Args:
            name: Name to retrieve.
        """
        if name in self._options:
            return self._options[name].value()
        if name not in self._sub_parsers:
            raise ConfigSourceError(
                "No ConfigManager, or ConfigOption can be found"
                f" with the name '{name}'"
            )
        return self._sub_parsers[name]


CONFIG_PARSER = ConfigManager(
    name="CONFIG_PARSER",
    file_path=CONFIG_FILE,
    _slices=[
        ConfigSlice(  # Optional connections file to read in connections from
            CONNECTIONS_FILE,
            ConfigSliceOptions(
                check_permissions=True,  # connections could live here, check permissions
            ),
            "connections",
        ),
    ],
)
CONFIG_PARSER.add_option(
    name="connections",
    parse_str=tomlkit.parse,
)

__all__ = [
    "ConfigOption",
    "ConfigManager",
    "CONFIG_PARSER",
]
