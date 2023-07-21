#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os.path
import re
import shutil
import stat
import warnings
from pathlib import Path
from test.randomize import random_string
from textwrap import dedent
from typing import Callable, Dict, Union
from unittest import mock

import pytest
from pytest import raises

from snowflake.connector.compat import IS_WINDOWS

try:
    from snowflake.connector.config_manager import (
        ConfigFileOptions,
        ConfigManager,
        ConfigOption,
    )
    from snowflake.connector.errors import ConfigManagerError, ConfigSourceError
    from snowflake.connector.sf_dirs import SFPlatformDirs, _resolve_platform_dirs
except ImportError:
    # olddriver tests
    pass


def tmp_files_helper(cwd: Path, to_create: files) -> None:
    for k, v in to_create.items():
        new_file = cwd / k
        if isinstance(v, str):
            new_file.touch()
            new_file.write_text(v)
        else:
            new_file.mkdir()
            tmp_files_helper(new_file, v)


files = Dict[str, Union[str, "files"]]


@pytest.fixture
def tmp_files(tmp_path: Path) -> Callable[[files], Path]:
    def create_tmp_files(to_create: files) -> Path:
        tmp_files_helper(tmp_path, to_create)
        return tmp_path

    return create_tmp_files


def test_incorrect_config_read(tmp_files):
    tmp_folder = tmp_files(
        {
            "config.toml": dedent(
                """
                [connections.defa
                """
            )
        }
    )
    config_file = tmp_folder / "config.toml"
    with raises(
        ConfigSourceError,
        match=re.escape(
            f"An unknown error happened while loading '{str(config_file)}'"
        ),
    ):
        ConfigManager(name="test", file_path=config_file).read_config()


def test_simple_config_read(tmp_files):
    tmp_folder = tmp_files(
        {
            "config.toml": dedent(
                """\
                [connections.snowflake]
                account = "snowflake"
                user = "snowball"
                password = "password"

                [settings]
                output_format = "yaml"
                """
            )
        }
    )
    config_file = tmp_folder / "config.toml"
    TEST_PARSER = ConfigManager(
        name="test",
        file_path=config_file,
    )
    from tomlkit import parse

    TEST_PARSER.add_option(
        name="connections",
        parse_str=parse,
    )
    settings_parser = ConfigManager(
        name="settings",
    )
    settings_parser.add_option(
        name="output_format",
        choices=("json", "yaml", "toml"),
    )
    TEST_PARSER.add_subparser(settings_parser)
    assert TEST_PARSER["connections"] == {
        "snowflake": {
            "account": "snowflake",
            "user": "snowball",
            "password": "password",
        }
    }
    assert TEST_PARSER["settings"]["output_format"] == "yaml"


def test_multiple_files(tmp_files):
    """Same test_simple_config_read, but rerads part of the config from another file."""
    tmp_folder = tmp_files(
        {
            "config.toml": dedent(
                """\
                [settings]
                output_format = "json"
                """
            ),
            "connections.toml": dedent(
                """\
                [snowflake]
                account = "snowflake"
                user = "snowball"
                password = "password"
                """
            ),
        }
    )
    TEST_PARSER = ConfigManager(
        name="root_parser",
        file_path=(
            (tmp_folder / "config.toml", ConfigFileOptions(), None),
            (tmp_folder / "connections.toml", ConfigFileOptions(), "connections"),
        ),
    )
    from tomlkit import parse

    TEST_PARSER.add_option(
        name="connections",
        parse_str=parse,
    )
    settings_parser = ConfigManager(
        name="settings",
    )
    settings_parser.add_option(
        name="output_format",
        choices=("json", "yaml", "toml"),
    )
    TEST_PARSER.add_subparser(settings_parser)
    assert TEST_PARSER["connections"] == {
        "snowflake": {
            "account": "snowflake",
            "user": "snowball",
            "password": "password",
        }
    }
    assert TEST_PARSER["settings"]["output_format"] == "json"


def test_simple_nesting(monkeypatch, tmp_path):
    c1 = ConfigManager(name="test", file_path=tmp_path / "config.toml")
    c2 = ConfigManager(name="sb")
    c3 = ConfigManager(name="sb")
    c3.add_option(name="b", parse_str=lambda e: e.lower() == "true")
    c2.add_subparser(c3)
    c1.add_subparser(c2)
    with monkeypatch.context() as m:
        m.setenv("SNOWFLAKE_SB_SB_B", "TrUe")
        assert c1["sb"]["sb"]["b"] is True


def test_complicated_nesting(monkeypatch, tmp_path):
    c_file = tmp_path / "config.toml"
    c1 = ConfigManager(file_path=c_file, name="root_parser")
    c2 = ConfigManager(file_path=tmp_path / "config2.toml", name="sp")
    c2.add_option(name="b", parse_str=lambda e: e.lower() == "true")
    c1.add_subparser(c2)
    c_file.write_text(
        dedent(
            """\
            [connections.default]
            user="testuser"
            account="testaccount"
            password="testpassword"

            [sp]
            b = true
            """
        )
    )
    assert c1["sp"]["b"] is True


def test_error_missing_file_path():
    with pytest.raises(
        ConfigManagerError,
        match="ConfigManager is trying to read config file," " but it doesn't have one",
    ):
        ConfigManager(name="test_parser").read_config()


def test_error_invalid_toml(tmp_path):
    c_file = tmp_path / "c.toml"
    c_file.write_text(
        dedent(
            """\
            invalid toml file
            """
        )
    )
    with pytest.raises(
        ConfigSourceError,
        match=re.escape(f"An unknown error happened while loading '{str(c_file)}'"),
    ):
        ConfigManager(
            name="test_parser",
            file_path=c_file,
        ).read_config()


def test_error_child_conflict():
    cp = ConfigManager(name="test_parser")
    cp.add_subparser(ConfigManager(name="b"))
    with pytest.raises(
        ConfigManagerError,
        match="'b' subparser, or option conflicts with a child element of 'test_parser'",
    ):
        cp.add_option(name="b")


def test_explicit_env_name(monkeypatch):
    rnd_string = random_string(5)
    toml_value = dedent(
        f"""\
        text = "{rnd_string}"
        """
    )
    TEST_PARSER = ConfigManager(
        name="test_parser",
    )

    from tomlkit import parse

    TEST_PARSER.add_option(name="connections", parse_str=parse, env_name="CONNECTIONS")
    with monkeypatch.context() as m:
        m.setenv("CONNECTIONS", toml_value)
        assert TEST_PARSER["connections"] == {"text": rnd_string}


def test_error_contains(monkeypatch):
    tp = ConfigManager(
        name="test_parser",
    )
    tp.add_option(name="output_format", choices=("json", "csv"))
    with monkeypatch.context() as m:
        m.setenv("SNOWFLAKE_OUTPUT_FORMAT", "toml")
        with pytest.raises(
            ConfigSourceError,
            match="The value of output_format read from environment variable "
            "is not part of",
        ):
            tp["output_format"]


def test_error_missing_item():
    tp = ConfigManager(
        name="test_parser",
    )
    with pytest.raises(
        ConfigSourceError,
        match="No ConfigManager, or ConfigOption can be found with the" " name 'asd'",
    ):
        tp["asd"]


def test_error_missing_fp():
    tp = ConfigManager(
        name="test_parser",
    )
    with pytest.raises(
        ConfigManagerError,
        match="ConfigManager is trying to read config file, but it doesn't have one",
    ):
        tp.read_config()


def test_missing_config_file(tmp_path):
    config_file = tmp_path / "config.toml"
    cm = ConfigManager(name="test", file_path=config_file)
    cm.add_option(name="output_format", choices=("json", "yaml"))
    with raises(
        ConfigSourceError,
        match=re.escape(f"The config file '{config_file}' does not exist"),
    ):
        cm["output_format"]


def test_missing_config_files(tmp_path):
    config_file = tmp_path / "config.toml"
    connections_file = tmp_path / "connections.toml"
    cm = ConfigManager(
        name="test",
        file_path=(
            (config_file, ConfigFileOptions(), None),
            (connections_file, ConfigFileOptions(), "connections"),
        ),
    )
    cm.add_option(
        name="connections",
    )
    with raises(
        ConfigSourceError,
        match=re.escape(
            f"None of the config files: {config_file}, {connections_file} exist"
        ),
    ):
        cm["connections"]


def test_error_missing_fp_retrieve():
    tp = ConfigManager(
        name="test_parser",
    )
    tp.add_option(name="option")
    with pytest.raises(
        ConfigManagerError,
        match="Root parser 'test_parser' is missing file_path",
    ):
        tp["option"]


@pytest.mark.parametrize("version", (None, "1"))
@pytest.mark.parametrize(
    "method",
    (
        "user_data_dir",
        "site_data_dir",
        "user_config_dir",
        "site_config_dir",
        "user_cache_dir",
        "user_state_dir",
        "user_log_dir",
        "user_documents_dir",
        "user_runtime_dir",
        "user_music_dir",
        "user_pictures_dir",
        "user_videos_dir",
    ),
)
def test_sf_dirs(tmp_path, method, version):
    appname = random_string(5)
    assert getattr(
        SFPlatformDirs(
            str(tmp_path),
            appname=appname,
            appauthor=False,
            version=version,
            ensure_exists=True,
        ),
        method,
    ) == str(tmp_path)


def test_config_file_resolution_sfdirs_default():
    default_loc = os.path.expanduser("~/.snowflake")
    existed_before = os.path.exists(default_loc)
    os.makedirs(default_loc, exist_ok=True)
    try:
        assert isinstance(_resolve_platform_dirs(), SFPlatformDirs)
    finally:
        if not existed_before:
            shutil.rmtree(default_loc)


def test_config_file_resolution_sfdirs_nondefault(tmp_path, monkeypatch):
    with monkeypatch.context() as m:
        m.setenv("SNOWFLAKE_HOME", str(tmp_path))
        assert isinstance(_resolve_platform_dirs(), SFPlatformDirs)


def test_config_file_resolution_non_sfdirs(monkeypatch):
    with monkeypatch.context() as m:
        m.delenv("SNOWFLAKE_HOME", raising=False)
        assert not isinstance(_resolve_platform_dirs(), SFPlatformDirs)


@pytest.mark.skipif(IS_WINDOWS, reason="no getuid on Windows")
def test_warn_config_file_owner(tmp_path, monkeypatch):
    c_file = tmp_path / "config.toml"
    c1 = ConfigManager(file_path=c_file, name="root_parser")
    c1.add_option(name="b", parse_str=lambda e: e.lower() == "true")
    c_file.write_text(
        dedent(
            """\
            b = true
            """
        )
    )
    c_file.chmod(stat.S_IRUSR | stat.S_IWUSR)
    with mock.patch("os.getuid", return_value=os.getuid() + 1):
        with warnings.catch_warnings(record=True) as c:
            assert c1["b"] is True
        assert len(c) == 1
        assert str(c[0].message) == f"Bad owner or permissions on {str(c_file)}"


def test_warn_config_file_permissions(tmp_path):
    c_file = tmp_path / "config.toml"
    c1 = ConfigManager(file_path=c_file, name="root_parser")
    c1.add_option(name="b", parse_str=lambda e: e.lower() == "true")
    c_file.write_text(
        dedent(
            """\
            b = true
            """
        )
    )
    c_file.chmod(stat.S_IMODE(c_file.stat().st_mode) | stat.S_IROTH)
    with warnings.catch_warnings(record=True) as c:
        assert c1["b"] is True
    assert len(c) == 1
    assert str(c[0].message) == f"Bad owner or permissions on {str(c_file)}"


def test_configoption_missing_root_manager():
    with pytest.raises(
        TypeError,
        match="_root_manager cannot be None",
    ):
        ConfigOption(
            name="test_option",
            _nest_path=["test_option"],
            _root_manager=None,
        )


def test_configoption_missing_nest_path():
    with pytest.raises(
        TypeError,
        match="_nest_path cannot be None",
    ):
        ConfigOption(
            name="test_option",
            _nest_path=None,
            _root_manager=ConfigManager(name="test_manager"),
        )
