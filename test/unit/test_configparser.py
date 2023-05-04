#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from pathlib import Path
from test.randomize import random_string
from textwrap import dedent
from typing import Callable, Dict, Union

import pytest
from pytest import raises

try:
    from snowflake.connector.config_parser import ConfigParser
    from snowflake.connector.errors import ConfigParserError, ConfigSourceError
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
    with raises(ConfigSourceError) as ex:
        ConfigParser(name="test", file_path=config_file).read_config()
    assert ex.match(f"An unknown error happened while loading '{str(config_file)}'")


def test_simple_config_read(tmp_files):
    tmp_folder = tmp_files(
        {
            "config.toml": dedent(
                """\
                [connections.snowflake]
                account = "snowflake"
                user = "snowball"
                password = "password"
                """
            )
        }
    )
    config_file = tmp_folder / "config.toml"
    TEST_PARSER = ConfigParser(
        name="test",
        file_path=config_file,
    )
    from tomlkit import parse

    TEST_PARSER.add_option(
        "connections",
        _type=parse,
    )
    assert TEST_PARSER["connections"] == {
        "snowflake": {
            "account": "snowflake",
            "user": "snowball",
            "password": "password",
        }
    }


def test_simple_nesting(monkeypatch, tmp_path):
    c1 = ConfigParser(name="test", file_path=tmp_path / "config.toml")
    c2 = ConfigParser(name="sb")
    c3 = ConfigParser(name="sb")
    c3.add_option(name="b", _type=lambda e: e.lower() == "true")
    c2.add_subparser(c3)
    c1.add_subparser(c2)
    with monkeypatch.context() as m:
        m.setenv("SF_SB_SB_B", "TrUe")
        assert c1["sb"]["sb"]["b"] is True


def test_complicated_nesting(monkeypatch, tmp_path):
    c_file = tmp_path / "config.toml"
    c1 = ConfigParser(file_path=c_file, name="root_parser")
    c2 = ConfigParser(file_path=tmp_path / "config2.toml", name="sp")
    c2.add_option(name="b", _type=lambda e: e.lower() == "true")
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
        ConfigParserError,
        match="ConfigParser is trying to read config file," " but it doesn't have one",
    ):
        ConfigParser(name="test_parser").read_config()


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
        match=f"An unknown error happened while loading '{str(c_file)}'",
    ):
        ConfigParser(
            name="test_parser",
            file_path=c_file,
        ).read_config()


def test_error_child_conflict():
    cp = ConfigParser(name="test_parser")
    cp.add_subparser(ConfigParser(name="b"))
    with pytest.raises(
        ConfigParserError,
        match="'b' subparser, or option conflicts with a child element of 'test_parser'",
    ):
        cp.add_option("b")


def test_explicit_env_name(monkeypatch):
    rnd_string = random_string(5)
    toml_value = dedent(
        f"""\
        text = "{rnd_string}"
        """
    )
    TEST_PARSER = ConfigParser(
        name="test_parser",
    )

    from tomlkit import parse

    TEST_PARSER.add_option("connections", _type=parse, env_name="CONNECTIONS")
    with monkeypatch.context() as m:
        m.setenv("CONNECTIONS", toml_value)
        assert TEST_PARSER["connections"] == {"text": rnd_string}


def test_error_contains(monkeypatch):
    tp = ConfigParser(
        name="test_parser",
    )
    tp.add_option("output_format", choices=("json", "csv"))
    with monkeypatch.context() as m:
        m.setenv("SF_OUTPUT_FORMAT", "toml")
        with pytest.raises(
            ConfigSourceError,
            match="The value of output_format read from environment variable "
            "is not part of",
        ):
            tp["output_format"]


def test_missing_item():
    tp = ConfigParser(
        name="test_parser",
    )
    with pytest.raises(
        ConfigSourceError,
        match="No ConfigParser, or ConfigOption can be found with the" " name 'asd'",
    ):
        tp["asd"]
