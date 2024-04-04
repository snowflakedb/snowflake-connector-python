#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import os.path

import pytest
import toml

from snowflake.connector import EasyLoggingConfigPython
from snowflake.connector.constants import CONNECTIONS_FILE


@pytest.fixture(scope="function")
def setup1():
    file_path = os.path.dirname(CONNECTIONS_FILE)
    if os.path.exists(file_path):
        with open(CONNECTIONS_FILE) as f:
            connection_content = toml.load(f)
            connection_content["common"] = {"log_level": "wrong"}
        with open(CONNECTIONS_FILE, "w") as f:
            toml.dump(connection_content, f)
    else:
        os.makedirs(file_path, exist_ok=True)
    yield
    with open(CONNECTIONS_FILE, "w") as f:
        connection_content.pop("common")
        toml.dump(connection_content, f)


@pytest.fixture(scope="function")
def setup2():
    file_path = os.path.dirname(CONNECTIONS_FILE)
    if os.path.exists(file_path):
        with open(CONNECTIONS_FILE) as f:
            connection_content = toml.load(f)
            connection_content["common"] = {
                "log_level": "DEBUG",
                "log_path": "incomplete_path/",
            }
        with open(CONNECTIONS_FILE, "w") as f:
            toml.dump(connection_content, f)
    else:
        os.makedirs(file_path, exist_ok=True)
    yield
    with open(CONNECTIONS_FILE, "w") as f:
        connection_content.pop("common")
        toml.dump(connection_content, f)


def test_config_file_wrong_content(setup1):
    try:
        EasyLoggingConfigPython()
    except ValueError as e:
        assert f"config file at {CONNECTIONS_FILE} is not in correct form" in str(e)


def test_log_path_not_full_path(setup2):
    try:
        EasyLoggingConfigPython()
    except FileNotFoundError as e:
        assert "given log path incomplete_path/ is not full path" in str(e)
