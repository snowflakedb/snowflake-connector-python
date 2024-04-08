#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


import os.path

import pytest
import tomlkit

from snowflake.connector import EasyLoggingConfigPython
from snowflake.connector.constants import CONFIG_FILE


@pytest.fixture(scope="function")
def setup1():
    file_path = os.path.dirname(CONFIG_FILE)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            connection_content = tomlkit.parse(f.read())
            connection_content["log"] = {"log_level": "wrong"}
        with open(CONFIG_FILE, "w") as f:
            f.write(tomlkit.dumps(connection_content))
    else:
        os.makedirs(file_path, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            connection_content = {
                "log": {
                    "level": "wrong",
                }
            }
            f.write(tomlkit.dumps(connection_content))
    yield
    with open(CONFIG_FILE, "w") as f:
        connection_content.pop("log")
        f.write(tomlkit.dumps(connection_content))


@pytest.fixture(scope="function")
def setup2():
    file_path = os.path.dirname(CONFIG_FILE)
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            connection_content = tomlkit.parse(f.read())
            connection_content["log"] = {
                "level": "DEBUG",
                "path": "incomplete_path/",
            }
        with open(CONFIG_FILE, "w") as f:
            f.write(tomlkit.dumps(connection_content))
    else:
        os.makedirs(file_path, exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            connection_content = {
                "log": {
                    "level": "DEBUG",
                    "path": "incomplete_path/",
                }
            }
            f.write(tomlkit.dumps(connection_content))
    yield
    with open(CONFIG_FILE, "w") as f:
        connection_content.pop("log")
        f.write(tomlkit.dumps(connection_content))


@pytest.mark.skipolddriver
def test_config_file_wrong_content(setup1):
    try:
        EasyLoggingConfigPython()
    except ValueError as e:
        assert f"config file at {CONFIG_FILE} is not in correct form" in str(e)


@pytest.mark.skipolddriver
def test_log_path_not_full_path(setup2):
    try:
        EasyLoggingConfigPython()
    except FileNotFoundError as e:
        assert "Log path must be an absolute file path: incomplete_path/" in str(e)
