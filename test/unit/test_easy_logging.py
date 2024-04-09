#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


import os.path
from pathlib import Path

import pytest
import tomlkit

from snowflake.connector import EasyLoggingConfigPython
from snowflake.connector.config_manager import CONFIG_MANAGER
from snowflake.connector.constants import CONFIG_FILE

THIS_DIR = os.path.dirname(os.path.realpath(__file__))
TEMP_CONFIG_FILE_DIR = os.path.join(THIS_DIR, "..", "data")
NONEXIST_PATH = os.path.join(THIS_DIR, "..", "data", "non_exist")
INABSOLUTE_PATH = os.path.join("..", "data")
INACCESSIBLE_PATH = os.path.join(THIS_DIR, "..", "data", "inaccessible")


@pytest.fixture(scope="function")
def config_file_setup(request):
    param = request.param
    # making different config file dir for each test to avoid race condition on modifying config.toml
    os.makedirs(os.path.join(TEMP_CONFIG_FILE_DIR, param), exist_ok=True)
    temp_config_file_path = os.path.join(TEMP_CONFIG_FILE_DIR, param, "config.toml")
    CONFIG_MANAGER.file_path = Path(temp_config_file_path)

    configs = {
        "nonexist_path": {"log": {"save_logs": False, "path": NONEXIST_PATH}},
        "inabsolute_path": {"log": {"save_logs": False, "path": INABSOLUTE_PATH}},
        "inaccessible_path": {"log": {"save_logs": False, "path": INACCESSIBLE_PATH}},
    }
    # create inaccessible path and make it inaccessible
    if not os.path.exists(INACCESSIBLE_PATH):
        os.mkdir(INACCESSIBLE_PATH)
    os.chmod(INACCESSIBLE_PATH, os.stat(INACCESSIBLE_PATH).st_mode & ~0o222)
    try:
        # create temp config file
        with open(temp_config_file_path, "w") as f:
            f.write(tomlkit.dumps(configs[param]))
        yield
    finally:
        # remove created dir and file, including log paths and config file paths
        CONFIG_MANAGER.file_path = CONFIG_FILE
        os.remove(temp_config_file_path)
        os.rmdir(os.path.join(TEMP_CONFIG_FILE_DIR, param))

        if os.path.exists(NONEXIST_PATH):
            os.rmdir(NONEXIST_PATH)
        if os.path.exists(INACCESSIBLE_PATH):
            os.rmdir(INACCESSIBLE_PATH)


@pytest.mark.parametrize("config_file_setup", ["nonexist_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_nonexist_path(config_file_setup):
    assert not os.path.exists(NONEXIST_PATH)
    EasyLoggingConfigPython()
    assert os.path.exists(NONEXIST_PATH)


@pytest.mark.parametrize("config_file_setup", ["inabsolute_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_inabsolute_path(config_file_setup):
    try:
        EasyLoggingConfigPython()
    except FileNotFoundError as e:
        assert f"Log path must be an absolute file path: {INABSOLUTE_PATH}" in str(e)


@pytest.mark.parametrize("config_file_setup", ["inaccessible_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_inaccessible_path(config_file_setup):
    try:
        EasyLoggingConfigPython()
    except PermissionError as e:
        assert (
            f"log path: {INACCESSIBLE_PATH} is not accessible, please verify your config file"
            in str(e)
        )
