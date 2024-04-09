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


@pytest.fixture(scope="function")
def temp_config_file(tmp_path_factory):
    return tmp_path_factory.mktemp("config_file_path") / "config.toml"


@pytest.fixture(scope="module")
def nonexist_file(tmp_path_factory):
    return tmp_path_factory.mktemp("log_path") / "nonexist_file"


@pytest.fixture(scope="module")
def inaccessible_file(tmp_path_factory):
    return tmp_path_factory.mktemp("inaccessible_file")


@pytest.fixture(scope="module")
def inabsolute_file(tmp_path_factory):
    directory = tmp_path_factory.mktemp("inabsolute_file")
    return os.path.basename(directory)


@pytest.fixture(scope="function")
def config_file_setup(
    request, temp_config_file, nonexist_file, inaccessible_file, inabsolute_file
):
    param = request.param
    # making different config file dir for each test to avoid race condition on modifying config.toml
    CONFIG_MANAGER.file_path = Path(temp_config_file)
    configs = {
        "nonexist_path": {"log": {"save_logs": False, "path": str(nonexist_file)}},
        "inabsolute_path": {"log": {"save_logs": False, "path": str(inabsolute_file)}},
        "inaccessible_path": {
            "log": {"save_logs": False, "path": str(inaccessible_file)}
        },
    }
    # create inaccessible path and make it inaccessible
    os.chmod(inaccessible_file, os.stat(inaccessible_file).st_mode & ~0o222)
    try:
        # create temp config file
        with open(temp_config_file, "w") as f:
            f.write(tomlkit.dumps(configs[param]))
        yield
    finally:
        # remove created dir and file, including log paths and config file paths
        CONFIG_MANAGER.file_path = CONFIG_FILE


@pytest.mark.parametrize("config_file_setup", ["nonexist_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_nonexist_path(config_file_setup, nonexist_file):
    assert not os.path.exists(nonexist_file)
    EasyLoggingConfigPython()
    assert os.path.exists(nonexist_file)


@pytest.mark.parametrize("config_file_setup", ["inabsolute_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_inabsolute_path(config_file_setup, inabsolute_file):
    with pytest.raises(FileNotFoundError) as e:
        EasyLoggingConfigPython()
    assert f"Log path must be an absolute file path: {str(inabsolute_file)}" in str(e)


@pytest.mark.parametrize("config_file_setup", ["inaccessible_path"], indirect=True)
@pytest.mark.skipolddriver
def test_config_file_inaccessible_path(config_file_setup, inaccessible_file):
    with pytest.raises(PermissionError) as e:
        EasyLoggingConfigPython()
    assert (
        f"log path: {str(inaccessible_file)} is not accessible, please verify your config file"
        in str(e)
    )
