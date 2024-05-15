#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from test.integ.conftest import create_connection

import pytest

pytestmark = pytest.mark.skipolddriver

import os.path
from logging import getLogger
from pathlib import Path

try:
    import tomlkit

    from snowflake.connector.config_manager import CONFIG_MANAGER
    from snowflake.connector.constants import CONFIG_FILE
except ModuleNotFoundError:
    pass


@pytest.fixture(scope="function")
def log_directory(tmp_path_factory):
    return tmp_path_factory.mktemp("log")


@pytest.fixture(scope="function")
def temp_config_file(tmp_path_factory):
    return tmp_path_factory.mktemp("config_file_path") / "config.toml"


@pytest.fixture(scope="function")
def config_file_setup(request, temp_config_file, log_directory):
    param = request.param
    CONFIG_MANAGER.file_path = Path(temp_config_file)
    configs = {
        "save_logs": {"log": {"save_logs": True, "path": str(log_directory)}},
        "no_save_logs": {"log": {"save_logs": False, "path": str(log_directory)}},
    }
    try:
        # create temp config file
        with open(temp_config_file, "w") as f:
            f.write(tomlkit.dumps(configs[param]))
        yield
    finally:
        # remove created dir and file, including log paths and config file paths
        CONFIG_MANAGER.file_path = CONFIG_FILE


@pytest.mark.parametrize("config_file_setup", ["save_logs"], indirect=True)
def test_save_logs(db_parameters, config_file_setup, log_directory):
    create_connection("default")

    assert os.path.exists(os.path.join(log_directory, "python-connector.log"))
    with open(os.path.join(log_directory, "python-connector.log")) as f:
        data = f.read()
    try:
        assert "Snowflake Connector for Python" in data
    finally:
        # set logger back to default
        getLogger("snowflake.connector").setLevel(10)
        getLogger("botocore").setLevel(0)
        getLogger("boto3").setLevel(0)


@pytest.mark.parametrize("config_file_setup", ["no_save_logs"], indirect=True)
def test_no_save_logs(config_file_setup, log_directory):
    create_connection("default")

    assert not os.path.exists(os.path.join(log_directory, "python-connector.log"))
