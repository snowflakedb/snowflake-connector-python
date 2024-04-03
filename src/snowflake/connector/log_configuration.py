#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#
from __future__ import annotations

import inspect
import json
import logging
import os

from snowflake.connector.secret_detector import SecretDetector
from src.snowflake.connector import SnowflakeConnection


def is_full_path(path: str) -> bool:
    return os.path.isabs(path)


class EasyLoggingConfigPython:
    def __init__(self, connection_parameters=None):
        self.log_path = None
        self.log_level = None
        self.connection_parameters = connection_parameters
        self.CLIENT_CONFIG_FILE = (
            connection_parameters["CLIENT_CONFIG_FILE"]
            if connection_parameters and "CLIENT_CONFIG_FILE" in connection_parameters
            else None
        )
        self.SF_CLIENT_CONFIG_FILE = (
            os.environ["SF_CLIENT_CONFIG_FILE"]
            if "SF_CLIENT_CONFIG_FILE" in os.environ
            else None
        )
        self.config_file_name = "sf_client_config.json"
        self.log_file_name = "python_connector.log"
        self.log_levels = logging._nameToLevel
        self.parse_config_file()

    def parse_config_file(self):
        config_file_path = self.search_config_file()
        if config_file_path:
            with open(config_file_path) as f:
                data = json.load(f)
                if (
                    "common" not in data
                    or "log_level" not in data["common"]
                    or "log_path" not in data["common"]
                ):
                    raise ValueError(
                        f"config file at {config_file_path} is not in correct form, please verify your config file"
                    )
                data = data["common"]
                self.log_level = data["log_level"]
                self.log_path = data["log_path"]
                if not os.access(self.log_path, os.R_OK | os.W_OK):
                    raise PermissionError(
                        f"log path: {self.log_path} is not accessible, please verify your config file"
                    )
                if self.log_level not in self.log_levels:
                    raise ValueError(
                        f"given log level: {self.log_level} is not valid, allowed log levels: {', '.join(list(self.log_levels.keys()))}"
                    )

    def search_config_file(self) -> str:
        # check connection parameter
        if self.CLIENT_CONFIG_FILE:
            if is_full_path(self.CLIENT_CONFIG_FILE):
                return self.CLIENT_CONFIG_FILE
            else:
                raise FileNotFoundError(
                    f"given file path {self.CLIENT_CONFIG_FILE} is not full path"
                )

        # check environment parameter
        if self.SF_CLIENT_CONFIG_FILE:
            if is_full_path(self.SF_CLIENT_CONFIG_FILE):
                return self.SF_CLIENT_CONFIG_FILE
            else:
                raise FileNotFoundError(
                    f"given file path {self.SF_CLIENT_CONFIG_FILE} is not full path"
                )

        # search under driver directory
        drive_directory = os.path.dirname(inspect.getfile(SnowflakeConnection))
        files = os.listdir(drive_directory)
        if self.config_file_name in files:
            return os.path.join(drive_directory, self.config_file_name)

        # search in user home directory
        home_dir = os.path.expanduser("~")
        files = os.listdir(home_dir)
        if self.config_file_name in files:
            return os.path.join(home_dir, self.config_file_name)

        # return empty str if file is not found
        return ""

    def create_log(self):
        logging.basicConfig(
            filename=self.log_path, level=logging.getLevelName(self.log_level)
        )
        for logger_name in ["snowflake.connector", "botocore", "boto3"]:
            logger = logging.getLogger(logger_name)
            logger.setLevel(logging.getLevelName(self.log_level))
            ch = logging.FileHandler(os.path.join(self.log_path, self.log_file_name))
            ch.setLevel(logging.getLevelName(self.log_level))
            ch.setFormatter(
                SecretDetector(
                    "%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s"
                )
            )
            logger.addHandler(ch)
