#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


from __future__ import annotations

import logging
import os
from datetime import datetime

import toml

from snowflake.connector.constants import CONNECTIONS_FILE
from snowflake.connector.secret_detector import SecretDetector


class EasyLoggingConfigPython:
    def __init__(self):
        self.log_path = None
        self.log_level = None
        self.config_file_path = CONNECTIONS_FILE
        self.log_file_name = None
        self.parse_config_file()

    def parse_config_file(self):
        with open(self.config_file_path) as f:
            data = toml.load(f)
            if "common" in data:
                if (
                    "log_level" not in data["common"]
                    or "log_path" not in data["common"]
                ):
                    raise ValueError(
                        f"config file at {self.config_file_path} is not in correct form, please verify your config file"
                    )
                data = data["common"]
                self.log_level = data["log_level"]
                self.log_path = data["log_path"]

                # if log path does not exist, create it, else check accessibility
                if not os.path.exists(self.log_path):
                    os.makedirs(self.log_path, exist_ok=True)
                elif not os.access(self.log_path, os.R_OK | os.W_OK):
                    raise PermissionError(
                        f"log path: {self.log_path} is not accessible, please verify your config file"
                    )
                if not os.path.isabs(self.log_path):
                    raise FileNotFoundError(
                        f"given log path {self.log_path} is not full path"
                    )

    # create_log() is called outside __init__() so that it can be easily turned off
    def create_log(self):
        self.log_file_name = f"python_connector_{datetime.now()}.log"
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
