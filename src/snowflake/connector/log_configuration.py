#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#


from __future__ import annotations

import logging
import os
from logging.handlers import TimedRotatingFileHandler

from snowflake.connector.config_manager import CONFIG_MANAGER
from snowflake.connector.constants import DIRS
from snowflake.connector.secret_detector import SecretDetector


class EasyLoggingConfigPython:
    def __init__(self):
        self.path = None
        self.level = None
        self.save_logs = None
        self.log_file_name = None
        self.parse_config_file()

    def parse_config_file(self):
        CONFIG_MANAGER.read_config()
        data = CONFIG_MANAGER.conf_file_cache
        if log := data.get("log"):
            self.save_logs = log.get("save_logs", False)
            self.level = log.get("level", "INFO")
            self.path = log.get("path", os.path.join(DIRS.user_config_path, "logs"))

            if not os.path.isabs(self.path):
                raise FileNotFoundError(
                    f"Log path must be an absolute file path: {self.path}"
                )
            # if log path does not exist, create it, else check accessibility
            if not os.path.exists(self.path):
                os.makedirs(self.path, exist_ok=True)
            elif not os.access(self.path, os.R_OK | os.W_OK):
                raise PermissionError(
                    f"log path: {self.path} is not accessible, please verify your config file"
                )

    # create_log() is called outside __init__() so that it can be easily turned off
    def create_log(self):
        if self.save_logs:
            self.log_file_name = "python-connector.log"
            logging.basicConfig(
                filename=os.path.join(self.path, self.log_file_name),
                level=logging.getLevelName(self.level),
            )
            for logger_name in ["snowflake.connector", "botocore", "boto3"]:
                logger = logging.getLogger(logger_name)
                logger.setLevel(logging.getLevelName(self.level))
                ch = TimedRotatingFileHandler(
                    os.path.join(self.path, self.log_file_name), when="midnight"
                )
                ch.setLevel(logging.getLevelName(self.level))
                ch.setFormatter(
                    SecretDetector(
                        "%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s"
                    )
                )
                logger.addHandler(ch)
