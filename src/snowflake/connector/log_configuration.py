from __future__ import annotations

import logging
import os
from logging.handlers import TimedRotatingFileHandler

from snowflake.connector.config_manager import CONFIG_MANAGER
from snowflake.connector.constants import DIRS
from snowflake.connector.secret_detector import SecretDetector

LOG_FILE_NAME = "python-connector.log"
LOG_FORMAT = (
    "%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - "
    "%(funcName)s() - %(levelname)s - %(message)s"
)
EASY_LOGGING_LOGGERS = ["snowflake.connector", "botocore", "boto3"]


class EasyLoggingConfigPython:
    def __init__(self, skip_config_file_permissions_check: bool = False):
        self.path: str | None = None
        self.level: str | None = None
        self.save_logs: bool = False
        self.parse_config_file(skip_config_file_permissions_check)

    def parse_config_file(self, skip_config_file_permissions_check: bool = False):
        CONFIG_MANAGER.read_config(
            skip_file_permissions_check=skip_config_file_permissions_check
        )
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
        if not self.save_logs:
            return

        log_file_path = os.path.abspath(os.path.join(self.path, LOG_FILE_NAME))
        level = logging.getLevelName(self.level)

        # A single TimedRotatingFileHandler is shared across all easy-logging
        # loggers, keeping exactly one open handle on the log file so rotation
        # works on Windows. create_log() runs on every connection, so skip any
        # logger that already has a rotating handler for this file to avoid
        # stacking handlers (SNOW-3680325).
        handler = None
        for logger_name in EASY_LOGGING_LOGGERS:
            logger = logging.getLogger(logger_name)
            logger.setLevel(level)
            if any(
                isinstance(h, TimedRotatingFileHandler)
                and getattr(h, "baseFilename", None) == log_file_path
                for h in logger.handlers
            ):
                continue
            if handler is None:
                handler = TimedRotatingFileHandler(log_file_path, when="midnight")
                handler.setLevel(level)
                handler.setFormatter(SecretDetector(LOG_FORMAT))
            logger.addHandler(handler)
