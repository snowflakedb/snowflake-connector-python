from __future__ import annotations

import logging
import os
import threading
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

# Serializes handler discovery and registration in create_log(). create_log()
# runs on every connection and connections may be opened concurrently from
# multiple threads, so without this lock two callers could both observe "no
# handler yet" and each attach their own TimedRotatingFileHandler, leaving two
# open handles on the same file and breaking rotation on Windows (SNOW-3680325).
_handler_lock = threading.Lock()


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

        # create_log() runs on every connection. A single TimedRotatingFileHandler
        # is shared across all easy-logging loggers, keeping exactly one open
        # handle on the log file so rotation works on Windows. The whole
        # find-or-create-then-attach block is serialized so concurrent
        # connections cannot each attach their own handler (SNOW-3680325).
        with _handler_lock:
            # Reuse an already-registered handler for this file if one exists on
            # any of the loggers. Looking across all of them (rather than lazily
            # creating one when a given logger has none) heals partial state: if
            # the handler was detached from some loggers but not others, the
            # remaining loggers are reattached to the same instance instead of
            # getting a second handler on the same file.
            handler = next(
                (
                    h
                    for logger_name in EASY_LOGGING_LOGGERS
                    for h in logging.getLogger(logger_name).handlers
                    if isinstance(h, TimedRotatingFileHandler)
                    and getattr(h, "baseFilename", None) == log_file_path
                ),
                None,
            )
            if handler is None:
                handler = TimedRotatingFileHandler(log_file_path, when="midnight")
                handler.setFormatter(SecretDetector(LOG_FORMAT))

            # Re-apply the configured level on every call so that a later
            # connection raising or lowering the level is reflected even when
            # the handler is reused.
            handler.setLevel(level)
            for logger_name in EASY_LOGGING_LOGGERS:
                logger = logging.getLogger(logger_name)
                logger.setLevel(level)
                if handler not in logger.handlers:
                    logger.addHandler(handler)
