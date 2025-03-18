#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
import time
from os import stat_result
from pathlib import Path
from time import sleep

MAX_RETRIES = 5
INITIAL_BACKOFF_SECONDS = 0.025
STALE_LOCK_AGE_SECONDS = 1


class FileLockError(Exception):
    pass


class FileLock:
    def __init__(self, path: Path) -> None:
        self.path: Path = path
        self.locked = False
        self.logger = logging.getLogger(__name__)

    def __enter__(self):
        statinfo: stat_result | None = None
        try:
            statinfo = self.path.stat()
        except FileNotFoundError:
            pass

        if statinfo and statinfo.st_ctime < time.time() - STALE_LOCK_AGE_SECONDS:
            self.logger.debug("Removing stale file lock")
            try:
                self.path.rmdir()
            except OSError:
                pass

            try:
                self.path.mkdir(mode=0o700)
                self.locked = True
            except FileExistsError:
                pass

        backoff_seconds = INITIAL_BACKOFF_SECONDS
        for attempt in range(MAX_RETRIES):
            self.logger.debug(
                "Trying to acquire file lock after %d seconds in attempt number %d.",
                backoff_seconds,
                attempt,
            )
            backoff_seconds = backoff_seconds * 2
            try:
                self.path.mkdir(mode=0o700)
                self.locked = True
                break
            except FileExistsError:
                sleep(backoff_seconds)
                continue

        if not self.locked:
            raise FileLockError()

    def __exit__(self, exc_type, exc_val, exc_tbc):
        self.path.rmdir()
        self.locked = False
