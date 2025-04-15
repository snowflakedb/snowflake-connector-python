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
        except OSError as e:
            raise FileLockError(f"Failed to stat lock file {self.path} due to {e=}")

        if statinfo and statinfo.st_ctime < time.time() - STALE_LOCK_AGE_SECONDS:
            self.logger.debug("Removing stale file lock")
            try:
                self.path.rmdir()
            except FileNotFoundError:
                pass
            except OSError as e:
                raise FileLockError(
                    f"Failed to remove stale lock file {self.path} due to {e=}"
                )

        backoff_seconds = INITIAL_BACKOFF_SECONDS
        for attempt in range(MAX_RETRIES):
            self.logger.debug(
                f"Trying to acquire file lock after {backoff_seconds} seconds in attempt number {attempt}.",
            )
            backoff_seconds = backoff_seconds * 2
            try:
                self.path.mkdir(mode=0o700)
                self.locked = True
                break
            except FileExistsError:
                sleep(backoff_seconds)
                continue
            except OSError as e:
                raise FileLockError(
                    f"Failed to acquire lock file {self.path} due to {e=}"
                )

        if not self.locked:
            raise FileLockError(
                f"Failed to acquire file lock, after {MAX_RETRIES} attempts."
            )

    def __exit__(self, exc_type, exc_val, exc_tbc):
        try:
            self.path.rmdir()
        except FileNotFoundError:
            pass
        self.locked = False
