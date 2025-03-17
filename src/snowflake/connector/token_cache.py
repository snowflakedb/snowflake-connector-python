#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import codecs
import hashlib
import json
import logging
import os
import stat
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TypeVar

from .compat import IS_LINUX, IS_MACOS, IS_WINDOWS
from .options import installed_keyring, keyring

KEYRING_DRIVER_NAME = "SNOWFLAKE-PYTHON-DRIVER"


class TokenType(Enum):
    ID_TOKEN = "ID_TOKEN"
    MFA_TOKEN = "MFA_TOKEN"
    OAUTH_ACCESS_TOKEN = "OAUTH_ACCESS_TOKEN"
    OAUTH_REFRESH_TOKEN = "OAUTH_REFRESH_TOKEN"


@dataclass
class TokenKey:
    user: str
    host: str
    tokenType: TokenType

    def string_key(self) -> str:
        return f"{self.host.upper()}:{self.user.upper()}:{self.tokenType.value}"

    def hash_key(self) -> str:
        m = hashlib.sha256()
        m.update(self.string_key().encode(encoding="utf-8"))
        return m.hexdigest()


class TokenCache(ABC):
    @staticmethod
    def make() -> TokenCache:
        if IS_MACOS or IS_WINDOWS:
            if not installed_keyring:
                logging.getLogger(__name__).debug(
                    "Dependency 'keyring' is not installed, cannot cache id token. You might experience "
                    "multiple authentication pop ups while using ExternalBrowser Authenticator. To avoid "
                    "this please install keyring module using the following command : pip install "
                    "snowflake-connector-python[secure-local-storage]"
                )
                return NoopTokenCache()
            return KeyringTokenCache()

        if IS_LINUX:
            return FileTokenCache()

    @abstractmethod
    def store(self, key: TokenKey, token: str) -> None:
        pass

    @abstractmethod
    def retrieve(self, key: TokenKey) -> str | None:
        pass

    @abstractmethod
    def remove(self, key: TokenKey) -> None:
        pass


T = TypeVar("T")


class FileLock:
    def __init__(self, path: Path) -> None:
        self.path: Path = path

    def __enter__(self):
        # TODO Improve locking
        self.path.mkdir(mode=0o700)

    def __exit__(self, exc_type, exc_val, exc_tbc):
        self.path.rmdir()


class FileTokenCacheError(Exception):
    pass


class OwnershipError(FileTokenCacheError):
    pass


class PermissionsTooWideError(FileTokenCacheError):
    pass


class CacheDirNotFoundError(FileTokenCacheError):
    pass


class InvalidCacheDirError(FileTokenCacheError):
    pass


class MalformedCacheFileError(FileTokenCacheError):
    pass


class CacheFileReadError(FileTokenCacheError):
    pass


class CacheFileWriteError(FileTokenCacheError):
    pass


class FileTokenCache(TokenCache):
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.cache_dir: Path | None = self._find_cache_dir()
        self.logger.error(f"Cache dir {self.cache_dir}")

    def store(self, key: TokenKey, token: str) -> None:
        try:
            self._validate_cache_dir(self.cache_dir)
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                cache["tokens"][key.hash_key()] = token
                self._write_cache_file(cache)
        except FileTokenCacheError as e:
            self.logger.error(f"Failed to store token: {type(e)} - {e}")
            return None

    def retrieve(self, key: TokenKey) -> str | None:
        try:
            self._validate_cache_dir(self.cache_dir)
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                return cache["tokens"].get(key.hash_key(), None)
        except FileTokenCacheError as e:
            self.logger.error(f"Failed to retrieve token: {type(e)} - {e}")
            return None

    def remove(self, key: TokenKey) -> None:
        try:
            self._validate_cache_dir(self.cache_dir)
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                cache["tokens"].pop(key.hash_key(), None)
                self._write_cache_file(cache)
        except FileTokenCacheError as e:
            self.logger.error(f"Failed to remove token: {type(e)} - {e}")
            return None

    def cache_file(self) -> Path:
        return self.cache_dir / "credential_cache_v1.json"

    def lock_file(self) -> Path:
        return self.cache_dir / "credential_cache_lock.json.lck"

    def _read_cache_file(self):
        fd = -1
        try:
            fd = os.open(self.cache_file(), os.O_RDONLY)
            self._ensure_permissions(fd, 0o600)
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, size)
            json_data = json.loads(codecs.decode(data, "utf-8"))
            return json_data
        except FileNotFoundError:
            self.logger.debug(f"{self.cache_file()} not found")
            return {"tokens": {}}
        except json.decoder.JSONDecodeError as e:
            self.logger.warning(
                f"Failed to decode json read from cache file {self.cache_file()}: {e}"
            )
            return {"tokens": {}}
        except UnicodeError as e:
            self.logger.warning(
                f"Failed to decode utf-8 read from cache file {self.cache_file()}: {e}"
            )
            return {"tokens": {}}
        except OSError as e:
            self.logger.warning(f"Failed to read cache file {self.cache_file()}: {e}")
            return {"tokens": {}}
        finally:
            if fd > 0:
                os.close(fd)

    def _write_cache_file(self, json_data: dict):
        fd = -1
        self.logger.debug(f"Writing cache file {self.cache_file()}")
        try:
            fd = os.open(
                self.cache_file(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            self._ensure_permissions(fd, 0o600)
            os.write(fd, codecs.encode(json.dumps(json_data), "utf-8"))
            return json_data
        except OSError as e:
            raise CacheFileWriteError("Failed to write cache file", e)
        finally:
            if fd > 0:
                os.close(fd)

    def _find_cache_dir(self) -> Path | None:
        def lookup_env_dir(env_var: str, subpath_segments: list[str]) -> Path | None:
            env_val = os.getenv(env_var)
            if env_val is None:
                self.logger.debug(
                    f"Environment variable {env_var} not set. Skipping it in cache directory lookup."
                )
                return None

            directory = Path(env_val)

            if len(subpath_segments) > 0:
                if not directory.exists():
                    self.logger.debug(
                        f"Path {str(directory)} does not exist. Skipping it in cache directory lookup."
                    )
                    return None

                if not directory.is_dir():
                    self.logger.debug(
                        f"Path {str(directory)} is not a directory. Skipping it in cache directory lookup."
                    )
                    return None

                for subpath in subpath_segments[:-1]:
                    directory = directory / subpath
                    directory.mkdir(exist_ok=True, mode=0o755)

                directory = directory / subpath_segments[-1]
                directory.mkdir(exist_ok=True, mode=0o700)

            try:
                self._validate_cache_dir(directory)
                return directory
            except FileTokenCacheError as e:
                self.logger.debug(
                    f"Cache directory validation failed for {str(directory)} due to error '{e}'. Skipping it in cache directory lookup."
                )
                return None

        lookup_functions = [
            lambda: lookup_env_dir("SF_TEMPORARY_CREDENTIAL_CACHE_DIR", []),
            lambda: lookup_env_dir("XDG_CACHE_HOME", ["snowflake"]),
            lambda: lookup_env_dir("HOME", [".cache", "snowflake"]),
        ]

        for lf in lookup_functions:
            cache_dir = lf()
            if cache_dir:
                return cache_dir

        return None

    def _validate_cache_dir(self, cache_dir: Path | None) -> None:
        try:
            statinfo = cache_dir.stat()

            if cache_dir is None:
                raise CacheDirNotFoundError("Cache dir was not found")

            if not stat.S_ISDIR(statinfo.st_mode):
                raise InvalidCacheDirError(f"Cache dir {cache_dir} is not a directory")

            permissions = stat.S_IMODE(statinfo.st_mode)
            if permissions != 0o700:
                raise PermissionsTooWideError(
                    f"Cache dir {cache_dir} has incorrect permissions. {permissions:o} != 0700"
                )

            euid = os.geteuid()
            if statinfo.st_uid != euid:
                raise OwnershipError(
                    f"Cache dir {cache_dir} has incorrect owner. {euid} != {statinfo.st_uid}"
                )

        except FileNotFoundError:
            raise CacheDirNotFoundError(
                f"Cache dir {cache_dir} was not found. Failed to stat."
            )

    def _ensure_permissions(self, fd: int, permissions: int) -> None:
        try:
            statinfo = os.fstat(fd)
            permissions = stat.S_IMODE(statinfo.st_mode)

            if permissions != 0o600:
                raise PermissionsTooWideError(
                    f"Cache file {self.cache_file()} has incorrect permissions. {permissions:o} != 0600"
                )

            euid = os.geteuid()
            if statinfo.st_uid != euid:
                raise OwnershipError(
                    f"Cache file {self.cache_file()} has incorrect owner. {euid} != {statinfo.st_uid}"
                )

        except FileNotFoundError:
            pass


class KeyringTokenCache(TokenCache):
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def store(self, key: TokenKey, token: str) -> None:
        try:
            keyring.set_password(
                key.string_key(),
                key.user.upper(),
                token,
            )
        except keyring.errors.KeyringError as ke:
            self.logger.error("Could not store id_token to keyring, %s", str(ke))

    def retrieve(self, key: TokenKey) -> str | None:
        try:
            return keyring.get_password(
                key.string_key(),
                key.user.upper(),
            )
        except keyring.errors.KeyringError as ke:
            self.logger.error(
                "Could not retrieve {} from secure storage : {}".format(
                    key.tokenType.value, str(ke)
                )
            )

    def remove(self, key: TokenKey) -> None:
        try:
            keyring.delete_password(
                key.string_key(),
                key.user.upper(),
            )
        except Exception as ex:
            self.logger.error(
                "Failed to delete credential in the keyring: err=[%s]", ex
            )
        pass


class NoopTokenCache(TokenCache):
    def store(self, key: TokenKey, token: str) -> None:
        return None

    def retrieve(self, key: TokenKey) -> str | None:
        return None

    def remove(self, key: TokenKey) -> None:
        return None
