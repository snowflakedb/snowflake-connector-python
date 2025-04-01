from __future__ import annotations

import codecs
import json
import logging
import tempfile
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from os import getenv, makedirs, mkdir, path, remove, removedirs, rmdir
from os.path import expanduser
from threading import Lock

from .compat import IS_LINUX, IS_MACOS, IS_WINDOWS
from .file_util import owner_rw_opener
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


class TokenCache(ABC):
    def build_temporary_credential_name(
        self, host: str, user: str, cred_type: TokenType
    ) -> str:
        return "{host}:{user}:{driver}:{cred}".format(
            host=host.upper(),
            user=user.upper(),
            driver=KEYRING_DRIVER_NAME,
            cred=cred_type.value,
        )

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
    def retrieve(self, key: TokenKey) -> str:
        pass

    @abstractmethod
    def remove(self, key: TokenKey) -> None:
        pass


class FileTokenCache(TokenCache):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.CACHE_ROOT_DIR = (
            getenv("SF_TEMPORARY_CREDENTIAL_CACHE_DIR")
            or expanduser("~")
            or tempfile.gettempdir()
        )
        self.CACHE_DIR = path.join(self.CACHE_ROOT_DIR, ".cache", "snowflake")

        if not path.exists(self.CACHE_DIR):
            try:
                makedirs(self.CACHE_DIR, mode=0o700)
            except Exception as ex:
                self.logger.debug(
                    "cannot create a cache directory: [%s], err=[%s]",
                    self.CACHE_DIR,
                    ex,
                )
                self.CACHE_DIR = None
        self.logger.debug("cache directory: %s", self.CACHE_DIR)

        # temporary credential cache
        self.TEMPORARY_CREDENTIAL: dict[str, dict[str, str | None]] = {}

        self.TEMPORARY_CREDENTIAL_LOCK = Lock()

        # temporary credential cache file name
        self.TEMPORARY_CREDENTIAL_FILE = "temporary_credential.json"
        self.TEMPORARY_CREDENTIAL_FILE = (
            path.join(self.CACHE_DIR, self.TEMPORARY_CREDENTIAL_FILE)
            if self.CACHE_DIR
            else ""
        )

        # temporary credential cache lock directory name
        self.TEMPORARY_CREDENTIAL_FILE_LOCK = self.TEMPORARY_CREDENTIAL_FILE + ".lck"

    def flush_temporary_credentials(self) -> None:
        """Flush temporary credentials in memory into disk. Need to hold TEMPORARY_CREDENTIAL_LOCK."""
        for _ in range(10):
            if self.lock_temporary_credential_file():
                break
            time.sleep(1)
        else:
            self.logger.debug(
                "The lock file still persists after the maximum wait time."
                "Will ignore it and write temporary credential file: %s",
                self.TEMPORARY_CREDENTIAL_FILE,
            )
        try:
            with open(
                self.TEMPORARY_CREDENTIAL_FILE,
                "w",
                encoding="utf-8",
                errors="ignore",
                opener=owner_rw_opener,
            ) as f:
                json.dump(self.TEMPORARY_CREDENTIAL, f)
        except Exception as ex:
            self.logger.debug(
                "Failed to write a credential file: " "file=[%s], err=[%s]",
                self.TEMPORARY_CREDENTIAL_FILE,
                ex,
            )
        finally:
            self.unlock_temporary_credential_file()

    def lock_temporary_credential_file(self) -> bool:
        try:
            mkdir(self.TEMPORARY_CREDENTIAL_FILE_LOCK)
            return True
        except OSError:
            self.logger.debug(
                "Temporary cache file lock already exists. Other "
                "process may be updating the temporary "
            )
            return False

    def unlock_temporary_credential_file(self) -> bool:
        try:
            rmdir(self.TEMPORARY_CREDENTIAL_FILE_LOCK)
            return True
        except OSError:
            self.logger.debug("Temporary cache file lock no longer exists.")
            return False

    def write_temporary_credential_file(
        self, host: str, cred_name: str, cred: str
    ) -> None:
        """Writes temporary credential file when OS is Linux."""
        if not self.CACHE_DIR:
            # no cache is enabled
            return
        with self.TEMPORARY_CREDENTIAL_LOCK:
            # update the cache
            host_data = self.TEMPORARY_CREDENTIAL.get(host.upper(), {})
            host_data[cred_name.upper()] = cred
            self.TEMPORARY_CREDENTIAL[host.upper()] = host_data
            self.flush_temporary_credentials()

    def read_temporary_credential_file(self):
        """Reads temporary credential file when OS is Linux."""
        if not self.CACHE_DIR:
            # no cache is enabled
            return

        with self.TEMPORARY_CREDENTIAL_LOCK:
            for _ in range(10):
                if self.lock_temporary_credential_file():
                    break
                time.sleep(1)
            else:
                self.logger.debug(
                    "The lock file still persists. Will ignore and "
                    "write the temporary credential file: %s",
                    self.TEMPORARY_CREDENTIAL_FILE,
                )
            try:
                with codecs.open(
                    self.TEMPORARY_CREDENTIAL_FILE,
                    "r",
                    encoding="utf-8",
                    errors="ignore",
                ) as f:
                    self.TEMPORARY_CREDENTIAL = json.load(f)
                return self.TEMPORARY_CREDENTIAL
            except Exception as ex:
                self.logger.debug(
                    "Failed to read a credential file. The file may not"
                    "exists: file=[%s], err=[%s]",
                    self.TEMPORARY_CREDENTIAL_FILE,
                    ex,
                )
            finally:
                self.unlock_temporary_credential_file()

    def temporary_credential_file_delete_password(
        self, host: str, user: str, cred_type: TokenType
    ) -> None:
        """Remove credential from temporary credential file when OS is Linux."""
        if not self.CACHE_DIR:
            # no cache is enabled
            return
        with self.TEMPORARY_CREDENTIAL_LOCK:
            # update the cache
            host_data = self.TEMPORARY_CREDENTIAL.get(host.upper(), {})
            host_data.pop(
                self.build_temporary_credential_name(host, user, cred_type), None
            )
            if not host_data:
                self.TEMPORARY_CREDENTIAL.pop(host.upper(), None)
            else:
                self.TEMPORARY_CREDENTIAL[host.upper()] = host_data
            self.flush_temporary_credentials()

    def delete_temporary_credential_file(self) -> None:
        """Deletes temporary credential file and its lock file."""
        try:
            remove(self.TEMPORARY_CREDENTIAL_FILE)
        except Exception as ex:
            self.logger.debug(
                "Failed to delete a credential file: " "file=[%s], err=[%s]",
                self.TEMPORARY_CREDENTIAL_FILE,
                ex,
            )
        try:
            removedirs(self.TEMPORARY_CREDENTIAL_FILE_LOCK)
        except Exception as ex:
            self.logger.debug("Failed to delete credential lock file: err=[%s]", ex)

    def store(self, key: TokenKey, token: str) -> None:
        return self.write_temporary_credential_file(
            key.host,
            self.build_temporary_credential_name(key.host, key.user, key.tokenType),
            token,
        )

    def retrieve(self, key: TokenKey) -> str:
        self.read_temporary_credential_file()
        token = self.TEMPORARY_CREDENTIAL.get(key.host.upper(), {}).get(
            self.build_temporary_credential_name(key.host, key.user, key.tokenType)
        )
        return token

    def remove(self, key: TokenKey) -> None:
        return self.temporary_credential_file_delete_password(
            key.host, key.user, key.tokenType
        )


class KeyringTokenCache(TokenCache):
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def store(self, key: TokenKey, token: str) -> None:
        try:
            keyring.set_password(
                self.build_temporary_credential_name(key.host, key.user, key.tokenType),
                key.user.upper(),
                token,
            )
        except keyring.errors.KeyringError as ke:
            self.logger.error("Could not store id_token to keyring, %s", str(ke))

    def retrieve(self, key: TokenKey) -> str:
        try:
            return keyring.get_password(
                self.build_temporary_credential_name(key.host, key.user, key.tokenType),
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
                self.build_temporary_credential_name(key.host, key.user, key.tokenType),
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
