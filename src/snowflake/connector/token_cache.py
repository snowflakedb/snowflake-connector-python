from __future__ import annotations

import codecs
import hashlib
import json
import logging
import os
import re
import stat
import sys
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

from .compat import IS_LINUX, IS_MACOS, IS_WINDOWS
from .file_lock import FileLock, FileLockError
from .options import installed_keyring, keyring

logger = logging.getLogger(__name__)
T = TypeVar("T")


class TokenType(Enum):
    """Types of credentials that can be cached to avoid repeated authentication.

    - ID_TOKEN: SSO identity token from external browser/Okta authentication
    - MFA_TOKEN: Multi-factor authentication token to skip MFA prompts
    - OAUTH_ACCESS_TOKEN: Short-lived OAuth access token
    - OAUTH_REFRESH_TOKEN: Long-lived OAuth token to obtain new access tokens
    """

    ID_TOKEN = "ID_TOKEN"
    MFA_TOKEN = "MFA_TOKEN"
    OAUTH_ACCESS_TOKEN = "OAUTH_ACCESS_TOKEN"
    OAUTH_REFRESH_TOKEN = "OAUTH_REFRESH_TOKEN"


class _InvalidTokenKeyError(Exception):
    pass


@dataclass
class TokenKey:
    """Key identifying a cached token.

    ``snowflake`` and ``username`` are required for all flows.
    ``idp`` and ``role`` are used only for OAuth flows; they default to ``""``
    and are ignored by ``build_cache_key`` for MFA and ID token flows.
    Raw (un-normalized) values are acceptable; ``build_cache_key`` normalizes
    them before hashing.

    Fields:
        token_type: The type of token being cached.
        snowflake: Snowflake server URL.
        username: Snowflake login name.
        idp: IdP / token-endpoint URL (OAuth flows only).
        role: Snowflake role (OAuth flows only).
    """

    token_type: TokenType
    snowflake: str
    username: str
    idp: str = ""
    role: str = ""


def normalize_url(url: str) -> str:
    """Strip scheme and userinfo, drop query/fragment, trim root slash, uppercase."""
    s = re.sub(r"^https?://", "", url)
    at = s.find("@")
    if at >= 0:
        s = s[at + 1 :]
    s = s.split("?")[0].split("#")[0]
    s = s.rstrip("/")
    return s.upper()


def normalize_identifier(identifier: str) -> str:
    """Uppercase unquoted segments; preserve double-quoted segments verbatim."""
    result = []
    in_quotes = False
    for ch in identifier:
        if ch == '"':
            in_quotes = not in_quotes
            result.append(ch)
        elif in_quotes:
            result.append(ch)
        else:
            result.append(ch.upper())
    return "".join(result)


_OAUTH_TYPES: frozenset[str] = frozenset(
    {
        "OAUTH_ACCESS_TOKEN",
        "OAUTH_REFRESH_TOKEN",
        "DPOP_BUNDLED_ACCESS_TOKEN",
    }
)


def build_cache_key(key: TokenKey) -> str:
    """Build the versioned, uniformly-hashed v2 cache key.

    Format: ``SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex(canonical_json)>``

    ``keyData`` is flow-dependent and never contains ``token_type``:

    - OAuth (``OAUTH_ACCESS_TOKEN``, ``OAUTH_REFRESH_TOKEN``,
      ``DPOP_BUNDLED_ACCESS_TOKEN``): 4 fields — ``idp``, ``role``,
      ``snowflake``, ``username``.
    - MFA / ID token (``MFA_TOKEN``, ``ID_TOKEN``): 2 fields —
      ``snowflake``, ``username`` only.

    The canonical JSON is compact (no whitespace) with keys sorted
    lexicographically, serialized to UTF-8. Hashing occurs exactly once here;
    cache backends store and retrieve the returned string verbatim.
    """
    if not key.snowflake:
        raise _InvalidTokenKeyError("snowflake URL must not be empty")
    if not key.username:
        raise _InvalidTokenKeyError("username must not be empty")

    token_type_value = key.token_type.value

    if token_type_value in _OAUTH_TYPES:
        key_data: dict[str, str] = {
            "idp": normalize_url(key.idp or ""),
            "role": normalize_identifier(key.role or ""),
            "snowflake": normalize_url(key.snowflake),
            "username": normalize_identifier(key.username),
        }
    else:
        # MFA_TOKEN, ID_TOKEN — idp and role are not part of the key
        key_data = {
            "snowflake": normalize_url(key.snowflake),
            "username": normalize_identifier(key.username),
        }

    canonical = json.dumps(key_data, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"SnowflakeTokenCache.v2.{token_type_value}.{digest}"


def _legacy_string_key(key: TokenKey) -> str:
    """Reconstruct the pre-v2 ``{HOST}:{USER}:{TOKEN_TYPE}`` string key.

    OAuth tokens historically keyed on the IdP hostname
    (``urlparse(token_request_url).hostname``); all other flows keyed on the
    Snowflake host. Used only to locate and migrate legacy cache entries.
    """
    if key.token_type in (
        TokenType.OAUTH_ACCESS_TOKEN,
        TokenType.OAUTH_REFRESH_TOKEN,
    ):
        host = urllib.parse.urlparse(key.idp).hostname or key.idp
    else:
        host = key.snowflake
    if not host:
        raise _InvalidTokenKeyError("Invalid key, host is empty")
    if not key.username:
        raise _InvalidTokenKeyError("Invalid key, user is empty")
    return f"{host.upper()}:{key.username.upper()}:{key.token_type.value}"


def _legacy_hash_key(key: TokenKey) -> str:
    """SHA-256 hex of the legacy string key (the pre-v2 ``hash_key`` layout)."""
    return hashlib.sha256(_legacy_string_key(key).encode("utf-8")).hexdigest()


def _warn(warning: str) -> None:
    logger.warning(warning)
    print("Warning: " + warning, file=sys.stderr)


class TokenCache(ABC):
    """Secure storage for authentication credentials to avoid repeated login prompts.

    Platform-specific implementations:
    - macOS/Windows: Uses OS keyring (Keychain/Credential Manager) via 'keyring' library
    - Linux: Uses JSON file in ~/.cache/snowflake/ with 0o600 permissions
    - Fallback: NoopTokenCache (no caching) if secure storage unavailable

    Tokens are keyed by a versioned, SHA-256-hashed canonical-JSON key (v2 format):
    ``SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex>``.  OAuth flows include
    ``idp`` and ``role`` in the hashed JSON; MFA and ID token flows use only
    ``snowflake`` and ``username``.
    """

    @staticmethod
    def make(skip_file_permissions_check: bool = False) -> TokenCache:
        if IS_MACOS or IS_WINDOWS:
            if not installed_keyring:
                _warn(
                    "Dependency 'keyring' is not installed, cannot cache id token. You might experience "
                    "multiple authentication pop ups while using ExternalBrowser/OAuth/MFA Authenticator. To avoid "
                    "this please install keyring module using the following command:\n"
                    " pip install snowflake-connector-python[secure-local-storage]"
                )
                return NoopTokenCache()
            return KeyringTokenCache()

        if IS_LINUX:
            cache = FileTokenCache.make(skip_file_permissions_check)
            if cache:
                return cache
            else:
                _warn(
                    "Failed to initialize file based token cache. You might experience "
                    "multiple authentication pop ups while using ExternalBrowser/OAuth/MFA Authenticator."
                )
                return NoopTokenCache()

    @abstractmethod
    def store(self, key: TokenKey, token: str) -> None:
        pass

    @abstractmethod
    def retrieve(self, key: TokenKey) -> str | None:
        pass

    @abstractmethod
    def remove(self, key: TokenKey) -> None:
        pass


class _FileTokenCacheError(Exception):
    pass


class _OwnershipError(_FileTokenCacheError):
    pass


class _PermissionsTooWideError(_FileTokenCacheError):
    pass


class _CacheDirNotFoundError(_FileTokenCacheError):
    pass


class _InvalidCacheDirError(_FileTokenCacheError):
    pass


class _MalformedCacheFileError(_FileTokenCacheError):
    pass


class _CacheFileReadError(_FileTokenCacheError):
    pass


class _CacheFileWriteError(_FileTokenCacheError):
    pass


class FileTokenCache(TokenCache):
    """Linux implementation: stores tokens in JSON file with strict security.

    Cache location (in priority order):
    1. $SF_TEMPORARY_CREDENTIAL_CACHE_DIR/credential_cache_v1.json
    2. $XDG_CACHE_HOME/snowflake/credential_cache_v1.json
    3. $HOME/.cache/snowflake/credential_cache_v1.json

    Security: File must have 0o600 permissions and be owned by current user.
    Uses file locks to prevent concurrent access corruption.

    JSON map keys are the full ``SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex>``
    strings produced by ``build_cache_key``; hashing is performed once before
    dispatch.
    Note: the filename (``credential_cache_v1.json``) is unchanged for
    backward compatibility; the ``v2`` in the key prefix refers to the
    key-format version, not the file format.

    For backward compatibility, :meth:`retrieve` also checks the legacy layout
    where the map key was ``sha256("{HOST}:{USER}:{TOKEN_TYPE}")``; matching
    entries are silently migrated to the v2 key on first use.
    """

    @staticmethod
    def make(skip_file_permissions_check: bool = False) -> FileTokenCache | None:
        cache_dir = FileTokenCache.find_cache_dir(skip_file_permissions_check)
        if cache_dir is None:
            logging.getLogger(__name__).debug(
                "Failed to find suitable cache directory for token cache. File based token cache initialization failed."
            )
            return None
        else:
            return FileTokenCache(
                cache_dir, skip_file_permissions_check=skip_file_permissions_check
            )

    def __init__(
        self, cache_dir: Path, skip_file_permissions_check: bool = False
    ) -> None:
        self.logger = logging.getLogger(__name__)
        self.cache_dir: Path = cache_dir
        self._skip_file_permissions_check = skip_file_permissions_check

    def store(self, key: TokenKey, token: str) -> None:
        try:
            final_key = build_cache_key(key)
            FileTokenCache.validate_cache_dir(
                self.cache_dir, self._skip_file_permissions_check
            )
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                cache["tokens"][final_key] = token
                self._write_cache_file(cache)
        except _FileTokenCacheError as e:
            self.logger.error(f"Failed to store token: {e=}")
        except FileLockError as e:
            self.logger.error(f"Unable to lock file lock: {e=}")
        except _InvalidTokenKeyError as e:
            self.logger.error(f"Failed to produce token key {e=}")

    def retrieve(self, key: TokenKey) -> str | None:
        try:
            final_key = build_cache_key(key)
            FileTokenCache.validate_cache_dir(
                self.cache_dir, self._skip_file_permissions_check
            )
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                tokens = cache["tokens"]
                token = tokens.get(final_key, None)
                if isinstance(token, str):
                    return token
                # Legacy v1 fallback: entries keyed by sha256("{HOST}:{USER}:{TYPE}").
                legacy_key = _legacy_hash_key(key)
                legacy_token = tokens.get(legacy_key, None)
                if isinstance(legacy_token, str):
                    tokens[final_key] = legacy_token
                    tokens.pop(legacy_key, None)
                    self._write_cache_file(cache)
                    self.logger.debug(
                        "migrated legacy file cache entry for %s",
                        key.token_type.value,
                    )
                    return legacy_token
                return None
        except _FileTokenCacheError as e:
            self.logger.error(f"Failed to retrieve token: {e=}")
            return None
        except FileLockError as e:
            self.logger.error(f"Unable to lock file lock: {e=}")
            return None
        except _InvalidTokenKeyError as e:
            self.logger.error(f"Failed to produce token key {e=}")
            return None

    def remove(self, key: TokenKey) -> None:
        try:
            final_key = build_cache_key(key)
            FileTokenCache.validate_cache_dir(
                self.cache_dir, self._skip_file_permissions_check
            )
            with FileLock(self.lock_file()):
                cache = self._read_cache_file()
                cache["tokens"].pop(final_key, None)
                self._write_cache_file(cache)
        except _FileTokenCacheError as e:
            self.logger.error(f"Failed to remove token: {e=}")
        except FileLockError as e:
            self.logger.error(f"Unable to lock file lock: {e=}")
        except _InvalidTokenKeyError as e:
            self.logger.error(f"Failed to produce token key {e=}")

    def cache_file(self) -> Path:
        return self.cache_dir / "credential_cache_v1.json"

    def lock_file(self) -> Path:
        return self.cache_dir / "credential_cache_v1.json.lck"

    def _read_cache_file(self) -> dict[str, dict[str, Any]]:
        fd = -1
        json_data = {"tokens": {}}
        try:
            fd = os.open(self.cache_file(), os.O_RDONLY)
            if not self._skip_file_permissions_check:
                self._ensure_permissions(fd, 0o600)
            size = os.lseek(fd, 0, os.SEEK_END)
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, size)
            json_data = json.loads(codecs.decode(data, "utf-8"))
        except FileNotFoundError:
            self.logger.debug(f"{self.cache_file()} not found")
        except json.decoder.JSONDecodeError as e:
            self.logger.warning(
                f"Failed to decode json read from cache file {self.cache_file()}: {e.__class__.__name__}"
            )
        except UnicodeError as e:
            self.logger.warning(
                f"Failed to decode utf-8 read from cache file {self.cache_file()}: {e.__class__.__name__}"
            )
        except OSError as e:
            self.logger.warning(f"Failed to read cache file {self.cache_file()}: {e}")
        finally:
            if fd > 0:
                os.close(fd)

        if "tokens" not in json_data or not isinstance(json_data["tokens"], dict):
            json_data["tokens"] = {}

        return json_data

    def _write_cache_file(self, json_data: dict):
        fd = -1
        self.logger.debug(f"Writing cache file {self.cache_file()}")
        try:
            fd = os.open(
                self.cache_file(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600
            )
            if not self._skip_file_permissions_check:
                self._ensure_permissions(fd, 0o600)
            os.write(fd, codecs.encode(json.dumps(json_data), "utf-8"))
            return json_data
        except OSError as e:
            raise _CacheFileWriteError("Failed to write cache file", e)
        finally:
            if fd > 0:
                os.close(fd)

    @staticmethod
    def find_cache_dir(skip_file_permissions_check: bool = False) -> Path | None:
        def lookup_env_dir(env_var: str, subpath_segments: list[str]) -> Path | None:
            env_val = os.getenv(env_var)
            if env_val is None:
                logger.debug(
                    f"Environment variable {env_var} not set. Skipping it in cache directory lookup."
                )
                return None

            directory = Path(env_val)

            if len(subpath_segments) > 0:
                if not directory.exists():
                    logger.debug(
                        f"Path {str(directory)} does not exist. Skipping it in cache directory lookup."
                    )
                    return None

                if not directory.is_dir():
                    logger.debug(
                        f"Path {str(directory)} is not a directory. Skipping it in cache directory lookup."
                    )
                    return None

                for subpath in subpath_segments[:-1]:
                    directory = directory / subpath
                    directory.mkdir(exist_ok=True, mode=0o755)

                directory = directory / subpath_segments[-1]
                directory.mkdir(exist_ok=True, mode=0o700)

            try:
                FileTokenCache.validate_cache_dir(
                    directory, skip_file_permissions_check
                )
                return directory
            except _FileTokenCacheError as e:
                _warn(
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

    @staticmethod
    def validate_cache_dir(
        cache_dir: Path | None, skip_file_permissions_check: bool = False
    ) -> None:
        try:
            statinfo = cache_dir.stat()

            if cache_dir is None:
                raise _CacheDirNotFoundError("Cache dir was not found")

            if not stat.S_ISDIR(statinfo.st_mode):
                raise _InvalidCacheDirError(f"Cache dir {cache_dir} is not a directory")

            if not skip_file_permissions_check:
                permissions = stat.S_IMODE(statinfo.st_mode)
                if permissions != 0o700:
                    raise _PermissionsTooWideError(
                        f"Cache dir {cache_dir} has incorrect permissions. {permissions:o} != 0700"
                    )

                euid = os.geteuid()
                if statinfo.st_uid != euid:
                    raise _OwnershipError(
                        f"Cache dir {cache_dir} has incorrect owner. {euid} != {statinfo.st_uid}"
                    )

        except FileNotFoundError:
            raise _CacheDirNotFoundError(
                f"Cache dir {cache_dir} was not found. Failed to stat."
            )

    def _ensure_permissions(self, fd: int, permissions: int) -> None:
        try:
            statinfo = os.fstat(fd)
            actual_permissions = stat.S_IMODE(statinfo.st_mode)

            if actual_permissions != permissions:
                raise _PermissionsTooWideError(
                    f"Cache file {self.cache_file()} has incorrect permissions. {permissions:o} != {actual_permissions:o}"
                )

            euid = os.geteuid()
            if statinfo.st_uid != euid:
                raise _OwnershipError(
                    f"Cache file {self.cache_file()} has incorrect owner. {euid} != {statinfo.st_uid}"
                )

        except FileNotFoundError:
            pass


class KeyringTokenCache(TokenCache):
    """macOS/Windows implementation: uses OS-native secure credential storage.

    - macOS: Stores tokens in Keychain
    - Windows: Stores tokens in Windows Credential Manager

    The v2 cache key (``SnowflakeTokenCache.v2.<TOKEN_TYPE>.<sha256hex>``) is
    used as the keyring service name, and the uppercase username is used as the
    account field. This ensures a distinct entry per token dimension while still
    letting related tokens share Keychain visibility per account.

    For backward compatibility, :meth:`retrieve` also checks two legacy layouts
    and silently migrates matching entries to v2 on first use:

    - hash layout (immediately prior): service ``com.snowflake.connector.python``
      with account ``sha256("{HOST}:{USER}:{TOKEN_TYPE}")``
    - string layout (oldest): service ``{HOST}:{USER}:{TOKEN_TYPE}`` with account
      equal to the uppercase username

    where ``string_key`` is ``{HOST}:{USER}:{TOKEN_TYPE}`` (HOST being the
    IdP hostname for OAuth tokens and the Snowflake host otherwise).
    """

    SERVICE_NAME = "com.snowflake.connector.python"

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def store(self, key: TokenKey, token: str) -> None:
        try:
            final_key = build_cache_key(key)
            keyring.set_password(final_key, key.username.upper(), token)
        except _InvalidTokenKeyError as e:
            self.logger.error(f"Could not store {key.token_type} in keyring, {e=}")
        except keyring.errors.KeyringError as ke:
            self.logger.error("Could not store token in keyring, %s", str(ke))

    def retrieve(self, key: TokenKey) -> str | None:
        try:
            final_key = build_cache_key(key)
            token = keyring.get_password(final_key, key.username.upper())
            if token is not None:
                return token
            return self._retrieve_legacy(key)
        except keyring.errors.KeyringError as ke:
            self.logger.error(
                "Could not retrieve {} from secure storage : {}".format(
                    key.token_type.value, str(ke)
                )
            )
        except _InvalidTokenKeyError as e:
            self.logger.error(
                f"Could not retrieve {key.token_type} from keyring, {e=}"
            )

    def _retrieve_legacy(self, key: TokenKey) -> str | None:
        """Read from pre-v2 keyring layouts and migrate matching entries to v2.

        Two historical layouts are checked, newest first:
        - hash layout: service ``SERVICE_NAME``, account ``sha256(string_key)``
        - string layout: service ``string_key``, account uppercase username

        where ``string_key`` is ``{HOST}:{USER}:{TOKEN_TYPE}`` (HOST being the
        IdP hostname for OAuth tokens and the Snowflake host otherwise).
        """
        try:
            legacy_string_key = _legacy_string_key(key)
            legacy_hash_key = _legacy_hash_key(key)
        except _InvalidTokenKeyError:
            return None

        account = key.username.upper()
        lookups = [
            (self.SERVICE_NAME, legacy_hash_key),
            (legacy_string_key, account),
        ]
        for service, acct in lookups:
            try:
                token = keyring.get_password(service, acct)
            except (keyring.errors.KeyringError, _InvalidTokenKeyError):
                continue
            if token is None:
                continue
            self.store(key, token)
            try:
                keyring.delete_password(service, acct)
            except Exception:
                pass
            self.logger.debug(
                "migrated legacy keyring entry for %s", key.token_type.value
            )
            return token
        return None

    def remove(self, key: TokenKey) -> None:
        try:
            final_key = build_cache_key(key)
            keyring.delete_password(final_key, key.username.upper())
        except _InvalidTokenKeyError as e:
            self.logger.error(f"Could not remove {key.token_type} from keyring, {e=}")
        except Exception as ex:
            self.logger.error(
                "Failed to delete credential in the keyring: err=[%s]", ex
            )


class NoopTokenCache(TokenCache):
    def store(self, key: TokenKey, token: str) -> None:
        return None

    def retrieve(self, key: TokenKey) -> str | None:
        return None

    def remove(self, key: TokenKey) -> None:
        return None
