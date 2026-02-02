from __future__ import annotations

import ctypes
import importlib
import logging
import os
import platform
import string
import threading
import time
from enum import Enum
from inspect import stack
from pathlib import Path
from random import choice
from threading import Timer
from uuid import UUID

from snowflake.connector.description import ISA, OPERATING_SYSTEM, OS_VERSION

logger = logging.getLogger(__name__)


class TempObjectType(Enum):
    TABLE = "TABLE"
    VIEW = "VIEW"
    STAGE = "STAGE"
    FUNCTION = "FUNCTION"
    FILE_FORMAT = "FILE_FORMAT"
    QUERY_TAG = "QUERY_TAG"
    COLUMN = "COLUMN"
    PROCEDURE = "PROCEDURE"
    TABLE_FUNCTION = "TABLE_FUNCTION"
    DYNAMIC_TABLE = "DYNAMIC_TABLE"
    AGGREGATE_FUNCTION = "AGGREGATE_FUNCTION"
    CTE = "CTE"


TEMP_OBJECT_NAME_PREFIX = "SNOWPARK_TEMP_"
ALPHANUMERIC = string.digits + string.ascii_lowercase
TEMPORARY_STRING = "TEMP"
SCOPED_TEMPORARY_STRING = "SCOPED TEMPORARY"
_PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS_STRING = (
    "PYTHON_SNOWPARK_USE_SCOPED_TEMP_OBJECTS"
)

REQUEST_ID_STATEMENT_PARAM_NAME = "requestId"

# Default server side cap on Degree of Parallelism for file transfer
# This default value is set to 2^30 (~ 10^9), such that it will not
# throttle regular sessions.
_DEFAULT_VALUE_SERVER_DOP_CAP_FOR_FILE_TRANSFER = 1 << 30
# Variable name of server DoP cap for file transfer
_VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER = (
    "snowflake_server_dop_cap_for_file_transfer"
)


def generate_random_alphanumeric(length: int = 10) -> str:
    return "".join(choice(ALPHANUMERIC) for _ in range(length))


def random_name_for_temp_object(object_type: TempObjectType) -> str:
    return f"{TEMP_OBJECT_NAME_PREFIX}{object_type.value}_{generate_random_alphanumeric().upper()}"


def get_temp_type_for_object(use_scoped_temp_objects: bool) -> str:
    return SCOPED_TEMPORARY_STRING if use_scoped_temp_objects else TEMPORARY_STRING


def is_uuid4(str_or_uuid: str | UUID) -> bool:
    """Check whether provided string str is a valid UUID version4."""
    if isinstance(str_or_uuid, UUID):
        return str_or_uuid.version == 4

    if not isinstance(str_or_uuid, str):
        return False

    try:
        uuid_str = str(UUID(str_or_uuid, version=4))
    except ValueError:
        return False
    return uuid_str == str_or_uuid


def _snowflake_max_parallelism_for_file_transfer(connection):
    """Returns the server side cap on max parallelism for file transfer for the given connection."""
    return getattr(
        connection,
        f"_{_VARIABLE_NAME_SERVER_DOP_CAP_FOR_FILE_TRANSFER}",
        _DEFAULT_VALUE_SERVER_DOP_CAP_FOR_FILE_TRANSFER,
    )


class _TrackedQueryCancellationTimer(Timer):
    def __init__(self, interval, function, args=None, kwargs=None):
        super().__init__(interval, function, args, kwargs)
        self.executed = False

    def run(self):
        super().run()
        self.executed = True


def get_application_path() -> str:
    """Get the path of the application script using the connector."""
    try:
        outermost_frame = stack()[-1]
        return outermost_frame.filename
    except Exception:
        return "unknown"


_SPCS_TOKEN_ENV_VAR_NAME = "SF_SPCS_TOKEN_PATH"
_SPCS_TOKEN_DEFAULT_PATH = "/snowflake/session/spcs_token"


def get_spcs_token() -> str | None:
    """Return the SPCS token read from the configured path, or None.

    The path is determined by the SF_SPCS_TOKEN_PATH environment variable,
    falling back to ``/snowflake/session/spcs_token`` when unset.

    Any I/O errors or missing/empty files are treated as \"no token\" and
    will not cause authentication to fail.
    """
    path = os.getenv(_SPCS_TOKEN_ENV_VAR_NAME) or _SPCS_TOKEN_DEFAULT_PATH
    try:
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as f:
            token = f.read().strip()
        if not token:
            return None
        return token
    except Exception as exc:  # pragma: no cover - best-effort logging only
        logger.debug("Failed to read SPCS token from %s: %s", path, exc)
        return None


class _NanoarrowLoader:
    def __init__(self):
        self._error: Exception | None = None

    def set_load_error(self, err: Exception):
        self._error = err

    def get_load_error(self) -> str:
        return str(self._error)


class _CoreLoader:
    def __init__(self):
        self._version: bytes | None = None
        self._error: Exception | None = None
        self._path: str | None = None
        self._load_time: float | None = None

    @staticmethod
    def _detect_os() -> str:
        """Detect the operating system."""
        system = platform.system().lower()
        if system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        elif system == "windows":
            return "windows"
        elif system == "aix":
            return "aix"
        else:
            return "unknown"

    @staticmethod
    def _detect_arch() -> str:
        """Detect the CPU architecture."""
        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            return "x86_64"
        elif machine in ("aarch64", "arm64"):
            return "aarch64"
        elif machine in ("i686", "i386", "x86"):
            return "i686"
        elif machine == "ppc64":
            return "ppc64"
        else:
            return "unknown"

    @staticmethod
    def _detect_libc() -> str:
        """Detect libc type on Linux (glibc vs musl)."""
        # Check if we're on Alpine/musl
        if Path("/etc/alpine-release").exists():
            return "musl"

        # Check for musl by looking at the libc library
        try:
            import subprocess

            result = subprocess.run(
                ["ldd", "--version"],
                capture_output=True,
                text=True,
            )
            if "musl" in result.stdout.lower() or "musl" in result.stderr.lower():
                return "musl"
        except Exception:
            pass

        # Default to glibc
        return "glibc"

    @staticmethod
    def _get_platform_subdir() -> str:
        """Get the platform-specific subdirectory name."""
        os_name = _CoreLoader._detect_os()
        arch = _CoreLoader._detect_arch()

        if os_name == "linux":
            libc = _CoreLoader._detect_libc()
            return f"linux_{arch}_{libc}"
        elif os_name == "macos":
            return f"macos_{arch}"
        elif os_name == "windows":
            return f"windows_{arch}"
        elif os_name == "aix":
            return f"aix_{arch}"

        raise OSError(f"Mini core binary for {os_name} {arch} not found")

    @staticmethod
    def _get_lib_name() -> str:
        """Get the library filename for the current platform."""
        os_name = _CoreLoader._detect_os()
        if os_name == "windows":
            return "sf_mini_core.dll"
        elif os_name == "macos":
            return "libsf_mini_core.dylib"
        elif os_name == "aix":
            return "libsf_mini_core.a"
        else:
            # Linux and other Unix-like systems
            return "libsf_mini_core.so"

    @staticmethod
    def _get_core_path():
        """Get the path to the minicore library for the current platform."""
        subdir = _CoreLoader._get_platform_subdir()
        lib_name = _CoreLoader._get_lib_name()

        files = importlib.resources.files("snowflake.connector.minicore")

        return files.joinpath(subdir, lib_name)

    @staticmethod
    def _register_functions(core: ctypes.CDLL):
        core.sf_core_full_version.argtypes = []
        core.sf_core_full_version.restype = ctypes.c_char_p

    @staticmethod
    def _load_minicore(path: str) -> ctypes.CDLL:
        # This context manager is the safe way to get a
        # file path from importlib.resources. It handles cases
        # where the file is inside a zip and needs to be extracted
        # to a temporary location.
        with importlib.resources.as_file(path) as lib_path:
            core = ctypes.CDLL(str(lib_path))
        return core

    def get_present_binaries(self) -> str:
        present_binaries = []
        try:
            minicore_files = importlib.resources.files("snowflake.connector.minicore")
            # Iterate through all items in the minicore module
            for item in minicore_files.iterdir():
                # Skip non-platform directories like __pycache__
                if item.is_dir() and not item.name.startswith("__"):
                    # This is a platform subdirectory
                    platform_name = item.name
                    try:
                        # List all files in this subdirectory
                        for binary_file in item.iterdir():
                            if binary_file.is_file():
                                # Store as "platform/filename"
                                present_binaries.append(
                                    f"{platform_name}/{binary_file.name}"
                                )
                    except Exception as e:
                        logger.debug(f"Error listing binaries in {platform_name}: {e}")
        except Exception as e:
            logger.debug(f"Error populating present binaries: {e}")

        return ",".join(present_binaries)

    def _is_core_disabled(self) -> bool:
        value = str(os.getenv("SNOWFLAKE_DISABLE_MINICORE", None)).lower()
        return value in ["1", "true"]

    def _load(self) -> None:
        start_time = time.perf_counter()
        try:
            path = self._get_core_path()
            self._path = str(path)
            core = self._load_minicore(path)
            self._register_functions(core)
            self._version = core.sf_core_full_version()
            self._error = None
        except Exception as err:
            self._error = err
        end_time = time.perf_counter()
        # Store load time in milliseconds (with sub-millisecond precision)
        self._load_time = (end_time - start_time) * 1000

    def load(self):
        """Spawn a separate thread to load the minicore library (non-blocking)."""
        if self._is_core_disabled():
            self._error = "mini-core-disabled"
            return
        self._error = "still-loading"
        thread = threading.Thread(target=self._load, daemon=True)
        thread.start()

    def get_load_error(self) -> str:
        return str(self._error)

    def get_core_version(self) -> str | None:
        if self._version:
            try:
                return self._version.decode("utf-8")
            except Exception:
                pass
        return None

    def get_file_name(self) -> str:
        return self._path

    def get_load_time(self) -> float | None:
        """Return the time it took to load the minicore binary in milliseconds."""
        return self._load_time


_core_loader = _CoreLoader()
_nanoarrow_loader = _NanoarrowLoader()


def build_minicore_usage_for_session() -> dict[str, str | None]:
    return {
        "ISA": ISA,
        "CORE_VERSION": _core_loader.get_core_version(),
        "CORE_FILE_NAME": _core_loader.get_file_name(),
    }


def build_minicore_usage_for_telemetry() -> dict[str, str | None]:
    return {
        "OS": OPERATING_SYSTEM,
        "OS_VERSION": OS_VERSION,
        "CORE_LOAD_ERROR": _core_loader.get_load_error(),
        "CORE_BINARIES_PRESENT": _core_loader.get_present_binaries(),
        "CORE_LOAD_TIME": _core_loader.get_load_time(),
        **build_minicore_usage_for_session(),
    }


def build_nanoarrow_usage_for_telemetry() -> dict[str, str | None]:
    return {
        "OS": OPERATING_SYSTEM,
        "OS_VERSION": OS_VERSION,
        "NANOARROW_LOAD_ERROR": _nanoarrow_loader.get_load_error(),
        "ISA": ISA,
    }
