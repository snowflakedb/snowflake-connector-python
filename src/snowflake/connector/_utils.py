from __future__ import annotations

import string
from enum import Enum
from inspect import stack
from random import choice
from threading import Timer
from uuid import UUID


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
