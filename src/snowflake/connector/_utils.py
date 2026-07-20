from __future__ import annotations

import string
from enum import Enum
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


class _TrackedQueryCancellationTimer(Timer):
    def __init__(self, interval, function, args=None, kwargs=None):
        super().__init__(interval, function, args, kwargs)
        self.executed = False

    def run(self):
        super().run()
        self.executed = True
