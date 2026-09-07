from __future__ import annotations

from snowflake.connector.logging_utils.filters import (
    DISABLE_LOG_SECRET_MASKING_ENV,
    install_secret_masking_filters,
)

# Re-exported for tests and callers that historically imported it from here.
__all__ = [
    "DISABLE_LOG_SECRET_MASKING_ENV",
    "MODULES_TO_MASK_LOGS_NAMES",
    "add_filters_to_external_loggers",
    "setup_external_libraries",
]

MODULES_TO_MASK_LOGS_NAMES = [
    "snowflake.connector",
    "snowflake.connector.vendored.urllib3",
    "botocore",
    "boto3",
    "aiohttp",  # this should not break even if [aio] extra is not installed - in such case logger will remain unused
    "aiobotocore",
    "aioboto3",
]
# TODO: after migration to the external urllib3 from the vendored one (SNOW-2041970),
#  we should change filters here immediately to the below module's logger:
#  MODULES_TO_MASK_LOGS_NAMES = [ "urllib3", ... ]


def add_filters_to_external_loggers():
    install_secret_masking_filters(MODULES_TO_MASK_LOGS_NAMES)


def setup_external_libraries():
    """
    Assures proper setup and injections before any external libraries are used.
    """
    add_filters_to_external_loggers()
