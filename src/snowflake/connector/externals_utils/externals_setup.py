from __future__ import annotations

from snowflake.connector.logging_utils.filters import (
    SecretMaskingFilter,
    add_filter_to_logger_and_children,
)

MODULES_TO_MASK_LOGS_NAMES = [
    "snowflake.connector.vendored.urllib3",
    "botocore",
    "boto3",
]
# TODO: after migration to the external urllib3 from the vendored one, we should change filters here immediately to the below module's logger:
# URLLIB3_MODULE_NAME = "urllib3"


def add_filters_to_external_loggers():
    for module_name in MODULES_TO_MASK_LOGS_NAMES:
        add_filter_to_logger_and_children(module_name, SecretMaskingFilter())


def setup_external_libraries():
    """
    Assures proper setup and injections before any external libraries are used.
    """
    add_filters_to_external_loggers()
