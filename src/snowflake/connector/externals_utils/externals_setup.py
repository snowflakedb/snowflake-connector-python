from __future__ import annotations

from logging import getLogger

from snowflake.connector.logging_utils.filters import SecretMaskingFilter

URLLIB3_MODULES_NAMES = ["snowflake.connector.vendored.urllib3"]
# TODO: after migration to the external urllib3 from the vendored one, we should change filters here immediately to the below module's logger:
# URLLIB3_MODULE_NAME = "urllib3"


def add_formatters_to_urllib3_loggers():
    for module_name in URLLIB3_MODULES_NAMES:
        logger = getLogger(module_name)
        logger.addFilter(SecretMaskingFilter)


def setup_external_libraries():
    """
    Assures proper setup and injections before any external libraries are used.
    """
    add_formatters_to_urllib3_loggers()
