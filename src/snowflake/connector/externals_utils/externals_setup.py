from __future__ import annotations

from logging import getLogger

from ..secret_detector import SecretDetector

URLLIB3_MODULES_NAMES = ["snowflake.connector.vendored.urllib3.connectionpool"]
EXTERNAL_LOGS_FORMAT = "%(asctime)s %(levelname)s %(message)s"

# TODO: after migration to the external urllib3 from the vendored one, we should change filters here immediately to the below module's logger:
# URLLIB3_MODULE_NAME = "urllib3"


def add_formatters_to_urllib3_loggers():
    # Import to make sure the logger of urllib3 was set up already and handlers were added
    import snowflake.connector.vendored.urllib3  # noqa: F401

    for module_name in URLLIB3_MODULES_NAMES:
        for handler in getLogger(module_name).handlers:
            handler.setFormatter(SecretDetector(EXTERNAL_LOGS_FORMAT))


def setup_external_libraries():
    """
    Assures proper setup and injections before any external libraries are used.
    """

    add_formatters_to_urllib3_loggers()
