from __future__ import annotations

from logging import getLogger

from ..secret_detector import SecretDetector

URLLIB3_MODULE_NAME = "snowflake.connector.vendored.urllib3.connectionpool"
# TODO: after migration to the external urllib3 from the vendored one, we should change filters here immediately to the below module's logger:
# URLLIB3_MODULE_NAME = "urllib3"


def add_formatters_to_loggers():
    for handler in getLogger(URLLIB3_MODULE_NAME).handlers:
        handler.setFormatter(SecretDetector("%(asctime)s %(levelname)s %(message)s"))


add_formatters_to_loggers()
