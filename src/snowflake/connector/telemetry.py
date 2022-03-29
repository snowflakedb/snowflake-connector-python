#!/usr/bin/env python
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from enum import Enum, unique
from threading import Lock
from typing import TYPE_CHECKING

from .secret_detector import SecretDetector
from .test_util import ENABLE_TELEMETRY_LOG, rt_plain_logger

if TYPE_CHECKING:
    from .network import SnowflakeRestful

logger = logging.getLogger(__name__)


@unique
class TelemetryField(Enum):
    # Fields which can be logged to telemetry
    TIME_CONSUME_FIRST_RESULT = "client_time_consume_first_result"
    TIME_CONSUME_LAST_RESULT = "client_time_consume_last_result"
    TIME_DOWNLOADING_CHUNKS = "client_time_downloading_chunks"
    TIME_PARSING_CHUNKS = "client_time_parsing_chunks"
    SQL_EXCEPTION = "client_sql_exception"
    GET_PARTITIONS_USED = "client_get_partitions_used"
    EMPTY_SEQ_INTERPOLATION = "client_pyformat_empty_seq_interpolation"
    # fetch_pandas_* usage
    PANDAS_FETCH_ALL = "client_fetch_pandas_all"
    PANDAS_FETCH_BATCHES = "client_fetch_pandas_batches"
    # fetch_arrow_* usage
    ARROW_FETCH_ALL = "client_fetch_arrow_all"
    ARROW_FETCH_BATCHES = "client_fetch_arrow_batches"
    # Keys for telemetry data sent through either in-band or out-of-band telemetry
    KEY_TYPE = "type"
    KEY_SOURCE = "source"
    KEY_SFQID = "QueryID"
    KEY_SQLSTATE = "SQLState"
    KEY_DRIVER_TYPE = "DriverType"
    KEY_DRIVER_VERSION = "DriverVersion"
    KEY_REASON = "reason"
    KEY_ERROR_NUMBER = "ErrorNumber"
    KEY_STACKTRACE = "Stacktrace"
    KEY_EXCEPTION = "Exception"


class TelemetryData:
    """An instance of telemetry data which can be sent to the server."""

    TRUE = 1
    FALSE = 0

    def __init__(self, message, timestamp):
        self.message = message
        self.timestamp = timestamp

    def to_dict(self):
        return {"message": self.message, "timestamp": str(self.timestamp)}

    def __repr__(self):
        return str(self.to_dict())


class TelemetryClient:
    """Client to enqueue and send metrics to the telemetry endpoint in batch."""

    SF_PATH_TELEMETRY = "/telemetry/send"
    DEFAULT_FORCE_FLUSH_SIZE = 100

    def __init__(self, rest: SnowflakeRestful, flush_size=None):
        self._rest: SnowflakeRestful | None = rest
        self._log_batch = []
        self._flush_size = flush_size or TelemetryClient.DEFAULT_FORCE_FLUSH_SIZE
        self._lock = Lock()
        self._enabled = True

    def add_log_to_batch(self, telemetry_data: TelemetryData) -> None:
        if self.is_closed:
            raise Exception("Attempted to add log when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Ignoring log.")
            return

        with self._lock:
            self._log_batch.append(telemetry_data)

        if len(self._log_batch) >= self._flush_size:
            self.send_batch()

    def try_add_log_to_batch(self, telemetry_data: TelemetryData) -> None:
        try:
            self.add_log_to_batch(telemetry_data)
        except Exception:
            logger.warning("Failed to add log to telemetry.", exc_info=True)

    def send_batch(self):
        if self.is_closed:
            raise Exception("Attempted to send batch when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Not sending logs.")
            return

        with self._lock:
            to_send = self._log_batch
            self._log_batch = []

        if not to_send:
            logger.debug("Nothing to send to telemetry.")
            return

        body = {"logs": [x.to_dict() for x in to_send]}
        logger.debug(
            "Sending %d logs to telemetry. Data is %s.",
            len(body),
            SecretDetector.mask_secrets(str(body))[1],
        )
        if ENABLE_TELEMETRY_LOG:
            # This logger guarantees the payload won't be masked. Testing purpose.
            rt_plain_logger.debug(f"Inband telemetry data being sent is {body}")
        try:
            ret = self._rest.request(
                TelemetryClient.SF_PATH_TELEMETRY,
                body=body,
                method="post",
                client=None,
                timeout=5,
            )
            if not ret["success"]:
                logger.info(
                    "Non-success response from telemetry server: %s. "
                    "Disabling telemetry.",
                    str(ret),
                )
                self._enabled = False
            else:
                logger.debug("Successfully uploading metrics to telemetry.")
        except Exception:
            self._enabled = False
            logger.debug("Failed to upload metrics to telemetry.", exc_info=True)

    @property
    def is_closed(self):
        return self._rest is None

    def close(self, send_on_close=True):
        if not self.is_closed:
            logger.debug("Closing telemetry client.")
            if send_on_close:
                self.send_batch()
            self._rest = None

    def disable(self):
        self._enabled = False

    def is_enabled(self):
        return self._enabled

    def buffer_size(self):
        return len(self._log_batch)
