#!/usr/bin/env python
#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..secret_detector import SecretDetector
from ..telemetry import TelemetryClient as TelemetryClientSync
from ..telemetry import TelemetryData as TelemetryDataSync
from ..telemetry import generate_telemetry_data_dict
from ..test_util import ENABLE_TELEMETRY_LOG, rt_plain_logger

if TYPE_CHECKING:
    from ._connection import SnowflakeConnection
    from ._network import SnowflakeRestful

logger = logging.getLogger(__name__)


class TelemetryData(TelemetryDataSync):
    """An instance of telemetry data which can be sent to the server."""

    def __init__(self, message, timestamp) -> None:
        super().__init__(message, timestamp)

    @classmethod
    def from_telemetry_data_dict(
        cls,
        from_dict: dict,
        timestamp: int,
        connection: SnowflakeConnection | None = None,
        is_oob_telemetry: bool = False,
    ):
        """
        Generate telemetry data with driver info from given dict and timestamp.
        It takes an optional connection object to read data from.
        It also takes a boolean is_oob_telemetry to indicate whether it's for out-of-band telemetry, as
        naming of keys for driver and version is different from the ones of in-band telemetry.
        """
        return cls(
            generate_telemetry_data_dict(
                from_dict=(from_dict or {}),
                connection=connection,
                is_oob_telemetry=is_oob_telemetry,
            ),
            timestamp,
        )


class TelemetryClient(TelemetryClientSync):
    """Client to enqueue and send metrics to the telemetry endpoint in batch."""

    def __init__(self, rest: SnowflakeRestful, flush_size=None) -> None:
        super().__init__(rest, flush_size)

    async def add_log_to_batch(self, telemetry_data: TelemetryData) -> None:
        if self.is_closed:
            raise Exception("Attempted to add log when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Ignoring log.")
            return

        with self._lock:
            self._log_batch.append(telemetry_data)

        if len(self._log_batch) >= self._flush_size:
            await self.send_batch()

    async def send_batch(self) -> None:
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
            ret = await self._rest.request(
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

    async def try_add_log_to_batch(self, telemetry_data: TelemetryData) -> None:
        try:
            await self.add_log_to_batch(telemetry_data)
        except Exception:
            logger.warning("Failed to add log to telemetry.", exc_info=True)

    async def close(self, send_on_close: bool = True) -> None:
        if not self.is_closed:
            logger.debug("Closing telemetry client.")
            if send_on_close:
                await self.send_batch()
            self._rest = None
