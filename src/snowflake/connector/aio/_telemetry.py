#!/usr/bin/env python


from __future__ import annotations

import logging
from asyncio import Lock
from typing import TYPE_CHECKING

from ..secret_detector import SecretDetector
from ..telemetry import TelemetryClient as TelemetryClientSync
from ..telemetry import TelemetryData
from ..test_util import ENABLE_TELEMETRY_LOG, rt_plain_logger

if TYPE_CHECKING:
    from ._network import SnowflakeRestful

logger = logging.getLogger(__name__)


class TelemetryClient(TelemetryClientSync):
    """Client to enqueue and send metrics to the telemetry endpoint in batch."""

    def __init__(self, rest: SnowflakeRestful, flush_size=None) -> None:
        super().__init__(rest, flush_size)
        self._lock = Lock()

    async def add_log_to_batch(self, telemetry_data: TelemetryData) -> None:
        if self.is_closed:
            raise Exception("Attempted to add log when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Ignoring log.")
            return

        async with self._lock:
            self._log_batch.append(telemetry_data)

        if len(self._log_batch) >= self._flush_size:
            await self.send_batch()

    async def send_batch(self, retry: bool = False) -> None:
        if self.is_closed:
            raise Exception("Attempted to send batch when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Not sending logs.")
            return

        async with self._lock:
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
                _no_retry=not retry,
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

    async def close(self, retry: bool = False) -> None:
        if not self.is_closed:
            logger.debug("Closing telemetry client.")
            await self.send_batch(retry=retry)
            self._rest = None
