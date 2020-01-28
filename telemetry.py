#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018-2019 Snowflake Computing Inc. All right reserved.
#
import logging
from threading import Lock

logger = logging.getLogger(__name__)


class TelemetryField(object):
    """
    Fields which can be logged to telemetry
    """
    TIME_CONSUME_FIRST_RESULT = "client_time_consume_first_result"
    TIME_CONSUME_LAST_RESULT = "client_time_consume_last_result"
    TIME_DOWNLOADING_CHUNKS = "client_time_downloading_chunks"
    TIME_PARSING_CHUNKS = "client_time_parsing_chunks"


class TelemetryData(object):
    """
    An instance of telemetry data which can be sent to the server
    """
    def __init__(self, message, timestamp):
        self.message = message
        self.timestamp = timestamp

    def to_dict(self):
        return {
            'message': self.message,
            'timestamp': str(self.timestamp)
        }

    def __repr__(self):
        return str(self.to_dict())


class TelemetryClient(object):
    """
    Client to enqueue and send metrics to the telemetry endpoint in batch
    """
    SF_PATH_TELEMETRY = "/telemetry/send"
    DEFAULT_FORCE_FLUSH_SIZE = 100

    def __init__(self, rest, flush_size=None):
        self._rest = rest
        self._log_batch = []
        self._is_closed = False
        self._flush_size = \
            flush_size or TelemetryClient.DEFAULT_FORCE_FLUSH_SIZE
        self._lock = Lock()
        self._enabled = True

    def add_log_to_batch(self, telemetry_data):
        if self._is_closed:
            raise Exception(
                "Attempted to add log when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Ignoring log.")
            return

        with self._lock:
            self._log_batch.append(telemetry_data)

        if len(self._log_batch) >= self._flush_size:
            self.send_batch()

    def try_add_log_to_batch(self, telemetry_data):
        try:
            self.add_log_to_batch(telemetry_data)
        except Exception:
            logger.warning("Failed to add log to telemetry.", exc_info=True)

    def send_batch(self):
        if self._is_closed:
            raise Exception(
                "Attempted to send batch when TelemetryClient is closed")
        elif not self._enabled:
            logger.debug("TelemetryClient disabled. Not sending logs.")
            return

        with self._lock:
            to_send = self._log_batch
            self._log_batch = []

        if not to_send:
            logger.debug("Nothing to send to telemetry.")
            return

        body = {'logs': [x.to_dict() for x in to_send]}
        logger.debug("Sending %d logs to telemetry.", len(body))
        try:
            ret = self._rest.request(TelemetryClient.SF_PATH_TELEMETRY, body=body,
                                     method='post', client=None, timeout=5)
            if not ret[u'success']:
                logger.info(
                    "Non-success response from telemetry server: %s. "
                    "Disabling telemetry.", str(ret))
                self._enabled = False
            else:
                logger.debug("Successfully uploading metrics to telemetry.")
        except Exception:
            self._enabled = False
            logger.debug("Failed to upload metrics to telemetry.", exc_info=True)

    def is_closed(self):
        return self._is_closed

    def close(self, send_on_close=True):
        if not self._is_closed:
            logger.debug("Closing telemetry client.")
            if send_on_close:
                self.send_batch()
            self._is_closed = True

    def disable(self):
        self._enabled = False

    def is_enabled(self):
        return self._enabled

    def buffer_size(self):
        return len(self._log_batch)
