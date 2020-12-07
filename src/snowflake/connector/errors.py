#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging
import os
import traceback
from logging import getLogger
from typing import TYPE_CHECKING, Dict, Optional

from snowflake.connector.constants import UTF8

from .compat import BASE_EXCEPTION_CLASS
from .description import CLIENT_NAME, SNOWFLAKE_CONNECTOR_VERSION
from .secret_detector import SecretDetector
from .telemetry import TelemetryData, TelemetryField
from .telemetry_oob import TelemetryService
from .time_util import get_time_millis

if TYPE_CHECKING:  # pragma: no cover
    from .connection import SnowflakeConnection
    from .cursor import SnowflakeCursor

logger = getLogger(__name__)
connector_base_path = os.path.join("snowflake", "connector")


class Error(BASE_EXCEPTION_CLASS):
    """Base Snowflake exception class."""

    def __init__(self, msg: Optional[str] = None, errno: Optional[int] = None, sqlstate: Optional[str] = None,
                 sfqid: Optional[str] = None, done_format_msg: Optional[bool] = None,
                 connection: Optional['SnowflakeConnection'] = None, cursor: Optional['SnowflakeCursor'] = None):
        self.msg = msg
        self.raw_msg = msg
        self.errno = errno or -1
        self.sqlstate = sqlstate or "n/a"
        self.sfqid = sfqid

        if not self.msg:
            self.msg = 'Unknown error'

        if self.errno != -1 and not done_format_msg:
            if self.sqlstate != "n/a":
                if logger.getEffectiveLevel() in (logging.INFO,
                                                  logging.DEBUG):
                    self.msg = '{errno:06d} ({sqlstate}): {sfqid}: {msg}'.format(
                        errno=self.errno, msg=self.msg,
                        sqlstate=self.sqlstate,
                        sfqid=self.sfqid)
                else:
                    self.msg = '{errno:06d} ({sqlstate}): {msg}'.format(
                        errno=self.errno,
                        sqlstate=self.sqlstate,
                        msg=self.msg)
            else:
                if logger.getEffectiveLevel() in (logging.INFO,
                                                  logging.DEBUG):
                    self.msg = '{errno:06d}: {sfqid}: {msg}'.format(
                        errno=self.errno, msg=self.msg,
                        sfqid=self.sfqid)
                else:
                    self.msg = '{errno:06d}: {msg}'.format(errno=self.errno,
                                                            msg=self.msg)

        # We want to skip the last frame/line in the traceback since it is the current frame
        self.telemetry_traceback = self.generate_telemetry_stacktrace()
        self.exception_telemetry(msg, cursor, connection)

    def __repr__(self):
        return self.__str__()

    def __unicode__(self):
        return self.msg

    def __bytes__(self):
        return self.__unicode__().encode(UTF8)

    def generate_telemetry_stacktrace(self) -> str:
        # Get the current stack minus this function and the Error init function
        stack_frames = traceback.extract_stack()[:-2]
        filtered_frames = list()
        for frame in stack_frames:
            # Only add frames associated with the snowflake python connector to the telemetry stacktrace
            if connector_base_path in frame.filename:
                # Get the index to truncate the file path to hide any user path
                safe_path_index = frame.filename.find(connector_base_path)
                # Create a new frame with the truncated file name and without the line argument since that can
                # output senitive data
                filtered_frames.append(
                    traceback.FrameSummary(frame.filename[safe_path_index:], frame.lineno, frame.name, line='')
                )

        return ''.join(traceback.format_list(filtered_frames))

    def telemetry_msg(self) -> Optional[str]:
        if self.sqlstate != "n/a":
            return '{errno:06d} ({sqlstate})'.format(errno=self.errno, sqlstate=self.sqlstate)
        elif self.errno != -1:
            return '{errno:06d}'.format(errno=self.errno)
        else:
            return None

    def generate_telemetry_exception_data(self) -> Dict[str, str]:
        """Generate the data to send through telemetry."""
        telemetry_data = {
            TelemetryField.KEY_DRIVER_TYPE: CLIENT_NAME,
            TelemetryField.KEY_DRIVER_VERSION: SNOWFLAKE_CONNECTOR_VERSION
        }
        telemetry_msg = self.telemetry_msg()
        if self.sfqid:
            telemetry_data[TelemetryField.KEY_SFQID] = self.sfqid
        if self.sqlstate:
            telemetry_data[TelemetryField.KEY_SQLSTATE] = self.sqlstate
        if telemetry_msg:
            telemetry_data[TelemetryField.KEY_REASON] = telemetry_msg
        if self.errno:
            telemetry_data[TelemetryField.KEY_ERROR_NUMBER] = str(self.errno)

        telemetry_data[TelemetryField.KEY_STACKTRACE] = SecretDetector.mask_secrets(self.telemetry_traceback)

        return telemetry_data

    def send_exception_telemetry(self,
                                 connection: Optional['SnowflakeConnection'],
                                 telemetry_data: Dict[str, str]) -> None:
        """Send telemetry data by in-band telemetry if it is enabled, otherwise send through out-of-band telemetry."""
        if connection is not None and connection.telemetry_enabled and not connection._telemetry.is_closed():
            # Send with in-band telemetry
            telemetry_data[TelemetryField.KEY_TYPE] = TelemetryField.SQL_EXCEPTION
            telemetry_data[TelemetryField.KEY_EXCEPTION] = self.__class__.__name__
            ts = get_time_millis()
            try:
                connection._log_telemetry(TelemetryData(telemetry_data, ts))
            except AttributeError:
                logger.debug(
                    "Cursor failed to log to telemetry.",
                    exc_info=True)
        elif connection is None:
            # Send with out-of-band telemetry
            telemetry_oob = TelemetryService.get_instance()
            telemetry_oob.log_general_exception(self.__class__.__name__, telemetry_data)

    def exception_telemetry(self,
                            msg: str,
                            cursor: Optional['SnowflakeCursor'],
                            connection: Optional['SnowflakeConnection']) -> None:
        """Main method to generate and send telemetry data for exceptions."""
        try:
            telemetry_data = self.generate_telemetry_exception_data()
            if cursor is not None:
                self.send_exception_telemetry(cursor.connection, telemetry_data)
            elif connection is not None:
                self.send_exception_telemetry(connection, telemetry_data)
            else:
                self.send_exception_telemetry(None, telemetry_data)
        except Exception:
            # Do nothing but log if sending telemetry fails
            logger.debug("Sending exception telemetry failed")

    @staticmethod
    def default_errorhandler(connection: 'SnowflakeConnection',
                             cursor: 'SnowflakeCursor',
                             error_class: Exception,
                             error_value: Dict[str, str]) -> None:
        """Default error handler that raises an error.

        Args:
            connection: Connections in which the error happened.
            cursor: Cursor in which the error happened.
            error_class: Class of error that needs handling.
            error_value: A dictionary of the error details.

        Raises:
            A Snowflake error.
        """
        raise error_class(
            msg=error_value.get('msg'),
            errno=error_value.get('errno'),
            sqlstate=error_value.get('sqlstate'),
            sfqid=error_value.get('sfqid'),
            done_format_msg=error_value.get('done_format_msg'),
            connection=connection,
            cursor=cursor)

    @staticmethod
    def errorhandler_wrapper(connection: 'SnowflakeConnection',
                             cursor: 'SnowflakeCursor',
                             error_class: Exception,
                             error_value: Optional[Dict[str, str]] = None):
        """Error handler wrapper that calls the errorhandler method.

        Args:
            connection: Connections in which the error happened.
            cursor: Cursor in which the error happened.
            error_class: Class of error that needs handling.
            error_value: An optional dictionary of the error details.

        Returns:
            None if no exceptions are raised by the connection's and cursor's error handlers.

        Raises:
            A Snowflake error if connection and cursor are None.
        """
        if error_value is None:
            # no value indicates errorclass is error_object
            error_object = error_class
            error_class = type(error_object)
            error_value = {
                'msg': error_object.msg,
                'errno': error_object.errno,
                'sqlstate': error_object.sqlstate,
                'done_format_msg': True
            }
        else:
            error_value['done_format_msg'] = False

        if connection is not None:
            connection.messages.append((error_class, error_value))
        if cursor is not None:
            cursor.messages.append((error_class, error_value))
            cursor.errorhandler(connection, cursor, error_class, error_value)
            return
        elif connection is not None:
            connection.errorhandler(connection, cursor, error_class, error_value)
            return

        if issubclass(error_class, Error):
            raise error_class(msg=error_value['msg'],
                              errno=error_value.get('errno'),
                              sqlstate=error_value.get('sqlstate'),
                              sfqid=error_value.get('sfqid'))
        else:
            raise error_class(error_value)


Error.__str__ = lambda self: self.__unicode__()


class Warning(BASE_EXCEPTION_CLASS):
    """Exception for important warnings."""
    pass


class InterfaceError(Error):
    """Exception for errors related to the interface."""
    pass


class DatabaseError(Error):
    """Exception for errors related to the database."""
    pass


class InternalError(DatabaseError):
    """Exception for errors internal database errors."""
    pass


class OperationalError(DatabaseError):
    """Exception for errors related to the database's operation."""
    pass


class ProgrammingError(DatabaseError):
    """Exception for errors programming errors."""
    pass


class IntegrityError(DatabaseError):
    """Exception for errors regarding relational integrity."""
    pass


class DataError(DatabaseError):
    """Exception for errors reporting problems with processed data."""
    pass


class NotSupportedError(DatabaseError):
    """Exception for errors when an unsupported database feature was used."""

    # Not supported errors do not have any PII in their
    def telemetry_msg(self):
        return self.msg


class RevocationCheckError(OperationalError):
    """Exception for errors during certificate revocation check."""

    # We already send OCSP exception events
    def exception_telemetry(self, msg, cursor, connection):
        pass


# internal errors
class InternalServerError(Error):
    """Exception for 500 HTTP code for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get('msg') or 'HTTP 500: Internal Server Error',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class ServiceUnavailableError(Error):
    """Exception for 503 HTTP code for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 503: Service Unavailable',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class GatewayTimeoutError(Error):
    """Exception for 504 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 504: Gateway Timeout',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class ForbiddenError(Error):
    """Exception for 403 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 403: Forbidden',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class RequestTimeoutError(Error):
    """Exception for 408 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 408: Request Timeout',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class BadRequest(Error):
    """Exception for 400 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 400: Bad Request',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class BadGatewayError(Error):
    """Exception for 502 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 502: Bad Gateway',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class MethodNotAllowed(Error):
    """Exception for 405 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP 405: Method not allowed',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class OtherHTTPRetryableError(Error):
    """Exception for other HTTP error for retry."""

    def __init__(self, **kwargs):
        code = kwargs.get('code', 'n/a')
        Error.__init__(
            self, msg=kwargs.get('msg') or 'HTTP {}'.format(code),
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class MissingDependencyError(Error):
    """Exception for missing extras dependencies."""

    def __init__(self, dependency: str):
        super(MissingDependencyError, self).__init__(msg="Missing optional dependency: {}".format(dependency))
