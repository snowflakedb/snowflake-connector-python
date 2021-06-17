#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import logging
import os
import traceback
from logging import getLogger
from typing import TYPE_CHECKING, Dict, Optional, Type, Union

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

    def __init__(
        self,
        msg: Optional[str] = None,
        errno: Optional[int] = None,
        sqlstate: Optional[str] = None,
        sfqid: Optional[str] = None,
        done_format_msg: Optional[bool] = None,
        connection: Optional["SnowflakeConnection"] = None,
        cursor: Optional["SnowflakeCursor"] = None,
    ):
        self.msg = msg
        self.raw_msg = msg
        self.errno = errno or -1
        self.sqlstate = sqlstate or "n/a"
        self.sfqid = sfqid

        if not self.msg:
            self.msg = "Unknown error"

        if self.errno != -1 and not done_format_msg:
            if self.sqlstate != "n/a":
                if logger.getEffectiveLevel() in (logging.INFO, logging.DEBUG):
                    self.msg = (
                        f"{self.errno:06d} ({self.sqlstate}): {self.sfqid}: {self.msg}"
                    )
                else:
                    self.msg = f"{self.errno:06d} ({self.sqlstate}): {self.msg}"
            else:
                if logger.getEffectiveLevel() in (logging.INFO, logging.DEBUG):
                    self.msg = f"{self.errno:06d}: {self.errno}: {self.msg}"
                else:
                    self.msg = f"{self.errno:06d}: {self.msg}"

        # We want to skip the last frame/line in the traceback since it is the current frame
        self.telemetry_traceback = self.generate_telemetry_stacktrace()
        self.exception_telemetry(msg, cursor, connection)

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        return self.msg

    @staticmethod
    def generate_telemetry_stacktrace() -> str:
        # Get the current stack minus this function and the Error init function
        stack_frames = traceback.extract_stack()[:-2]
        filtered_frames = list()
        for frame in stack_frames:
            # Only add frames associated with the snowflake python connector to the telemetry stacktrace
            if connector_base_path in frame.filename:
                # Get the index to truncate the file path to hide any user path
                safe_path_index = frame.filename.find(connector_base_path)
                # Create a new frame with the truncated file name and without the line argument since that can
                # output sensitive data
                filtered_frames.append(
                    traceback.FrameSummary(
                        frame.filename[safe_path_index:],
                        frame.lineno,
                        frame.name,
                        line="",
                    )
                )

        return "".join(traceback.format_list(filtered_frames))

    def telemetry_msg(self) -> Optional[str]:
        if self.sqlstate != "n/a":
            return f"{self.errno:06d} ({self.sqlstate})"
        elif self.errno != -1:
            return f"{self.errno:06d}"
        else:
            return None

    def generate_telemetry_exception_data(self) -> Dict[str, str]:
        """Generate the data to send through telemetry."""
        telemetry_data = {
            TelemetryField.KEY_DRIVER_TYPE: CLIENT_NAME,
            TelemetryField.KEY_DRIVER_VERSION: SNOWFLAKE_CONNECTOR_VERSION,
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

        telemetry_data[TelemetryField.KEY_STACKTRACE] = SecretDetector.mask_secrets(
            self.telemetry_traceback
        )

        return telemetry_data

    def send_exception_telemetry(
        self,
        connection: Optional["SnowflakeConnection"],
        telemetry_data: Dict[str, str],
    ) -> None:
        """Send telemetry data by in-band telemetry if it is enabled, otherwise send through out-of-band telemetry."""
        if (
            connection is not None
            and connection.telemetry_enabled
            and not connection._telemetry.is_closed()
        ):
            # Send with in-band telemetry
            telemetry_data[TelemetryField.KEY_TYPE] = TelemetryField.SQL_EXCEPTION
            telemetry_data[TelemetryField.KEY_EXCEPTION] = self.__class__.__name__
            ts = get_time_millis()
            try:
                connection._log_telemetry(TelemetryData(telemetry_data, ts))
            except AttributeError:
                logger.debug("Cursor failed to log to telemetry.", exc_info=True)
        elif connection is None:
            # Send with out-of-band telemetry
            telemetry_oob = TelemetryService.get_instance()
            telemetry_oob.log_general_exception(self.__class__.__name__, telemetry_data)

    def exception_telemetry(
        self,
        msg: str,
        cursor: Optional["SnowflakeCursor"],
        connection: Optional["SnowflakeConnection"],
    ) -> None:
        """Main method to generate and send telemetry data for exceptions."""
        try:
            telemetry_data = self.generate_telemetry_exception_data()
            if cursor is not None:
                self.send_exception_telemetry(cursor.connection, telemetry_data)
            elif connection is not None:
                self.send_exception_telemetry(connection, telemetry_data)
            else:
                self.send_exception_telemetry(None, telemetry_data)
        except Exception:  # NOQA
            # Do nothing but log if sending telemetry fails
            logger.debug("Sending exception telemetry failed")

    @staticmethod
    def default_errorhandler(
        connection: "SnowflakeConnection",
        cursor: "SnowflakeCursor",
        error_class: Type["Error"],
        error_value: Dict[str, str],
    ) -> None:
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
            msg=error_value.get("msg"),
            errno=error_value.get("errno"),
            sqlstate=error_value.get("sqlstate"),
            sfqid=error_value.get("sfqid"),
            done_format_msg=error_value.get("done_format_msg"),
            connection=connection,
            cursor=cursor,
        )

    @staticmethod
    def errorhandler_wrapper_from_cause(
        connection: "SnowflakeConnection",
        cause: Union["Error", Exception],
        cursor: Optional["SnowflakeCursor"] = None,
    ) -> None:
        """Wrapper for errorhandler_wrapper, it is called with a cause instead of a dictionary.

        The dictionary is first extracted from the cause and then it's given to errorhandler_wrapper

        Args:
            connection: Connections in which the error happened.
            cursor: Cursor in which the error happened.
            cause: Error instance that we want to handle.

        Returns:
            None if no exceptions are raised by the connection's and cursor's error handlers.

        Raises:
            A Snowflake error if connection and cursor are None.
        """
        return Error.errorhandler_wrapper(
            connection,
            cursor,
            type(cause),
            {
                "msg": cause.msg,
                "errno": cause.errno,
                "sqlstate": cause.sqlstate,
                "done_format_msg": True,
            },
        )

    @staticmethod
    def errorhandler_wrapper(
        connection: Optional["SnowflakeConnection"],
        cursor: Optional["SnowflakeCursor"],
        error_class: Union[Type["Error"], Type[Exception]],
        error_value: Dict[str, Union[str, bool]],
    ) -> None:
        """Error handler wrapper that calls the errorhandler method.

        Args:
            connection: Connections in which the error happened.
            cursor: Cursor in which the error happened.
            error_class: Class of error that needs handling.
            error_value: An optional dictionary of the error details.

        Returns:
            None if no exceptions are raised by the connection's and cursor's error handlers.

        Raises:
            A Snowflake error if connection, or cursor are None. Otherwise it gives the
            exception to the first handler in that order.
        """

        handed_over = Error.hand_to_other_handler(
            connection,
            cursor,
            error_class,
            error_value,
        )
        if not handed_over:
            raise Error.errorhandler_make_exception(
                error_class,
                error_value,
            )

    @staticmethod
    def errorhandler_wrapper_from_ready_exception(
        connection: Optional["SnowflakeConnection"],
        cursor: Optional["SnowflakeCursor"],
        error_exc: Union["Error", Exception],
    ) -> None:
        """Like errorhandler_wrapper, but it takes a ready to go Exception."""
        if isinstance(error_exc, Error):
            error_value = {
                "msg": error_exc.msg,
                "errno": error_exc.errno,
                "sqlstate": error_exc.sqlstate,
                "sfqid": error_exc.sfqid,
            }
        else:
            error_value = error_exc.args

        handed_over = Error.hand_to_other_handler(
            connection,
            cursor,
            type(error_exc),
            error_value,
        )
        if not handed_over:
            raise error_exc

    @staticmethod
    def hand_to_other_handler(
        connection: Optional["SnowflakeConnection"],
        cursor: Optional["SnowflakeCursor"],
        error_class: Union[Type["Error"], Type[Exception]],
        error_value: Dict[str, Union[str, bool]],
    ) -> bool:
        """If possible give error to a higher error handler in connection, or cursor.

        Returns:
            Whether it error was successfully given to a handler.
        """
        if connection is not None:
            connection.messages.append((error_class, error_value))
        if cursor is not None:
            cursor.messages.append((error_class, error_value))
            cursor.errorhandler(connection, cursor, error_class, error_value)
            return True
        elif connection is not None:
            connection.errorhandler(connection, cursor, error_class, error_value)
            return True
        return False

    @staticmethod
    def errorhandler_make_exception(
        error_class: Union[Type["Error"], Type[Exception]],
        error_value: Dict[str, Union[str, bool]],
    ) -> Union["Error", Exception]:
        """Helper function to errorhandler_wrapper that creates the exception."""
        error_value.setdefault("done_format_msg", False)

        if issubclass(error_class, Error):
            return error_class(
                msg=error_value["msg"],
                errno=error_value.get("errno"),
                sqlstate=error_value.get("sqlstate"),
                sfqid=error_value.get("sfqid"),
            )
        return error_class(error_value)


class _Warning(BASE_EXCEPTION_CLASS):
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
            msg=kwargs.get("msg") or "HTTP 500: Internal Server Error",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class ServiceUnavailableError(Error):
    """Exception for 503 HTTP code for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 503: Service Unavailable",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class GatewayTimeoutError(Error):
    """Exception for 504 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 504: Gateway Timeout",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class ForbiddenError(Error):
    """Exception for 403 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 403: Forbidden",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class RequestTimeoutError(Error):
    """Exception for 408 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 408: Request Timeout",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class BadRequest(Error):
    """Exception for 400 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 400: Bad Request",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class BadGatewayError(Error):
    """Exception for 502 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 502: Bad Gateway",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class MethodNotAllowed(Error):
    """Exception for 405 HTTP error for retry."""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get("msg") or "HTTP 405: Method not allowed",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class OtherHTTPRetryableError(Error):
    """Exception for other HTTP error for retry."""

    def __init__(self, **kwargs):
        code = kwargs.get("code", "n/a")
        Error.__init__(
            self,
            msg=kwargs.get("msg") or f"HTTP {code}",
            errno=kwargs.get("errno"),
            sqlstate=kwargs.get("sqlstate"),
            sfqid=kwargs.get("sfqid"),
        )


class MissingDependencyError(Error):
    """Exception for missing extras dependencies."""

    def __init__(self, dependency: str):
        super(MissingDependencyError, self).__init__(
            msg=f"Missing optional dependency: {dependency}"
        )


class BindUploadError(Error):
    """Exception for bulk array binding stage optimization fails."""

    pass
