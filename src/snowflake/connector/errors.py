#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import logging
from logging import getLogger
from typing import TYPE_CHECKING, Dict

from snowflake.connector.constants import UTF8

from .compat import BASE_EXCEPTION_CLASS

if TYPE_CHECKING:  # pragma: no cover
    from .connection import SnowflakeConnection
    from .cursor import SnowflakeCursor

logger = getLogger(__name__)


class Error(BASE_EXCEPTION_CLASS):
    """Base Snowflake exception class."""

    def __init__(self, msg=None, errno=None, sqlstate=None, sfqid=None,
                 done_format_msg=False):
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

    def __repr__(self):
        return self.__str__()

    def __unicode__(self):
        return self.msg

    def __bytes__(self):
        return self.__unicode__().encode(UTF8)

    @staticmethod
    def default_errorhandler(connection: 'SnowflakeConnection',
                             cursor: 'SnowflakeCursor',
                             error_class,
                             error_value: Dict[str, str]):
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
            done_format_msg=error_value.get('done_format_msg'))

    @staticmethod
    def errorhandler_wrapper(connection, cursor, error_class, error_value=None):
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
    pass


class RevocationCheckError(OperationalError):
    """Exception for errors during certificate revocation check."""
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

    def __init__(self, dependency):
        super(MissingDependencyError, self).__init__(msg="Missing optional dependency: {}".format(dependency))
