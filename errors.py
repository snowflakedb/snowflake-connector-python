#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import logging
from logging import getLogger

from snowflake.connector.constants import UTF8
from .compat import BASE_EXCEPTION_CLASS

logger = getLogger(__name__)


class Error(BASE_EXCEPTION_CLASS):
    u"""
    Exception that is base class for all other error exceptions
    """

    def __init__(self, msg=None, errno=None, sqlstate=None, sfqid=None,
                 done_format_msg=False):
        self.msg = msg
        self.raw_msg = msg
        self.errno = errno or -1
        self.sqlstate = sqlstate or "n/a"
        self.sfqid = sfqid

        if not self.msg:
            self.msg = u'Unknown error'

        if self.errno != -1 and not done_format_msg:
            if self.sqlstate != "n/a":
                if logger.getEffectiveLevel() in (logging.INFO,
                                                  logging.DEBUG):
                    self.msg = u'{errno:06d} ({sqlstate}): {sfqid}: {msg}'.format(
                        errno=self.errno, msg=self.msg,
                        sqlstate=self.sqlstate,
                        sfqid=self.sfqid)
                else:
                    self.msg = u'{errno:06d} ({sqlstate}): {msg}'.format(
                        errno=self.errno,
                        sqlstate=self.sqlstate,
                        msg=self.msg)
            else:
                if logger.getEffectiveLevel() in (logging.INFO,
                                                  logging.DEBUG):
                    self.msg = u'{errno:06d}: {sfqid}: {msg}'.format(
                        errno=self.errno, msg=self.msg,
                        sfqid=self.sfqid)
                else:
                    self.msg = u'{errno:06d}: {msg}'.format(errno=self.errno,
                                                            msg=self.msg)

    def __repr__(self):
        return self.__str__()

    def __unicode__(self):
        return self.msg

    def __bytes__(self):
        return self.__unicode__().encode(UTF8)

    @staticmethod
    def default_errorhandler(connection, cursor, errorclass, errorvalue):
        u"""
        Default error handler that raises an error
        """
        raise errorclass(
            msg=errorvalue.get(u'msg'),
            errno=errorvalue.get(u'errno'),
            sqlstate=errorvalue.get(u'sqlstate'),
            sfqid=errorvalue.get(u'sfqid'),
            done_format_msg=errorvalue.get(u'done_format_msg'))

    @staticmethod
    def errorhandler_wrapper(connection, cursor, errorclass, errorvalue=None):
        u"""
        Error handler wrapper that calls the errorhandler method
        """
        if errorvalue is None:
            # no value indicates errorclass is errorobject
            errorobject = errorclass
            errorclass = type(errorobject)
            errorvalue = {
                u'msg': errorobject.msg,
                u'errno': errorobject.errno,
                u'sqlstate': errorobject.sqlstate,
                u'done_format_msg': True
            }
        else:
            errorvalue[u'done_format_msg'] = False

        if connection is not None:
            connection.messages.append((errorclass, errorvalue))
        if cursor is not None:
            cursor.messages.append((errorclass, errorvalue))
            cursor.errorhandler(connection, cursor, errorclass, errorvalue)
            return
        elif connection is not None:
            connection.errorhandler(connection, cursor, errorclass, errorvalue)
            return

        if issubclass(errorclass, Error):
            raise errorclass(msg=errorvalue[u'msg'],
                             errno=errorvalue.get(u'errno'),
                             sqlstate=errorvalue.get(u'sqlstate'),
                             sfqid=errorvalue.get(u'sfqid'))
        else:
            raise errorclass(errorvalue)


Error.__str__ = lambda self: self.__unicode__()


class Warning(BASE_EXCEPTION_CLASS):
    u"""Exception for important warnings"""
    pass


class InterfaceError(Error):
    u"""Exception for errors related to the interface"""
    pass


class DatabaseError(Error):
    u"""Exception for errors related to the database"""
    pass


class InternalError(DatabaseError):
    u"""Exception for errors internal database errors"""
    pass


class OperationalError(DatabaseError):
    u"""Exception for errors related to the database's operation"""
    pass


class ProgrammingError(DatabaseError):
    u"""Exception for errors programming errors"""
    pass


class IntegrityError(DatabaseError):
    u"""Exception for errors regarding relational integrity"""
    pass


class DataError(DatabaseError):
    u"""Exception for errors reporting problems with processed data"""
    pass


class NotSupportedError(DatabaseError):
    u"""Exception for errors when an unsupported database feature was used"""
    pass


class RevocationCheckError(OperationalError):
    u"""Exception for errors during certificate revocation check"""
    pass


# internal errors
class InternalServerError(Error):
    u"""Exception for 500 HTTP code for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self,
            msg=kwargs.get('msg') or u'HTTP 500: Internal Server Error',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class ServiceUnavailableError(Error):
    u"""Exception for 503 HTTP code for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 503: Service Unavailable',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class GatewayTimeoutError(Error):
    u"""Exception for 504 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 504: Gateway Timeout',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class ForbiddenError(Error):
    """Exception for 403 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 403: Forbidden',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class RequestTimeoutError(Error):
    u"""Exception for 408 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 408: Request Timeout',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class BadRequest(Error):
    u"""Exception for 400 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 400: Bad Request',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class BadGatewayError(Error):
    u"""Exception for 502 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 502: Bad Gateway',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class MethodNotAllowed(Error):
    u"""Exception for 405 HTTP error for retry"""

    def __init__(self, **kwargs):
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP 405: Method not allowed',
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class OtherHTTPRetryableError(Error):
    """
    Exception for other HTTP error for retry
    """

    def __init__(self, **kwargs):
        code = kwargs.get('code', 'n/a')
        Error.__init__(
            self, msg=kwargs.get('msg') or u'HTTP {}'.format(code),
            errno=kwargs.get('errno'),
            sqlstate=kwargs.get('sqlstate'),
            sfqid=kwargs.get('sfqid'))


class MissingDependencyError(Error):
    u"""Exception for missing extras dependencies"""

    def __init__(self, dependency):
        super(MissingDependencyError, self).__init__(msg="Missing optional dependency: {}".format(dependency))
