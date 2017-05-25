#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import re
import sys
import uuid
from io import StringIO
from threading import Lock
from time import strptime

from . import errors
from . import network
from .chunk_downloader import SnowflakeChunkDownloader
from .compat import (TO_UNICODE, IS_OLD_PYTHON, urlencode, PY2, PY_ISSUE_23517)
from .converter import SnowflakeConverter
from .converter_issue23517 import SnowflakeConverterIssue23517
from .cursor import SnowflakeCursor
from .errorcode import (ER_CONNECTION_IS_CLOSED,
                        ER_NO_ACCOUNT_NAME, ER_OLD_PYTHON, ER_NO_USER,
                        ER_NO_PASSWORD, ER_INVALID_VALUE)
from .errors import (Error, ProgrammingError, InterfaceError,
                     DatabaseError)
from .sqlstate import (SQLSTATE_CONNECTION_NOT_EXISTS,
                       SQLSTATE_FEATURE_NOT_SUPPORTED)
from .util_text import split_statements, construct_hostname

try:
    import snowflake.internal.constants

    TEST_ACCOUNTS = snowflake.internal.constants.TEST_ACCOUNTS
except ImportError:
    TEST_ACCOUNTS = frozenset([])

import logging
from logging import getLogger

# default configs
DEFAULT_CONFIGURATION = {
    u'dsn': None,  # standard
    u'user': u'',  # standard
    u'password': u'',  # standard
    u'host': u'127.0.0.1',  # standard
    u'port': 8080,  # standard
    u'database': None,  # standard
    u'proxy_host': None,  # snowflake
    u'proxy_port': None,  # snowflake
    u'proxy_user': None,  # snowflake
    u'proxy_password': None,  # snowflake
    u'protocol': u'http',  # snowflake
    u'warehouse': None,  # snowflake
    u'region': None,  # snowflake
    u'account': None,  # snowflake
    u'schema': None,  # snowflake
    u'role': None,  # snowflake
    u'session_id': None,  # snowflake
    u'connect_timeout': None,  # snowflake internal connection timeout
    u'request_timeout': None,  # snowflake internal request timeout
    u'login_timeout': 60,  # login timeout
    u'network_timeout': None,  # network timeout (infinite by default)
    u'passcode_in_password': False,  # Snowflake MFA
    u'passcode': None,  # Snowflake MFA
    u'authenticator': network.DEFAULT_AUTHENTICATOR,
    u'mfa_callback': None,
    u'password_callback': None,
    u'application': network.CLIENT_NAME,
    u'internal_application_name': network.CLIENT_NAME,
    u'internal_application_version': network.CLIENT_VERSION,

    u'insecure_mode': False,  # Error security fix requirement
    u'injectClientPause': 0,  # snowflake internal
    u'session_parameters': {},  # snowflake session parameters
    u'autocommit': None,  # snowflake
    u'numpy': False,  # snowflake
    u'ocsp_response_cache_filename': None,  # snowflake internal
    u'converter_class':
        SnowflakeConverter if not PY_ISSUE_23517 else SnowflakeConverterIssue23517,
    u'chunk_downloader_class': SnowflakeChunkDownloader,  # snowflake internal
}

APPLICATION_RE = re.compile(r'[\w\d_]+')

# adding the exception class to Connection class
for m in [method for method in dir(errors) if
          callable(getattr(errors, method))]:
    setattr(sys.modules[__name__], m, getattr(errors, m))

# Workaround for https://bugs.python.org/issue7980
strptime('20150102030405', '%Y%m%d%H%M%S')


class SnowflakeConnection(object):
    u"""
    Implementation of the connection object for the Snowflake Database. Use
    connect(..) to get the object.
    """

    def __init__(self, **kwargs):
        self._lock_sequence_counter = Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self.messages = []
        self.logger = getLogger(__name__)
        self.logger.info(
            u"Snowflake Connector for Python Version: %s, "
            u"Python Version: %s, Platform: %s",
            network.SNOWFLAKE_CONNECTOR_VERSION,
            network.PYTHON_VERSION, network.PLATFORM)

        self._con = None
        for name, value in DEFAULT_CONFIGURATION.items():
            setattr(self, u'_' + name, value)

        self.converter = None
        self.connect(**kwargs)

    def __del__(self):
        try:
            self.close()
        except:
            pass

    @property
    def session_id(self):
        u"""
        session id
        """
        return self._session_id

    @property
    def user(self):
        u"""
        User name
        """
        return self._user

    @property
    def host(self):
        u"""
        Host name
        """
        return self._host

    @property
    def port(self):
        u"""
        Port number
        """
        return self._port

    @property
    def region(self):
        u"""
        Region name if not the default Snowflake Database deployment
        """
        return self._region

    @property
    def proxy_host(self):
        u"""
        Proxy host name
        """
        return self._proxy_host

    @property
    def proxy_port(self):
        u"""
        Proxy port number
        """
        return self._proxy_port

    @property
    def proxy_user(self):
        u"""
        Proxy user name
        """
        return self._proxy_user

    @property
    def proxy_password(self):
        u"""
        Proxy password
        """
        return self._proxy_password

    @property
    def account(self):
        u"""
        Account name
        """
        return self._account

    @property
    def connect_timeout(self):
        u"""Connection timeout
        """
        return self._connect_timeout

    @property
    def request_timeout(self):
        u"""Request timeout for one query
        """
        return self._request_timeout

    @property
    def login_timeout(self):
        """
        Login timeout. Used in authentication
        """
        return self._login_timeout

    @property
    def network_timeout(self):
        """
        Network timeout. Used for general purpose
        """
        return self._network_timeout

    @property
    def rest(self):
        u"""
        Snowflake REST API object. Internal use only. Maybe removed in the
        later release
        """
        return self._con

    @property
    def application(self):
        u"""
        Application name. By default, PythonConnector.
        Set this for Snowflake to identify the application by name
        """
        return self._application

    @property
    def errorhandler(self):
        u"""
        Error handler. By default, an exception is raised on error.
        """
        return self._errorhandler

    @property
    def converter_class(self):
        """
        Converter Class
        """
        return self._converter_class

    @errorhandler.setter
    def errorhandler(self, value):
        if value is None:
            raise ProgrammingError(u'None errorhandler is specified')
        self._errorhandler = value

    def connect(self, **kwargs):
        u"""
        Connects to the database
        """
        self.logger.debug(u'connect')
        if len(kwargs) > 0:
            self.__config(**kwargs)

        self.__set_error_attributes()

        self.__open_connection(mfa_callback=kwargs.get('mfa_callback'),
                               password_callback=kwargs.get(
                                   'password_callback'))
        self.__post_connection()

    def close(self):
        u"""
        Closes the connection.
        """
        try:
            if not self._con:
                return

            self._con._delete_session()
            self._con.close()
            self._con = None
            del self.messages[:]
        except:
            pass

    def is_closed(self):
        u"""
        Is closed?
        """
        return self._con is None

    def autocommit(self, mode):
        u"""
        Sets autocommit mode. True/False. Default: True
        """
        if not self._con:
            Error.errorhandler_wrapper(
                self, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })
        if not isinstance(mode, bool):
            Error.errorhandler_wrapper(
                self, None, ProgrammingError,
                {
                    u'msg': u'Invalid parameter: {0}'.format(mode),
                    u'errno': ER_INVALID_VALUE,
                }
            )
        try:
            self.cursor().execute(
                "ALTER SESSION SET autocommit={0}".format(mode))
        except Error as e:
            if e.sqlstate == SQLSTATE_FEATURE_NOT_SUPPORTED:
                self.logger.info(u"Autocommit feature is not enabled for this "
                                 u"connection. Ignored")
            else:
                raise e

    def commit(self):
        u"""Commits the current transaction.
        """
        self.cursor().execute("COMMIT")

    def rollback(self):
        u"""Rollbacks the current transaction.
        """
        self.cursor().execute("ROLLBACK")

    def cursor(self, cursor_class=SnowflakeCursor):
        u"""Creates a cursor object. Each statement should create a new cursor
        object.
        """
        self.logger.debug(u'cursor')
        if not self._con:
            Error.errorhandler_wrapper(
                self, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,

                })
        return cursor_class(self)

    def execute_string(self, sql_text,
                       remove_comments=False,
                       return_cursors=True):
        """
        Executes a SQL text including multiple statements.
        This is a non-standard convenient method.
        """
        ret = []
        if PY2:
            stream = StringIO(sql_text.decode('utf-8') if isinstance(
                sql_text, str) else sql_text)
        else:
            stream = StringIO(sql_text)
        for sql, is_put_or_get in split_statements(
                stream, remove_comments=remove_comments):
            cur = self.cursor()
            if return_cursors:
                ret.append(cur)
            cur.execute(sql, _is_put_get=is_put_or_get)
        return ret

    def execute_stream(self, stream,
                       remove_comments=False):
        """
        Executes a stream of SQL statements.
        This is a non-standard convenient method.
        """
        for sql, is_put_or_get in split_statements(
                stream, remove_comments=remove_comments):
            cur = self.cursor()
            cur.execute(sql, _is_put_get=is_put_or_get)
            yield cur

    def __set_error_attributes(self):
        for m in [method for method in dir(errors) if
                  callable(getattr(errors, method))]:
            setattr(self, m, getattr(errors, m))

    def __post_connection(self):
        """
        Executes post connection process
        """
        # load current session info
        self.logger.debug(u'__post connection')
        self.converter = self._converter_class(
            use_sfbinaryformat=False,
            use_numpy=self._numpy)

    def __open_connection(self, mfa_callback, password_callback):
        u"""
        Opens a new network connection
        """
        self._con = network.SnowflakeRestful(
            host=self._host,
            port=self._port,
            proxy_host=self._proxy_host,
            proxy_port=self._proxy_port,
            proxy_user=self._proxy_user,
            proxy_password=self._proxy_password,
            protocol=self._protocol,
            connect_timeout=self._connect_timeout,
            request_timeout=self._request_timeout,
            injectClientPause=self._injectClientPause,
            connection=self)
        self.logger.debug(u'REST API object was created: %s:%s, proxy=%s:%s, '
                          u'proxy_user=%s',
                          self._host,
                          self._port,
                          self._proxy_host,
                          self._proxy_port,
                          self._proxy_user)

        saml_response = None
        if self._authenticator.upper() != network.DEFAULT_AUTHENTICATOR:
            saml_response = self._con.authenticate_by_saml(
                authenticator=self._authenticator,
                account=self._account,
                user=self._user,
                password=self._password,
            )

        if self._autocommit is not None:
            self._session_parameters['AUTOCOMMIT'] = self._autocommit

        token = self._token if hasattr(self, u'_token') else None
        master_token = self._master_token if hasattr(
            self,
            u'_master_token') else None
        self._con.authenticate(
            account=self._account,
            user=self._user,
            password=self._password,
            master_token=master_token,
            token=token,
            database=self._database,
            schema=self._schema,
            warehouse=self._warehouse,
            role=self._role,
            passcode=self._passcode,
            passcode_in_password=self._passcode_in_password,
            saml_response=saml_response,
            mfa_callback=mfa_callback,
            password_callback=password_callback,
            session_parameters=self._session_parameters,
        )
        self._password = None
        self._token = self._con.token
        self._master_token = self._con.master_token

    def __config(self, **kwargs):
        u"""
        Sets the parameters
        """
        self.logger.debug(u'__config')
        for name, value in kwargs.items():
            if name == u'sequence_counter':
                self.sequence_counter = value
            elif name == u'application':
                if not APPLICATION_RE.match(value):
                    msg = u'Invalid application name: {0}'.format(value)
                    raise ProgrammingError(
                        msg=msg,
                        errno=0
                    )
                else:
                    setattr(self, u'_' + name, value)
            else:
                setattr(self, u'_' + name, value)

        if u'account' in kwargs and kwargs[u'account'] not in TEST_ACCOUNTS:
            if u'host' not in kwargs:
                setattr(self, u'_host',
                        construct_hostname(
                            kwargs.get(u'region'), self._account))
            if u'port' not in kwargs:
                setattr(self, u'_port', u'443')
            if u'protocol' not in kwargs:
                setattr(self, u'_protocol', u'https')

        if not self._user:
            Error.errorhandler_wrapper(
                self, None, ProgrammingError,
                {
                    u'msg': u"User is empty",
                    u'errno': ER_NO_USER
                })
        if not self._password:
            Error.errorhandler_wrapper(
                self, None, ProgrammingError,
                {
                    u'msg': u"Password is empty",
                    u'errno': ER_NO_PASSWORD
                })

        if not self._account:
            Error.errorhandler_wrapper(
                self, None, ProgrammingError,
                {
                    u'msg': u"Account must be specified",
                    u'errno': ER_NO_ACCOUNT_NAME
                })
        if u'.' in self._account:
            # remove region subdomain
            self._account = self._account[0:self._account.find(u'.')]

        if self._insecure_mode:
            self.logger.info(
                u'THIS CONNECTION IS IN INSECURE MODE. IT '
                u'MEANS THE CERTIFICATE WILL BE VALIDATED BUT THE '
                u'CERTIFICATE REVOCATION STATUS WILL NOT BE '
                u'CHECKED.')
        if not self._insecure_mode and self._protocol == u'https' and \
                        self._account not in TEST_ACCOUNTS:
            if IS_OLD_PYTHON():
                msg = (u"ERROR: The ssl package installed with your Python "
                       u"- version {0} - does not have the security fix. "
                       u"Upgrade to Python 2.7.9/3.4.3 or higher.\n").format(
                    network.PYTHON_VERSION)
                raise InterfaceError(
                    msg=msg,
                    errno=ER_OLD_PYTHON)

    def _cmd_query(self, sql, sequence_counter, request_id,
                   is_file_transfer=False, statement_params=None,
                   is_internal=False, _no_results=False):
        u"""
        Executes a query with a sequence counter.
        """
        self.logger.debug(u'_cmd_query')
        data = {
            u'sqlText': sql,
            u'asyncExec': _no_results,
            u'sequenceId': sequence_counter,
        }
        if statement_params is not None:
            data[u'parameters'] = statement_params
        if is_internal:
            data[u'isInternal'] = is_internal
        client = u'sfsql_file_transfer' if is_file_transfer else u'sfsql'

        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            self.logger.debug(
                u'sql=[%s], sequence_id=[%s], is_file_transfer=[%s]',
                u' '.join(
                    line.strip() for line in
                    data[u'sqlText'].split(u'\n')),
                data[u'sequenceId'],
                is_file_transfer
            )

        url_parameters = {u'requestId': request_id}

        # retry 1000 times/4.5 hours for general queries
        ret = self._con.request(
            u'/queries/v1/query-request?' + urlencode(url_parameters),
            data, client=client, _no_results=_no_results)

        if ret is not None and u'data' in ret and ret[u'data'] is None:
            ret[u'data'] = {}
        return ret

    def _cancel_query(self, sql, sequence_counter, request_id):
        u"""
        Cancels the query by the sequence counter. The sequence counter
        is used to identify the query submitted by the client.
        """
        self.logger.debug(u'_cancel_query sql=[%s], sequence_id=[%s]', sql,
                          sequence_counter)
        url_parameters = {u'requestId': TO_UNICODE(uuid.uuid4())}

        return self._con.request(
            u'/queries/v1/abort-request?' + urlencode(url_parameters), {
                u'sqlText': sql,
                u'requestId': TO_UNICODE(request_id),
            })

    def _next_sequence_counter(self):
        u"""Gets next sequence counter. Used internally.
        """
        with self._lock_sequence_counter:
            self.sequence_counter += 1
            self.logger.debug(u'sequence counter: %s', self.sequence_counter)
            return self.sequence_counter

    def __enter__(self):
        u"""
        context manager
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        u"""
        context manager with commit or rollback
        """
        if exc_tb is None:
            self.commit()
        else:
            self.rollback()
        self.close()
