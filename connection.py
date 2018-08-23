#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import re
import sys
import uuid
from io import StringIO
from logging import getLogger
from threading import Lock
from time import strptime

from . import errors
from .auth import Auth
from .auth_default import AuthByDefault
from .auth_keypair import AuthByKeyPair
from .auth_oauth import AuthByOAuth
from .auth_okta import AuthByOkta
from .auth_webbrowser import AuthByWebBrowser
from .chunk_downloader import SnowflakeChunkDownloader
from .compat import (TO_UNICODE, IS_OLD_PYTHON, urlencode, PY2, PY_ISSUE_23517)
from .converter import SnowflakeConverter
from .converter_issue23517 import SnowflakeConverterIssue23517
from .cursor import SnowflakeCursor
from .errorcode import (ER_CONNECTION_IS_CLOSED,
                        ER_NO_ACCOUNT_NAME, ER_OLD_PYTHON, ER_NO_USER,
                        ER_NO_PASSWORD, ER_INVALID_VALUE,
                        ER_FAILED_PROCESSING_PYFORMAT,
                        ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE)
from .errors import (Error, ProgrammingError, InterfaceError,
                     DatabaseError)
from .network import (
    SNOWFLAKE_CONNECTOR_VERSION,
    PYTHON_VERSION,
    PLATFORM,
    CLIENT_NAME,
    CLIENT_VERSION,
    DEFAULT_AUTHENTICATOR,
    EXTERNAL_BROWSER_AUTHENTICATOR,
    EXTERNAL_BROWSER_CACHE_DISABLED_AUTHENTICATOR,
    KEY_PAIR_AUTHENTICATOR,
    OAUTH_AUTHENTICATOR,
    SnowflakeRestful,
)
from .sqlstate import (SQLSTATE_CONNECTION_NOT_EXISTS,
                       SQLSTATE_FEATURE_NOT_SUPPORTED)
from .telemetry import (TelemetryClient)
from .time_util import get_time_millis
from .util_text import split_statements, construct_hostname

SUPPORTED_PARAMSTYLES = {
    u"qmark",
    u'numeric',
    u'format',
    u'pyformat',
}
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
    u'login_timeout': 120,  # login timeout
    u'network_timeout': None,  # network timeout (infinite by default)
    u'passcode_in_password': False,  # Snowflake MFA
    u'passcode': None,  # Snowflake MFA
    u'private_key': None,
    u'token': None,  # OAuth or JWT Token
    u'authenticator': DEFAULT_AUTHENTICATOR,
    u'mfa_callback': None,
    u'password_callback': None,
    u'application': CLIENT_NAME,
    u'internal_application_name': CLIENT_NAME,
    u'internal_application_version': CLIENT_VERSION,

    u'insecure_mode': False,  # Error security fix requirement
    u'inject_client_pause': 0,  # snowflake internal
    u'session_parameters': {},  # snowflake session parameters
    u'autocommit': None,  # snowflake
    u'numpy': False,  # snowflake
    u'ocsp_response_cache_filename': None,  # snowflake internal
    u'converter_class':
        SnowflakeConverter if not PY_ISSUE_23517 else SnowflakeConverterIssue23517,
    u'chunk_downloader_class': SnowflakeChunkDownloader,  # snowflake internal
    u'validate_default_parameters': False,  # snowflake
    u'probe_connection': False,  # snowflake
    u'paramstyle': None,  # standard/snowflake
    u'timezone': None,  # snowflake
}

APPLICATION_RE = re.compile(r'[\w\d_]+')

# adding the exception class to Connection class
for m in [method for method in dir(errors) if
          callable(getattr(errors, method))]:
    setattr(sys.modules[__name__], m, getattr(errors, m))

# Workaround for https://bugs.python.org/issue7980
strptime('20150102030405', '%Y%m%d%H%M%S')

logger = getLogger(__name__)


class SnowflakeConnection(object):
    u"""
    Implementation of the connection object for the Snowflake Database. Use
    connect(..) to get the object.
    """

    def __init__(self, **kwargs):
        self._lock_sequence_counter = Lock()
        self.sequence_counter = 0
        self._errorhandler = Error.default_errorhandler
        self._lock_converter = Lock()
        self.messages = []
        logger.info(
            u"Snowflake Connector for Python Version: %s, "
            u"Python Version: %s, Platform: %s",
            SNOWFLAKE_CONNECTOR_VERSION,
            PYTHON_VERSION, PLATFORM)

        self._rest = None
        for name, value in DEFAULT_CONFIGURATION.items():
            setattr(self, u'_' + name, value)

        self.converter = None
        self.connect(**kwargs)
        self._telemetry = TelemetryClient(self._rest)
        self._telemetry_enabled = False

    def __del__(self):
        try:
            self.close()
        except:
            pass

    @property
    def insecure_mode(self):
        u"""
        insecure mode. It validates the TLS certificate but doesn't check
        a revocation status.
        :return:
        """
        return self._insecure_mode

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
    def database(self):
        u"""
        Database name
        """
        return self._database

    @property
    def schema(self):
        u"""
        Schema name
        """
        return self._schema

    @property
    def warehouse(self):
        u"""
        Schema name
        """
        return self._warehouse

    @property
    def role(self):
        u"""
        Role name
        """
        return self._role

    @property
    def login_timeout(self):
        """
        Login timeout. Used in authentication
        """
        return int(self._login_timeout) if self._login_timeout is not None \
            else None

    @property
    def network_timeout(self):
        """
        Network timeout. Used for general purpose
        """
        return int(self._network_timeout) if self._network_timeout is not \
                                             None else None

    @property
    def rest(self):
        u"""
        Snowflake REST API object. Internal use only. Maybe removed in the
        later release
        """
        return self._rest

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

    @errorhandler.setter
    def errorhandler(self, value):
        if value is None:
            raise ProgrammingError(u'None errorhandler is specified')
        self._errorhandler = value

    @property
    def converter_class(self):
        """
        Converter Class
        """
        return self._converter_class

    @property
    def validate_default_parameters(self):
        """
        Validate default database, schema, role and warehouse?
        """
        return self._validate_default_parameters

    @property
    def is_pyformat(self):
        """
        Is binding parameter style pyformat or format?

        The default value should be True.
        """
        return self._paramstyle in (u'pyformat', u'format')

    def connect(self, **kwargs):
        u"""
        Connects to the database
        """
        logger.debug(u'connect')
        if len(kwargs) > 0:
            self.__config(**kwargs)

        self.__set_error_attributes()
        self.__open_connection()

    def close(self):
        u"""
        Closes the connection.
        """
        try:
            if not self.rest:
                return

            # close telemetry first, since it needs rest to send remaining data
            self._telemetry.close()
            self.rest.delete_session()
            self.rest.close()
            self._rest = None
            del self.messages[:]
        except:
            pass

    def is_closed(self):
        u"""
        Is closed?
        """
        return self.rest is None

    def autocommit(self, mode):
        u"""
        Sets autocommit mode. True/False. Default: True
        """
        if not self.rest:
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
                logger.info(u"Autocommit feature is not enabled for this "
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
        logger.debug(u'cursor')
        if not self.rest:
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

    def __open_connection(self):
        u"""
        Opens a new network connection
        """
        self.converter = self._converter_class(
            use_sfbinaryformat=False,
            use_numpy=self._numpy)

        self._rest = SnowflakeRestful(
            host=self.host,
            port=self.port,
            proxy_host=self.proxy_host,
            proxy_port=self.proxy_port,
            proxy_user=self.proxy_user,
            proxy_password=self.proxy_password,
            protocol=self._protocol,
            inject_client_pause=self._inject_client_pause,
            connection=self)
        logger.debug(u'REST API object was created: %s:%s, proxy=%s:%s, '
                     u'proxy_user=%s',
                     self.host,
                     self.port,
                     self.proxy_host,
                     self.proxy_port,
                     self.proxy_user)

        if self.host.endswith(u".privatelink.snowflakecomputing.com"):
            ocsp_cache_server = \
                u'http://ocsp{}/ocsp_response_cache.json'.format(
                    self.host[self.host.index('.'):])
            os.environ['SF_OCSP_RESPONSE_CACHE_SERVER_URL'] = ocsp_cache_server
            logger.debug(u"OCSP Cache Server is updated: %s", ocsp_cache_server)
        else:
            if 'SF_OCSP_RESPONSE_CACHE_SERVER_URL' in os.environ:
                del os.environ['SF_OCSP_RESPONSE_CACHE_SERVER_URL']

        if self._authenticator == DEFAULT_AUTHENTICATOR:
            auth_instance = AuthByDefault(self._password)
        elif self._authenticator in (
                EXTERNAL_BROWSER_AUTHENTICATOR,
                EXTERNAL_BROWSER_CACHE_DISABLED_AUTHENTICATOR):
            auth_instance = AuthByWebBrowser(self.rest, self.application)
        elif self._authenticator == KEY_PAIR_AUTHENTICATOR:
            auth_instance = AuthByKeyPair(self._private_key)
        elif self._authenticator == OAUTH_AUTHENTICATOR:
            auth_instance = AuthByOAuth(self._token)
        else:
            # okta URL, e.g., https://<account>.okta.com/
            auth_instance = AuthByOkta(self.rest, self.application)

        if self._session_parameters is None:
            self._session_parameters = {}
        if self._autocommit is not None:
            self._session_parameters['AUTOCOMMIT'] = self._autocommit

        if self._timezone is not None:
            self._session_parameters['TIMEZONE'] = self._timezone

        if self._authenticator == EXTERNAL_BROWSER_AUTHENTICATOR:
            # enable storing temporary credential in a file
            self._session_parameters['CLIENT_STORE_TEMPORARY_CREDENTIAL'] = True
        elif self._authenticator == \
                EXTERNAL_BROWSER_CACHE_DISABLED_AUTHENTICATOR:
            # disable storing temporary credential in a file
            self._session_parameters[
                'CLIENT_STORE_TEMPORARY_CREDENTIAL'] = False

        auth = Auth(self.rest)
        if not auth.read_temporary_credential(
                self.account, self.user, self._session_parameters):
            self.__authenticate(auth_instance)
        else:
            # set the current objects as the session is derived from the id
            # token, and the current objects may be different.
            self._set_current_objects()

        self._password = None  # ensure password won't persist

    def __config(self, **kwargs):
        u"""
        Sets the parameters
        """
        logger.debug(u'__config')
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

        if self._paramstyle is None:
            import snowflake.connector
            self._paramstyle = snowflake.connector.paramstyle
        elif self._paramstyle not in SUPPORTED_PARAMSTYLES:
            raise ProgrammingError(
                msg=u'Invalid paramstyle is specified',
                errno=ER_INVALID_VALUE
            )

        if u'account' in kwargs:
            if u'host' not in kwargs:
                setattr(self, u'_host',
                        construct_hostname(
                            kwargs.get(u'region'), self._account))
            if u'port' not in kwargs:
                setattr(self, u'_port', u'443')
            if u'protocol' not in kwargs:
                setattr(self, u'_protocol', u'https')

        if not self.user and self._authenticator != OAUTH_AUTHENTICATOR:
            # OAuth Authentication does not require a username
            Error.errorhandler_wrapper(
                self, None, ProgrammingError,
                {
                    u'msg': u"User is empty",
                    u'errno': ER_NO_USER
                })

        if self._private_key:
            self._authenticator = KEY_PAIR_AUTHENTICATOR

        if self._authenticator:
            self._authenticator = self._authenticator.upper()

        if self._authenticator != EXTERNAL_BROWSER_AUTHENTICATOR and \
                self._authenticator != OAUTH_AUTHENTICATOR and \
                self._authenticator != KEY_PAIR_AUTHENTICATOR:
            # authentication is done by the browser if the authenticator
            # is externalbrowser
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

        if self.insecure_mode:
            logger.info(
                u'THIS CONNECTION IS IN INSECURE MODE. IT '
                u'MEANS THE CERTIFICATE WILL BE VALIDATED BUT THE '
                u'CERTIFICATE REVOCATION STATUS WILL NOT BE '
                u'CHECKED.')
        elif self._protocol == u'https':
            if IS_OLD_PYTHON():
                msg = (u"ERROR: The ssl package installed with your Python "
                       u"- version {0} - does not have the security fix. "
                       u"Upgrade to Python 2.7.9/3.4.3 or higher.\n").format(
                    PYTHON_VERSION)
                raise InterfaceError(
                    msg=msg,
                    errno=ER_OLD_PYTHON)

    def cmd_query(self, sql, sequence_counter, request_id,
                  binding_params=None,
                  is_file_transfer=False, statement_params=None,
                  is_internal=False, _no_results=False,
                  _update_current_object=True):
        u"""
        Executes a query with a sequence counter.
        """
        logger.debug(u'_cmd_query')
        data = {
            u'sqlText': sql,
            u'asyncExec': _no_results,
            u'sequenceId': sequence_counter,
            u'querySubmissionTime': get_time_millis(),
        }
        if statement_params is not None:
            data[u'parameters'] = statement_params
        if is_internal:
            data[u'isInternal'] = is_internal
        if binding_params is not None:
            # binding parameters. This is for qmarks paramstyle.
            data[u'bindings'] = binding_params

        client = u'sfsql_file_transfer' if is_file_transfer else u'sfsql'

        if logger.getEffectiveLevel() <= logging.DEBUG:
            logger.debug(
                u'sql=[%s], sequence_id=[%s], is_file_transfer=[%s]',
                u' '.join(
                    line.strip() for line in
                    data[u'sqlText'].split(u'\n')),
                data[u'sequenceId'],
                is_file_transfer
            )

        url_parameters = {u'requestId': request_id}

        ret = self.rest.request(
            u'/queries/v1/query-request?' + urlencode(url_parameters),
            data, client=client, _no_results=_no_results,
            _include_retry_params=True)

        if ret is None:
            ret = {u'data': {}}
        if ret.get(u'data') is None:
            ret[u'data'] = {}
        if _update_current_object:
            data = ret['data']
            if u'finalDatabaseName' in data:
                self._database = data[u'finalDatabaseName']
            if u'finalSchemaName' in data:
                self._schema = data[u'finalSchemaName']
            if u'finalWarehouseName' in data:
                self._warehouse = data[u'finalWarehouseName']
            if u'finalRoleName' in data:
                self._role = data[u'finalRoleName']

        return ret

    def _set_current_objects(self):
        """
        Sets the current objects to the specified ones. This is mainly used
        when a session token is derived from an id token.
        """

        def cmd(sql, params, _update_current_object=False):
            processed_params = self._process_params_qmarks(params)
            sequence_counter = self._next_sequence_counter()
            request_id = uuid.uuid4()
            self.cmd_query(
                sql,
                sequence_counter,
                request_id,
                binding_params=processed_params,
                is_internal=True,
                _update_current_object=_update_current_object)

        if self._role:
            cmd(u"USE ROLE IDENTIFIER(?)", (self._role,))
        if self._warehouse:
            cmd(u"USE WAREHOUSE IDENTIFIER(?)", (self._warehouse,))
        if self._database:
            cmd(u"USE DATABASE IDENTIFIER(?)", (self._database,))
        if self._schema:
            cmd(u'USE SCHEMA IDENTIFIER(?)', (self._schema,))
        cmd(u"SELECT 1", (), _update_current_object=True)

    def _reauthenticate_by_webbrowser(self):
        auth_instance = AuthByWebBrowser(self.rest, self.application)
        self.__authenticate(auth_instance)
        self._set_current_objects()
        return {u'success': True}

    def __authenticate(self, auth_instance):
        auth_instance.authenticate(
            authenticator=self._authenticator,
            account=self.account,
            user=self.user,
            password=self._password,
        )
        auth = Auth(self.rest)
        self._session_parameters = auth.authenticate(
            auth_instance=auth_instance,
            account=self.account,
            user=self.user,
            database=self.database,
            schema=self.schema,
            warehouse=self.warehouse,
            role=self.role,
            passcode=self._passcode,
            passcode_in_password=self._passcode_in_password,
            mfa_callback=self._mfa_callback,
            password_callback=self._password_callback,
            session_parameters=self._session_parameters,
        )

    def _process_params_qmarks(self, params, cursor=None):
        if not params:
            return None
        processed_params = {}
        if not isinstance(params, (list, tuple)):
            errorvalue = {
                u'msg': u"Binding parameters must be a list: {0}".format(
                    params
                ),
                u'errno': ER_FAILED_PROCESSING_PYFORMAT
            }
            Error.errorhandler_wrapper(self, cursor,
                                       ProgrammingError,
                                       errorvalue)
            return None
        for idx, v in enumerate(params):
            if isinstance(v, tuple):
                if len(v) != 2:
                    Error.errorhandler_wrapper(
                        self, cursor,
                        ProgrammingError,
                        {
                            u'msg': u"Binding parameters must be a list "
                                    u"where one element is a single value or "
                                    u"a pair of Snowflake datatype and a value",
                            u'errno': ER_FAILED_PROCESSING_PYFORMAT,
                        }
                    )
                    return None
                processed_params[TO_UNICODE(idx + 1)] = {
                    'type': v[0],
                    'value': self.converter.to_snowflake_bindings(
                        v[0], v[1])}
            else:
                snowflake_type = self.converter.snowflake_type(
                    v)
                if snowflake_type is None:
                    Error.errorhandler_wrapper(
                        self, cursor,
                        ProgrammingError,
                        {
                            u'msg': u"Python data type [{0}] cannot be "
                                    u"automatically mapped to Snowflake data "
                                    u"type. Specify the snowflake data type "
                                    u"explicitly.".format(
                                v.__class__.__name__.lower()),
                            u'errno': ER_NOT_IMPLICITY_SNOWFLAKE_DATATYPE
                        }
                    )
                    return None
                if isinstance(v, list):
                    vv = [
                        self.converter.to_snowflake_bindings(
                            snowflake_type, v0) for v0 in v]
                else:
                    vv = self.converter.to_snowflake_bindings(
                        snowflake_type, v)
                processed_params[TO_UNICODE(idx + 1)] = {
                    'type': snowflake_type,
                    'value': vv}
        if logger.getEffectiveLevel() <= logging.DEBUG:
            for k, v in processed_params.items():
                logger.debug("idx: %s, type: %s", k, v.get('type'))
        return processed_params

    def _process_params(self, params, cursor=None):
        if params is None:
            return {}
        if isinstance(params, dict):
            return self.__process_params_dict(params)

        if not isinstance(params, (tuple, list)):
            params = [params, ]

        try:
            res = params
            res = map(self.converter.to_snowflake, res)
            res = map(self.converter.escape, res)
            res = map(self.converter.quote, res)
            ret = tuple(res)
            logger.debug(u'parameters: %s', ret)
            return ret
        except Exception as e:
            errorvalue = {
                u'msg': u"Failed processing pyformat-parameters; {0}".format(
                    e),
                u'errno': ER_FAILED_PROCESSING_PYFORMAT}
            Error.errorhandler_wrapper(self, cursor,
                                       ProgrammingError,
                                       errorvalue)

    def __process_params_dict(self, params, cursor=None):
        try:
            to_snowflake = self.converter.to_snowflake
            escape = self.converter.escape
            quote = self.converter.quote
            res = {}
            for k, v in params.items():
                c = v
                c = to_snowflake(c)
                c = escape(c)
                c = quote(c)
                res[k] = c
            logger.debug(u'parameters: %s', res)
            return res
        except Exception as e:
            errorvalue = {
                u'msg': u"Failed processing pyformat-parameters; {0}".format(
                    e),
                u'errno': ER_FAILED_PROCESSING_PYFORMAT}
            Error.errorhandler_wrapper(
                self, cursor, ProgrammingError, errorvalue)

    def _cancel_query(self, sql, sequence_counter, request_id):
        u"""
        Cancels the query by the sequence counter. The sequence counter
        is used to identify the query submitted by the client.
        """
        logger.debug(u'_cancel_query sql=[%s], sequence_id=[%s]', sql,
                     sequence_counter)
        url_parameters = {u'requestId': TO_UNICODE(uuid.uuid4())}

        return self.rest.request(
            u'/queries/v1/abort-request?' + urlencode(url_parameters), {
                u'sqlText': sql,
                u'requestId': TO_UNICODE(request_id),
            })

    def _next_sequence_counter(self):
        u"""Gets next sequence counter. Used internally.
        """
        with self._lock_sequence_counter:
            self.sequence_counter += 1
            logger.debug(u'sequence counter: %s', self.sequence_counter)
            return self.sequence_counter

    def _log_telemetry(self, telemetry_data):
        u"""
        Logs data to telemetry
        """
        if self._telemetry_enabled:
            self._telemetry.try_add_log_to_batch(telemetry_data)

    def set_telemetry_enabled(self, enabled):
        u"""
        Sets whether to use telemetry
        """
        self._telemetry_enabled = enabled

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
