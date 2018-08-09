#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import codecs
import copy
import json
import logging
import platform
import tempfile
import time
import uuid
from os import getenv, path, makedirs, mkdir, rmdir, removedirs, remove
from os.path import expanduser
from threading import Lock
from threading import Thread

from .compat import (TO_UNICODE, urlencode)
from .errorcode import (ER_FAILED_TO_CONNECT_TO_DB, ER_INVALID_VALUE)
from .errors import (Error,
                     DatabaseError,
                     ServiceUnavailableError,
                     ForbiddenError,
                     BadGatewayError)
from .network import (CONTENT_TYPE_APPLICATION_JSON,
                      ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
                      PYTHON_CONNECTOR_USER_AGENT,
                      OPERATING_SYSTEM,
                      PLATFORM,
                      PYTHON_VERSION,
                      IMPLEMENTATION, COMPILER,
                      ReauthenticationRequest)
from .sqlstate import (SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)
from .version import VERSION

logger = logging.getLogger(__name__)

# Cache directory
CACHE_ROOT_DIR = getenv('SF_TEMPORARY_CREDENTIAL_CACHE_DIR') or \
                 expanduser("~") or tempfile.gettempdir()
if platform.system() == 'Windows':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'AppData', 'Local', 'Snowflake',
                          'Caches')
elif platform.system() == 'Darwin':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, '.cache', 'snowflake')

if not path.exists(CACHE_DIR):
    try:
        makedirs(CACHE_DIR, mode=0o700)
    except Exception as ex:
        logger.warning('cannot create a cache directory: [%s], err=[%s]',
                       CACHE_DIR, ex)
        CACHE_DIR = None
logger.debug("cache directory: %s", CACHE_DIR)

# temporary credential cache
TEMPORARY_CREDENTIAL = {}

TEMPORARY_CREDENTIAL_LOCK = Lock()

# temporary credential cache file name
TEMPORARY_CREDENTIAL_FILE = "temporary_credential.json"
TEMPORARY_CREDENTIAL_FILE = path.join(
    CACHE_DIR, TEMPORARY_CREDENTIAL_FILE) if CACHE_DIR else ""

# temporary credential cache lock directory name
TEMPORARY_CREDENTIAL_FILE_LOCK = TEMPORARY_CREDENTIAL_FILE + ".lck"


class AuthByPlugin(object):
    """
    External Authenticator interface.
    """

    @property
    def assertion_content(self):
        raise NotImplementedError

    def update_body(self, body):
        raise NotImplementedError

    def authenticate(self, authenticator, account, user, password):
        raise NotImplementedError

    def handle_failure(self, ret):
        """ Handles a failure when connecting to Snowflake

        Args:
            ret: dictionary returned from Snowflake.
        """
        Error.errorhandler_wrapper(
            self._rest._connection, None, DatabaseError,
            {
                u'msg': (u"Failed to connect to DB: {host}:{port}, "
                         u"proxies={proxy_host}:{proxy_port}, "
                         u"proxy_user={proxy_user}, "
                         u"{message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    proxy_host=self._rest._proxy_host,
                    proxy_port=self._rest._proxy_port,
                    proxy_user=self._rest._proxy_user,
                    message=ret[u'message'],
                ),
                u'errno': int(ret.get(u'code', -1)),
                u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            })


class Auth(object):
    """
    Snowflake Authenticator
    """

    def __init__(self, rest):
        self._rest = rest

    @staticmethod
    def base_auth_data(user, account, application,
                       internal_application_name,
                       internal_application_version):
        return {
            u'data': {
                u"CLIENT_APP_ID": internal_application_name,
                u"CLIENT_APP_VERSION": internal_application_version,
                u"SVN_REVISION": VERSION[3],
                u"ACCOUNT_NAME": account,
                u"LOGIN_NAME": user,
                u"CLIENT_ENVIRONMENT": {
                    u"APPLICATION": application,
                    u"OS": OPERATING_SYSTEM,
                    u"OS_VERSION": PLATFORM,
                    u"PYTHON_VERSION": PYTHON_VERSION,
                    u"PYTHON_RUNTIME": IMPLEMENTATION,
                    u"PYTHON_COMPILER": COMPILER,
                }
            },
        }

    def authenticate(self, auth_instance, account, user,
                     database=None, schema=None,
                     warehouse=None, role=None, passcode=None,
                     passcode_in_password=False,
                     mfa_callback=None, password_callback=None,
                     session_parameters=None, timeout=120):
        logger.debug(u'authenticate')

        if session_parameters is None:
            session_parameters = {}

        request_id = TO_UNICODE(uuid.uuid4())
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        url = u"/session/v1/login-request"
        body_template = Auth.base_auth_data(
            user, account, self._rest._connection.application,
            self._rest._connection._internal_application_name,
            self._rest._connection._internal_application_version)

        body = copy.deepcopy(body_template)
        # updating request body
        logger.debug(u'assertion content: %s',
                     auth_instance.assertion_content)
        auth_instance.update_body(body)

        logger.debug(
            u'account=%s, user=%s, database=%s, schema=%s, '
            u'warehouse=%s, role=%s, request_id=%s',
            account,
            user,
            database,
            schema,
            warehouse,
            role,
            request_id,
        )
        url_parameters = {u'request_id': request_id}
        if database is not None:
            url_parameters[u'databaseName'] = database
        if schema is not None:
            url_parameters[u'schemaName'] = schema
        if warehouse is not None:
            url_parameters[u'warehouse'] = warehouse
        if role is not None:
            url_parameters[u'roleName'] = role

        url = url + u'?' + urlencode(url_parameters)

        # first auth request
        if passcode_in_password:
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'passcode'
        elif passcode:
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'passcode'
            body[u'data'][u'PASSCODE'] = passcode

        if session_parameters:
            body[u'data'][u'SESSION_PARAMETERS'] = session_parameters

        logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body[u'data'].items() if k != u'PASSWORD'})

        try:
            ret = self._rest._post_request(
                url, headers, json.dumps(body),
                timeout=self._rest._connection.login_timeout,
                socket_timeout=self._rest._connection.login_timeout)
        except ForbiddenError as err:
            # HTTP 403
            raise err.__class__(
                msg=(u"Failed to connect to DB. "
                     u"Verify the account name is correct: {host}:{port}, "
                     u"proxies={proxy_host}:{proxy_port}, "
                     u"proxy_user={proxy_user}. {message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    proxy_host=self._rest._proxy_host,
                    proxy_port=self._rest._proxy_port,
                    proxy_user=self._rest._proxy_user,
                    message=TO_UNICODE(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)
        except (ServiceUnavailableError, BadGatewayError) as err:
            # HTTP 502/504
            raise err.__class__(
                msg=(u"Failed to connect to DB. "
                     u"Service is unavailable: {host}:{port}, "
                     u"proxies={proxy_host}:{proxy_port}, "
                     u"proxy_user={proxy_user}. {message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    proxy_host=self._rest._proxy_host,
                    proxy_port=self._rest._proxy_port,
                    proxy_user=self._rest._proxy_user,
                    message=TO_UNICODE(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)

        # waiting for MFA authentication
        if ret[u'data'].get(u'nextAction') == u'EXT_AUTHN_DUO_ALL':
            body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'push'
            self.ret = {u'message': "Timeout", u'data': {}}

            def post_request_wrapper(self, url, headers, body):
                # get the MFA response
                self.ret = self._rest._post_request(
                    url, headers, body,
                    timeout=self._rest._connection.login_timeout)

            # send new request to wait until MFA is approved
            t = Thread(target=post_request_wrapper,
                       args=[self, url, headers, json.dumps(body)])
            t.daemon = True
            t.start()
            if callable(mfa_callback):
                c = mfa_callback()
                while not self.ret or self.ret.get(u'message') == u'Timeout':
                    next(c)
            else:
                t.join(timeout=timeout)

            ret = self.ret
            if ret and ret[u'data'].get(u'nextAction') == u'EXT_AUTHN_SUCCESS':
                body = copy.deepcopy(body_template)
                body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
                # final request to get tokens
                ret = self._rest._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._rest._connection.login_timeout,
                    socket_timeout=self._rest._connection.login_timeout)
            elif not ret or not ret[u'data'].get(u'token'):
                # not token is returned.
                Error.errorhandler_wrapper(
                    self._rest._connection, None, DatabaseError,
                    {
                        u'msg': (u"Failed to connect to DB. MFA "
                                 u"authentication failed: {"
                                 u"host}:{port}, "
                                 u"proxies={proxy_host}:{proxy_port}, "
                                 u"proxy_user={proxy_user}, "
                                 u"{message}").format(
                            host=self._rest._host,
                            port=self._rest._port,
                            proxy_host=self._rest._proxy_host,
                            proxy_port=self._rest._proxy_port,
                            proxy_user=self._rest._proxy_user,
                            message=ret[u'message'],
                        ),
                        u'errno': ER_FAILED_TO_CONNECT_TO_DB,
                        u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    })
                return session_parameters  # required for unit test

        elif ret[u'data'].get(u'nextAction') == u'PWD_CHANGE':
            if callable(password_callback):
                body = copy.deepcopy(body_template)
                body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
                body[u'data'][u"LOGIN_NAME"] = user
                body[u'data'][u"PASSWORD"] = \
                    auth_instance.password if hasattr(
                        auth_instance, 'password') else None
                body[u'data'][u'CHOSEN_NEW_PASSWORD'] = password_callback()
                # New Password input
                ret = self._rest._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._rest._connection.login_timeout,
                    socket_timeout=self._rest._connection.login_timeout)

        logger.debug(u'completed authentication')
        if not ret[u'success']:
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
                {
                    u'msg': (u"Failed to connect to DB: {host}:{port}, "
                             u"proxies={proxy_host}:{proxy_port}, "
                             u"proxy_user={proxy_user}, "
                             u"{message}").format(
                        host=self._rest._host,
                        port=self._rest._port,
                        proxy_host=self._rest._proxy_host,
                        proxy_port=self._rest._proxy_port,
                        proxy_user=self._rest._proxy_user,
                        message=ret[u'message'],
                    ),
                    u'errno': ER_FAILED_TO_CONNECT_TO_DB,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })
        else:
            logger.debug(u'token = %s',
                         '******' if ret[u'data'][u'token'] is not None else
                         'NULL')
            logger.debug(u'master_token = %s',
                         '******' if ret[u'data'][
                                         u'masterToken'] is not None else
                         'NULL')
            logger.debug(u'id_token = %s',
                         '******' if ret[u'data'].get(
                             u'id_token') is not None else
                         'NULL')
            self._rest.update_tokens(
                ret[u'data'][u'token'], ret[u'data'][u'masterToken'],
                id_token=ret[u'data'].get(u'idToken'),
                id_token_password=ret[u'data'].get(u'idTokenPassword'))
            write_temporary_credential_file(
                account, user, self._rest.id_token)
            if u'sessionId' in ret[u'data']:
                self._rest._connection._session_id = ret[u'data'][u'sessionId']
            if u'sessionInfo' in ret[u'data']:
                session_info = ret[u'data'][u'sessionInfo']
                self._validate_default_database(session_info)
                self._validate_default_schema(session_info)
                self._validate_default_role(session_info)
                self._validate_default_warehouse(session_info)
            if u'parameters' in ret[u'data']:
                if u'CLIENT_TELEMETRY_ENABLED' in ret[u'data']:
                    self._rest._connection.set_telemetry_enabled(ret[u'data'])
                with self._rest._connection._lock_converter:
                    self._rest._connection.converter.set_parameters(
                        ret[u'data'][u'parameters'])
                for kv in ret[u'data'][u'parameters']:
                    session_parameters[kv['name']] = kv['value']
        return session_parameters

    def _validate_default_database(self, session_info):
        default_value = self._rest._connection.database
        session_info_value = session_info.get(u'databaseName')
        self._rest._connection._database = session_info_value
        self._validate_default_parameter(
            'database', default_value, session_info_value)

    def _validate_default_schema(self, session_info):
        default_value = self._rest._connection.schema
        session_info_value = session_info.get(u'schemaName')
        self._rest._connection._schema = session_info_value
        self._validate_default_parameter(
            'schema', default_value, session_info_value)

    def _validate_default_role(self, session_info):
        default_value = self._rest._connection.role
        session_info_value = session_info.get(u'roleName')
        self._rest._connection._role = session_info_value
        self._validate_default_parameter(
            'role', default_value, session_info_value)

    def _validate_default_warehouse(self, session_info):
        default_value = self._rest._connection.warehouse
        session_info_value = session_info.get(u'warehouseName')
        self._rest._connection._warehouse = session_info_value
        self._validate_default_parameter(
            'warehouse', default_value, session_info_value)

    def _validate_default_parameter(
            self, name, default_value, session_info_value):
        if self._rest._connection.validate_default_parameters and \
                default_value is not None and \
                session_info_value is None:
            # validate default parameter
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
                {
                    u'msg': u'Invalid {0} name: {1}'.format(
                        name, default_value),
                    u'errno': ER_INVALID_VALUE,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,

                })

    def read_temporary_credential(self, account, user, session_parameters):
        if session_parameters.get('CLIENT_STORE_TEMPORARY_CREDENTIAL'):
            read_temporary_credential_file()
            id_token = TEMPORARY_CREDENTIAL.get(
                account.upper(), {}).get(user.upper())
            if id_token:
                self._rest.id_token = id_token
            if self._rest.id_token:
                try:
                    self._rest._id_token_session()
                    return True
                except ReauthenticationRequest as ex:
                    # catch token expiration error
                    logger.debug(
                        "ID token expired. Reauthenticating...: %s", ex)
        return False


def write_temporary_credential_file(account, user, id_token):
    if not CACHE_DIR or not id_token:
        # no cache is enabled or no id_token is given
        return
    global TEMPORARY_CREDENTIAL
    global TEMPORARY_CREDENTIAL_LOCK
    global TEMPORARY_CREDENTIAL_FILE
    with TEMPORARY_CREDENTIAL_LOCK:
        # update the cache
        account_data = TEMPORARY_CREDENTIAL.get(account.upper(), {})
        account_data[user.upper()] = id_token
        TEMPORARY_CREDENTIAL[account.upper()] = account_data
        for _ in range(10):
            if lock_temporary_credential_file():
                break
            time.sleep(1)
        else:
            logger.warning("The lock file still persists. Will ignore and "
                           "write the temporary credential file: %s",
                           TEMPORARY_CREDENTIAL_FILE)
        try:
            with codecs.open(TEMPORARY_CREDENTIAL_FILE, 'w',
                             encoding='utf-8', errors='ignore') as f:
                json.dump(TEMPORARY_CREDENTIAL, f)
        except Exception as ex:
            logger.debug("Failed to write a credential file: "
                         "file=[%s], err=[%s]", TEMPORARY_CREDENTIAL_FILE, ex)
        finally:
            unlock_temporary_credential_file()


def read_temporary_credential_file():
    """
    Read temporary credential file
    """
    if not CACHE_DIR:
        # no cache is enabled
        return

    global TEMPORARY_CREDENTIAL
    global TEMPORARY_CREDENTIAL_LOCK
    global TEMPORARY_CREDENTIAL_FILE
    with TEMPORARY_CREDENTIAL_LOCK:
        for _ in range(10):
            if lock_temporary_credential_file():
                break
            time.sleep(1)
        else:
            logger.warning("The lock file still persists. Will ignore and "
                           "write the temporary credential file: %s",
                           TEMPORARY_CREDENTIAL_FILE)
        try:
            with codecs.open(
                    TEMPORARY_CREDENTIAL_FILE, 'r',
                    encoding='utf-8', errors='ignore') as f:
                TEMPORARY_CREDENTIAL = json.load(f)
            return TEMPORARY_CREDENTIAL
        except Exception as ex:
            logger.debug("Failed to read a credential file. The file may not"
                         "exists: file=[%s], err=[%s]",
                         TEMPORARY_CREDENTIAL_FILE, ex)
        finally:
            unlock_temporary_credential_file()
    return None


def lock_temporary_credential_file():
    global TEMPORARY_CREDENTIAL_FILE_LOCK
    try:
        mkdir(TEMPORARY_CREDENTIAL_FILE_LOCK)
        return True
    except OSError:
        logger.info("Temporary cache file lock already exists. Other "
                    "process may be updating the temporary ")
        return False


def unlock_temporary_credential_file():
    global TEMPORARY_CREDENTIAL_FILE_LOCK
    try:
        rmdir(TEMPORARY_CREDENTIAL_FILE_LOCK)
        return True
    except OSError:
        logger.debug("Temporary cache file lock no longer exists.")
        return False


def delete_temporary_credential_file():
    """
    Delete temporary credential file and its lock file
    """
    global TEMPORARY_CREDENTIAL_FILE
    try:
        remove(TEMPORARY_CREDENTIAL_FILE)
    except Exception as ex:
        logger.debug("Failed to delete a credential file: "
                     "file=[%s], err=[%s]", TEMPORARY_CREDENTIAL_FILE, ex)
    try:
        removedirs(TEMPORARY_CREDENTIAL_FILE_LOCK)
    except Exception as ex:
        logger.debug("Failed to delete credential lock file: err=[%s]", ex)
