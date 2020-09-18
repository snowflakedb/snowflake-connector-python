#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import codecs
import copy
import json
import logging
import tempfile
import time
import uuid
from datetime import datetime
from os import getenv, makedirs, mkdir, path, remove, removedirs, rmdir
from os.path import expanduser
from threading import Lock, Thread

from .auth_keypair import AuthByKeyPair
from .compat import IS_LINUX, IS_MACOS, IS_WINDOWS, urlencode
from .constants import (
    HTTP_HEADER_ACCEPT,
    HTTP_HEADER_CONTENT_TYPE,
    HTTP_HEADER_SERVICE_NAME,
    HTTP_HEADER_USER_AGENT,
    PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL,
)
from .description import COMPILER, IMPLEMENTATION, OPERATING_SYSTEM, PLATFORM, PYTHON_VERSION
from .errorcode import ER_FAILED_TO_CONNECT_TO_DB
from .errors import BadGatewayError, DatabaseError, Error, ForbiddenError, ProgrammingError, ServiceUnavailableError
from .network import (
    ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
    CONTENT_TYPE_APPLICATION_JSON,
    ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE,
    PYTHON_CONNECTOR_USER_AGENT,
    ReauthenticationRequest,
)
from .sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
from .version import VERSION

logger = logging.getLogger(__name__)

try:
    import keyring
except ImportError as ie:
    keyring = None
    logger.debug('Failed to import keyring module. err=[%s]', ie)

# Cache directory
CACHE_ROOT_DIR = getenv('SF_TEMPORARY_CREDENTIAL_CACHE_DIR') or \
                 expanduser("~") or tempfile.gettempdir()
if IS_WINDOWS:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'AppData', 'Local', 'Snowflake',
                          'Caches')
elif IS_MACOS:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, '.cache', 'snowflake')

if not path.exists(CACHE_DIR):
    try:
        makedirs(CACHE_DIR, mode=0o700)
    except Exception as ex:
        logger.debug('cannot create a cache directory: [%s], err=[%s]',
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

# keyring
KEYRING_SERVICE_NAME = "net.snowflake.temporary_token"
KEYRING_USER = "temp_token"
KEYRING_DRIVER_NAME = "SNOWFLAKE-PYTHON-DRIVER"


class Auth(object):
    """Snowflake Authenticator."""

    def __init__(self, rest):
        self._rest = rest

    @staticmethod
    def base_auth_data(user, account, application,
                       internal_application_name,
                       internal_application_version,
                       ocsp_mode, login_timeout,
                       network_timeout=None,
                       store_temp_cred=None):
        return {
            'data': {
                "CLIENT_APP_ID": internal_application_name,
                "CLIENT_APP_VERSION": internal_application_version,
                "SVN_REVISION": VERSION[3],
                "ACCOUNT_NAME": account,
                "LOGIN_NAME": user,
                "CLIENT_ENVIRONMENT": {
                    "APPLICATION": application,
                    "OS": OPERATING_SYSTEM,
                    "OS_VERSION": PLATFORM,
                    "PYTHON_VERSION": PYTHON_VERSION,
                    "PYTHON_RUNTIME": IMPLEMENTATION,
                    "PYTHON_COMPILER": COMPILER,
                    "OCSP_MODE": ocsp_mode.name,
                    "TRACING": logger.getEffectiveLevel(),
                    "LOGIN_TIMEOUT": login_timeout,
                    "NETWORK_TIMEOUT": network_timeout,
                    "CLIENT_STORE_TEMPORARY_CREDENTIAL": store_temp_cred,
                }
            },
        }

    def authenticate(self, auth_instance, account, user,
                     database=None, schema=None,
                     warehouse=None, role=None, passcode=None,
                     passcode_in_password=False,
                     mfa_callback=None, password_callback=None,
                     session_parameters=None, timeout=120):
        logger.debug('authenticate')

        if session_parameters is None:
            session_parameters = {}

        request_id = str(uuid.uuid4())
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if HTTP_HEADER_SERVICE_NAME in session_parameters:
            headers[HTTP_HEADER_SERVICE_NAME] = \
                session_parameters[HTTP_HEADER_SERVICE_NAME]
        url = "/session/v1/login-request"
        if session_parameters is not None \
                and PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL in session_parameters:
            store_temp_cred = session_parameters[
                PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL]
        else:
            store_temp_cred = None

        body_template = Auth.base_auth_data(
            user, account, self._rest._connection.application,
            self._rest._connection._internal_application_name,
            self._rest._connection._internal_application_version,
            self._rest._connection._ocsp_mode(),
            self._rest._connection._login_timeout,
            self._rest._connection._network_timeout,
            store_temp_cred,
        )

        body = copy.deepcopy(body_template)
        # updating request body
        logger.debug('assertion content: %s',
                     auth_instance.assertion_content)
        auth_instance.update_body(body)

        logger.debug(
            'account=%s, user=%s, database=%s, schema=%s, '
            'warehouse=%s, role=%s, request_id=%s',
            account,
            user,
            database,
            schema,
            warehouse,
            role,
            request_id,
        )
        url_parameters = {'request_id': request_id}
        if database is not None:
            url_parameters['databaseName'] = database
        if schema is not None:
            url_parameters['schemaName'] = schema
        if warehouse is not None:
            url_parameters['warehouse'] = warehouse
        if role is not None:
            url_parameters['roleName'] = role

        url = url + '?' + urlencode(url_parameters)

        # first auth request
        if passcode_in_password:
            body['data']['EXT_AUTHN_DUO_METHOD'] = 'passcode'
        elif passcode:
            body['data']['EXT_AUTHN_DUO_METHOD'] = 'passcode'
            body['data']['PASSCODE'] = passcode

        if session_parameters:
            body['data']['SESSION_PARAMETERS'] = session_parameters

        logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body['data'].items() if k != 'PASSWORD'})

        try:
            ret = self._rest._post_request(
                url, headers, json.dumps(body),
                timeout=self._rest._connection.login_timeout,
                socket_timeout=self._rest._connection.login_timeout)
        except ForbiddenError as err:
            # HTTP 403
            raise err.__class__(
                msg=("Failed to connect to DB. "
                     "Verify the account name is correct: {host}:{port}. "
                     "{message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    message=str(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)
        except (ServiceUnavailableError, BadGatewayError) as err:
            # HTTP 502/504
            raise err.__class__(
                msg=("Failed to connect to DB. "
                     "Service is unavailable: {host}:{port}. "
                     "{message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    message=str(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)

        # waiting for MFA authentication
        if ret['data'].get('nextAction') == 'EXT_AUTHN_DUO_ALL':
            body['inFlightCtx'] = ret['data']['inFlightCtx']
            body['data']['EXT_AUTHN_DUO_METHOD'] = 'push'
            self.ret = {'message': "Timeout", 'data': {}}

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
                while not self.ret or self.ret.get('message') == 'Timeout':
                    next(c)
            else:
                t.join(timeout=timeout)

            ret = self.ret
            if ret and ret['data'].get('nextAction') == 'EXT_AUTHN_SUCCESS':
                body = copy.deepcopy(body_template)
                body['inFlightCtx'] = ret['data']['inFlightCtx']
                # final request to get tokens
                ret = self._rest._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._rest._connection.login_timeout,
                    socket_timeout=self._rest._connection.login_timeout)
            elif not ret or not ret['data'].get('token'):
                # not token is returned.
                Error.errorhandler_wrapper(
                    self._rest._connection, None, DatabaseError,
                    {
                        'msg': ("Failed to connect to DB. MFA "
                                 "authentication failed: {"
                                 "host}:{port}. {message}").format(
                            host=self._rest._host,
                            port=self._rest._port,
                            message=ret['message'],
                        ),
                        'errno': ER_FAILED_TO_CONNECT_TO_DB,
                        'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                    })
                return session_parameters  # required for unit test

        elif ret['data'].get('nextAction') == 'PWD_CHANGE':
            if callable(password_callback):
                body = copy.deepcopy(body_template)
                body['inFlightCtx'] = ret['data']['inFlightCtx']
                body['data']["LOGIN_NAME"] = user
                body['data']["PASSWORD"] = \
                    auth_instance.password if hasattr(
                        auth_instance, 'password') else None
                body['data']['CHOSEN_NEW_PASSWORD'] = password_callback()
                # New Password input
                ret = self._rest._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._rest._connection.login_timeout,
                    socket_timeout=self._rest._connection.login_timeout)

        logger.debug('completed authentication')
        if not ret['success']:
            errno = ret.get('code', ER_FAILED_TO_CONNECT_TO_DB)
            if errno == ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE:
                # clear stored id_token if failed to connect because of id_token
                # raise an exception for reauthing without id_token
                self._rest.id_token = None
                delete_temporary_credential(self._rest._host, user, True)
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=ret['message'],
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED))

            if type(auth_instance) is AuthByKeyPair:
                logger.debug(
                    "JWT Token authentication failed. "
                    "Token expires at: %s. "
                    "Current Time: %s",
                    str(auth_instance._jwt_token_exp),
                    str(datetime.utcnow())
                )
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
                {
                    'msg': ("Failed to connect to DB: {host}:{port}. "
                             "{message}").format(
                        host=self._rest._host,
                        port=self._rest._port,
                        message=ret['message'],
                    ),
                    'errno': ER_FAILED_TO_CONNECT_TO_DB,
                    'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })
        else:
            logger.debug('token = %s',
                         '******' if ret['data']['token'] is not None else
                         'NULL')
            logger.debug('master_token = %s',
                         '******' if ret['data'][
                                         'masterToken'] is not None else
                         'NULL')
            logger.debug('id_token = %s',
                         '******' if ret['data'].get(
                             'id_token') is not None else
                         'NULL')
            self._rest.update_tokens(
                ret['data']['token'], ret['data']['masterToken'],
                master_validity_in_seconds=ret['data'].get(
                    'masterValidityInSeconds'),
                id_token=ret['data'].get('idToken')
            )
            if self._rest._connection.consent_cache_id_token:
                write_temporary_credential(
                    self._rest._host, account, user, self._rest.id_token,
                    session_parameters.get(
                        PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL))
            if 'sessionId' in ret['data']:
                self._rest._connection._session_id = ret['data']['sessionId']
            if 'sessionInfo' in ret['data']:
                session_info = ret['data']['sessionInfo']
                self._rest._connection._database = session_info.get('databaseName')
                self._rest._connection._schema = session_info.get('schemaName')
                self._rest._connection._warehouse = session_info.get('warehouseName')
                self._rest._connection._role = session_info.get('roleName')
            self._rest._connection._set_parameters(ret, session_parameters)

        return session_parameters

    def read_temporary_credential(self, host, account, user, session_parameters):
        if session_parameters.get(PARAMETER_CLIENT_STORE_TEMPORARY_CREDENTIAL, False):
            id_token = None
            if IS_MACOS or IS_WINDOWS:
                if not keyring:
                    # we will leave the exception for write_temporary_credential function to raise
                    return
                new_target = convert_target(host, user)
                try:
                    id_token = keyring.get_password(new_target, user.upper())
                except keyring.errors.KeyringError as ke:
                    logger.debug("Could not retrieve id_token from secure storage : {}".format(str(ke)))
            elif IS_LINUX:
                read_temporary_credential_file()
                id_token = TEMPORARY_CREDENTIAL.get(
                    account.upper(), {}).get(user.upper())
            else:
                logger.debug("connection parameter enable_sso_temporary_credential not set or OS not support")
            self._rest.id_token = id_token
        return


def write_temporary_credential(host, account, user, id_token, store_temporary_credential=False):
    if not id_token:
        logger.debug("no ID token is given when try to store temporary credential")
        return
    if IS_MACOS or IS_WINDOWS:
        if not keyring:
            logger.debug("Dependency 'keyring' is not installed, cannot cache id token. You might experience "
                         "multiple authentication pop ups while using ExternalBrowser Authenticator. To avoid "
                         "this please install keyring module using the following command : pip install "
                         "snowflake-connector-python[secure-local-storage]")
            return
        new_target = convert_target(host, user)
        try:
            keyring.set_password(new_target, user.upper(), id_token)
        except keyring.errors.KeyringError as ke:
            logger.debug("Could not store id_token to keyring, %s", str(ke))
    elif IS_LINUX and store_temporary_credential:
        write_temporary_credential_file(host, account, user, id_token)
    else:
        logger.debug("connection parameter client_store_temporary_credential not set or OS not support")


def write_temporary_credential_file(host, account, user, id_token):
    """Writes temporary credential file when OS is Linux."""
    if not CACHE_DIR:
        # no cache is enabled
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
            logger.debug("The lock file still persists. Will ignore and "
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
    """Reads temporary credential file when OS is Linux."""
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
            logger.debug("The lock file still persists. Will ignore and "
                           "write the temporary credential file: %s",
                           TEMPORARY_CREDENTIAL_FILE)
        try:
            with codecs.open(TEMPORARY_CREDENTIAL_FILE, 'r',
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
        logger.debug("Temporary cache file lock already exists. Other "
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


def delete_temporary_credential(host, user, store_temporary_credential=False):
    if (IS_MACOS or IS_WINDOWS) and keyring:
        new_target = convert_target(host, user)
        try:
            keyring.delete_password(new_target, user.upper())
        except Exception as ex:
            logger.debug("Failed to delete credential in the keyring: err=[%s]",
                         ex)
    elif IS_LINUX and store_temporary_credential:
        delete_temporary_credential_file()


def delete_temporary_credential_file():
    """Deletes temporary credential file and its lock file."""
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


def convert_target(host, user):
    return "{host}:{user}:{driver}".format(
            host=host.upper(), user=user.upper(), driver=KEYRING_DRIVER_NAME)
