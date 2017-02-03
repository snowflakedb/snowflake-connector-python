#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import copy
import gzip
import json
import logging
import platform
import sys
import time
import uuid
from io import StringIO, BytesIO
from logging import getLogger
from threading import Thread

import OpenSSL
from botocore.vendored import requests
from botocore.vendored.requests.adapters import (HTTPAdapter, DEFAULT_POOLSIZE)
from botocore.vendored.requests.auth import AuthBase
from botocore.vendored.requests.exceptions import (ConnectionError, SSLError)
from botocore.vendored.requests.packages.urllib3.exceptions import (
    ProtocolError)

from . import ssl_wrap_socket
from .compat import (
    BAD_REQUEST, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT,
    FORBIDDEN, BAD_GATEWAY,
    UNAUTHORIZED, INTERNAL_SERVER_ERROR, OK, BadStatusLine)
from .compat import (Queue, EmptyQueue)
from .compat import (TO_UNICODE, urlencode)
from .compat import proxy_bypass
from .errorcode import (ER_FAILED_TO_CONNECT_TO_DB, ER_CONNECTION_IS_CLOSED,
                        ER_FAILED_TO_REQUEST, ER_FAILED_TO_RENEW_SESSION,
                        ER_FAILED_TO_SERVER)
from .errors import (Error, OperationalError, DatabaseError, ProgrammingError,
                     GatewayTimeoutError, ServiceUnavailableError,
                     InterfaceError, InternalServerError, ForbiddenError,
                     BadGatewayError, BadRequest)
from .gzip_decoder import (decompress_raw_data)
from .sqlstate import (SQLSTATE_CONNECTION_NOT_EXISTS,
                       SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                       SQLSTATE_CONNECTION_REJECTED)
from .util_text import split_rows_from_stream
from .version import VERSION

"""
Monkey patch for PyOpenSSL Socket wrapper
"""
ssl_wrap_socket.inject_into_urllib3()

import errno

REQUESTS_RETRY = 5  # requests retry
QUERY_IN_PROGRESS_CODE = u'333333'  # GS code: the query is in progress
QUERY_IN_PROGRESS_ASYNC_CODE = u'333334'  # GS code: the query is detached
SESSION_EXPIRED_GS_CODE = u'390112'  # GS code: session expired. need to renew
DEFAULT_CONNECT_TIMEOUT = 1 * 60  # 60 seconds
DEFAULT_REQUEST_TIMEOUT = 2 * 60  # 120 seconds

CONTENT_TYPE_APPLICATION_JSON = u'application/json'
ACCEPT_TYPE_APPLICATION_SNOWFLAKE = u'application/snowflake'

REQUEST_TYPE_RENEW = u'RENEW'
REQUEST_TYPE_CLONE = u'CLONE'
REQUEST_TYPE_ISSUE = u'ISSUE'

HEADER_AUTHORIZATION_KEY = u"Authorization"
HEADER_SNOWFLAKE_TOKEN = u'Snowflake Token="{token}"'

MAX_CONNECTION_POOL = DEFAULT_POOLSIZE  # max connetion pool size in urllib3

SNOWFLAKE_CONNECTOR_VERSION = u'.'.join(TO_UNICODE(v) for v in VERSION[0:3])
PYTHON_VERSION = u'.'.join(TO_UNICODE(v) for v in sys.version_info[:3])
PLATFORM = platform.platform()
IMPLEMENTATION = platform.python_implementation()
COMPILER = platform.python_compiler()

CLIENT_NAME = u"PythonConnector"
CLIENT_VERSION = u'.'.join([TO_UNICODE(v) for v in VERSION[:3]])
PYTHON_CONNECTOR_USER_AGENT = \
    u'{name}/{version}/{python_version}/{platform}'.format(
        name=CLIENT_NAME,
        version=SNOWFLAKE_CONNECTOR_VERSION,
        python_version=PYTHON_VERSION,
        platform=PLATFORM)

DEFAULT_AUTHENTICATOR = u'SNOWFLAKE'  # default authenticator name
NO_TOKEN = u'no-token'

STATUS_TO_EXCEPTION = {
    INTERNAL_SERVER_ERROR: InternalServerError,
    FORBIDDEN: ForbiddenError,
    SERVICE_UNAVAILABLE: ServiceUnavailableError,
    GATEWAY_TIMEOUT: GatewayTimeoutError,
    BAD_REQUEST: BadRequest,
    BAD_GATEWAY: BadGatewayError,
}


class RequestRetry(Exception):
    pass


class SnowflakeAuth(AuthBase):
    """Attaches HTTP Authorization header for Snowflake"""

    def __init__(self, token):
        # setup any auth-related data here
        self.token = token

    def __call__(self, r):
        # modify and return the request
        if HEADER_AUTHORIZATION_KEY in r.headers:
            del r.headers[HEADER_AUTHORIZATION_KEY]
        if self.token != NO_TOKEN:
            r.headers[
                HEADER_AUTHORIZATION_KEY] = HEADER_SNOWFLAKE_TOKEN.format(
                token=self.token)
        return r


class SnowflakeRestful(object):
    u"""
    Snowflake Restful class
    """

    def __init__(self, host=u'127.0.0.1', port=8080,
                 proxy_host=None,
                 proxy_port=None,
                 proxy_user=None,
                 proxy_password=None,
                 protocol=u'http',
                 connect_timeout=DEFAULT_CONNECT_TIMEOUT,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 injectClientPause=0,
                 max_connection_pool=MAX_CONNECTION_POOL,
                 connection=None):
        self._host = host
        self._port = port
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_password = proxy_password
        self._protocol = protocol
        self._connect_timeout = connect_timeout or DEFAULT_CONNECT_TIMEOUT
        self._request_timeout = request_timeout or DEFAULT_REQUEST_TIMEOUT
        self._session = None
        self._injectClientPause = injectClientPause
        self._max_connection_pool = max_connection_pool
        self._connection = connection
        self.logger = getLogger(__name__)
        ssl_wrap_socket.FEATURE_INSECURE_MODE = \
            self._connection and self._connection._insecure_mode
        ssl_wrap_socket.FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = \
            self._connection and self._connection._ocsp_response_cache_filename

        # This is to address the issue where requests hangs
        _ = 'dummy'.encode('idna').decode('utf-8')
        proxy_bypass('www.snowflake.net:443')

    @property
    def token(self):
        return self._token if hasattr(self, u'_token') else None

    @property
    def master_token(self):
        return self._master_token if hasattr(self, u'_master_token') else None

    @staticmethod
    def set_proxies(proxy_host,
                    proxy_port,
                    proxy_user=None,
                    proxy_password=None):
        proxies = None
        if proxy_host and proxy_port:
            if proxy_user or proxy_password:
                proxy_auth = u'{proxy_user}:{proxy_password}@'.format(
                    proxy_user=proxy_user if proxy_user is not None else '',
                    proxy_password=proxy_password if proxy_password is not
                                                     None else ''
                )
            else:
                proxy_auth = u''
            proxies = {
                u'http': u'http://{proxy_auth}{proxy_host}:{proxy_port}'.format(
                    proxy_host=proxy_host,
                    proxy_port=TO_UNICODE(proxy_port),
                    proxy_auth=proxy_auth,
                ),
                u'https': u'http://{proxy_auth}{proxy_host}:{proxy_port}'.format(
                    proxy_host=proxy_host,
                    proxy_port=TO_UNICODE(proxy_port),
                    proxy_auth=proxy_auth,
                ),
            }
        return proxies

    def close(self):
        if hasattr(self, u'_token'):
            del self._token
        if hasattr(self, u'_master_token'):
            del self._master_token
        self._session = None

    def authenticate(self, account, user, password, master_token=None,
                     token=None, database=None, schema=None,
                     warehouse=None, role=None, passcode=None,
                     passcode_in_password=False, saml_response=None,
                     mfa_callback=None, password_callback=None,
                     session_parameters=None):
        self.logger.info(u'authenticate')

        if token and master_token:
            self._token = token
            self._master_token = token
            self.logger.debug(u'token is given. no authentication was done')
            return

        application = self._connection.application if \
            self._connection else CLIENT_NAME
        internal_application_name = \
            self._connection._internal_application_name if \
                self._connection else CLIENT_NAME
        internal_application_version = \
            self._connection._internal_application_version if \
                self._connection else CLIENT_VERSION
        request_id = TO_UNICODE(uuid.uuid4())
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": ACCEPT_TYPE_APPLICATION_SNOWFLAKE,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        url = u"/session/v1/login-request"
        body_template = {
            u'data': {
                u"CLIENT_APP_ID": internal_application_name,
                u"CLIENT_APP_VERSION": internal_application_version,
                u"SVN_REVISION": VERSION[3],
                u"ACCOUNT_NAME": account,
                u"CLIENT_ENVIRONMENT": {
                    u"APPLICATION": application,
                    u"OS_VERSION": PLATFORM,
                    u"PYTHON_VERSION": PYTHON_VERSION,
                    u"PYTHON_RUNTIME": IMPLEMENTATION,
                    u"PYTHON_COMPILER": COMPILER,
                }
            },
        }

        body = copy.deepcopy(body_template)
        self.logger.info(u'saml: %s', saml_response is not None)
        if saml_response:
            body[u'data'][u'RAW_SAML_RESPONSE'] = saml_response
        else:
            body[u'data'][u"LOGIN_NAME"] = user
            body[u'data'][u"PASSWORD"] = password

        self.logger.debug(
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
        url_parameters = {}
        url_parameters[u'request_id'] = request_id
        if database is not None:
            url_parameters[u'databaseName'] = database
        if schema is not None:
            url_parameters[u'schemaName'] = schema
        if warehouse is not None:
            url_parameters[u'warehouse'] = warehouse
        if role is not None:
            url_parameters[u'roleName'] = role

        if len(url_parameters) > 0:
            url = url + u'?' + urlencode(url_parameters)

        # first auth request
        if passcode_in_password:
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'passcode'
        elif passcode:
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'passcode'
            body[u'data'][u'PASSCODE'] = passcode

        if session_parameters:
            body[u'data'][u'SESSION_PARAMETERS'] = session_parameters

        self.logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body[u'data'].items() if k != u'PASSWORD'})

        ret = self._post_request(
            url, headers, json.dumps(body),
            timeout=self._connection._login_timeout)
        # this means we are waiting for MFA authentication
        if ret[u'data'].get(u'nextAction') and ret[u'data'][
            u'nextAction'] == u'EXT_AUTHN_DUO_ALL':
            body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
            body[u'data'][u'EXT_AUTHN_DUO_METHOD'] = u'push'
            self.ret = None

            def post_request_wrapper(self, url, headers, body):
                # get the MFA response
                self.ret = self._post_request(
                    url, headers, body,
                    timeout=self._connection._login_timeout)

            # send new request to wait until MFA is approved
            t = Thread(target=post_request_wrapper,
                       args=[self, url, headers, json.dumps(body)])
            t.daemon = True
            t.start()
            if callable(mfa_callback):
                c = mfa_callback()
                while not self.ret:
                    next(c)
            else:
                t.join(timeout=120)
            ret = self.ret
            if ret[u'data'].get(u'nextAction') and ret[u'data'][
                u'nextAction'] == u'EXT_AUTHN_SUCCESS':
                body = copy.deepcopy(body_template)
                body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
                # final request to get tokens
                ret = self._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._connection._login_timeout)

        elif ret[u'data'].get(u'nextAction') and ret[u'data'][
            u'nextAction'] == u'PWD_CHANGE':
            if callable(password_callback):
                body = copy.deepcopy(body_template)
                body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
                body[u'data'][u"LOGIN_NAME"] = user
                body[u'data'][u"PASSWORD"] = password
                body[u'data'][u'CHOSEN_NEW_PASSWORD'] = password_callback()
                # New Password input
                ret = self._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._connection._login_timeout)

        self.logger.debug(u'completed authentication')
        if not ret[u'success']:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': (u"failed to connect to DB: {host}:{port}, "
                             u"proxies={proxy_host}:{proxy_port}, "
                             u"proxy_user={proxy_user}, "
                             u"{message}").format(
                        host=self._host,
                        port=self._port,
                        proxy_host=self._proxy_host,
                        proxy_port=self._proxy_port,
                        proxy_user=self._proxy_user,
                        message=ret[u'message'],
                    ),
                    u'errno': ER_FAILED_TO_CONNECT_TO_DB,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })
        else:
            self._token = ret[u'data'][u'token']
            self._master_token = ret[u'data'][u'masterToken']
            self.logger.debug(u'token = %s', self._token)
            self.logger.debug(u'master_token = %s', self._master_token)
            if u'sessionId' in ret[u'data']:
                self._connection._session_id = ret[u'data'][u'sessionId']
            if u'sessionInfo' in ret[u'data']:
                session_info = ret[u'data'][u'sessionInfo']
                if u'databaseName' in session_info:
                    self._connection._database = session_info[u'databaseName']
                if u'schemaName' in session_info:
                    self._connection.schema = session_info[u'schemaName']
                if u'roleName' in session_info:
                    self._connection._role = session_info[u'roleName']
                if u'warehouseName' in session_info:
                    self._connection._warehouse = session_info[u'warehouseName']

    def request(self, url, body=None, method=u'post', client=u'sfsql',
                _no_results=False):
        if body is None:
            body = {}
        if not hasattr(self, u'_master_token'):
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        if client == u'sfsql':
            accept_type = ACCEPT_TYPE_APPLICATION_SNOWFLAKE
        else:
            accept_type = CONTENT_TYPE_APPLICATION_JSON

        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": accept_type,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        if method == u'post':
            return self._post_request(
                url, headers, json.dumps(body),
                token=self._token, _no_results=_no_results,
                timeout=self._connection._network_timeout)
        else:
            return self._get_request(
                url, headers, token=self._token,
                timeout=self._connection._network_timeout)

    def _renew_session(self):
        if not hasattr(self, u'_master_token'):
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        self.logger.debug(u'updating session')
        self.logger.debug(u'master_token: %s', self._master_token)
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": CONTENT_TYPE_APPLICATION_JSON,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        request_id = TO_UNICODE(uuid.uuid4())
        self.logger.debug(u'request_id: %s', request_id)
        url = u'/session/token-request?' + urlencode({
            u'requestId': request_id})

        body = {
            u"oldSessionToken": self._token,
            u"requestType": REQUEST_TYPE_RENEW,
        }
        self._session = None  # invalidate session object
        ret = self._post_request(
            url, headers, json.dumps(body),
            token=self._master_token,
            timeout=self._connection._network_timeout)
        if ret[u'success'] and u'data' in ret \
                and u'sessionToken' in ret[u'data']:
            self.logger.debug(u'success: %s', ret)
            self._token = ret[u'data'][u'sessionToken']
            self._master_token = ret[u'data'][u'masterToken']
            self.logger.debug(u'updating session completed')
            return ret
        else:
            self.logger.debug(u'failed: %s', ret)
            err = ret[u'message']
            if u'data' in ret and u'errorMessage' in ret[u'data']:
                err += ret[u'data'][u'errorMessage']
            Error.errorhandler_wrapper(
                self._connection, None, ProgrammingError,
                {
                    u'msg': err,
                    u'errno': ER_FAILED_TO_RENEW_SESSION,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })

    def _delete_session(self):
        if not hasattr(self, u'_master_token'):
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        url = u'/session?' + urlencode({u'delete': u'true'})
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": CONTENT_TYPE_APPLICATION_JSON,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        body = {}
        try:
            ret = self._post_request(
                url, headers, json.dumps(body),
                token=self._token, timeout=5, is_single_thread=True)
            if not ret or ret.get(u'success'):
                return
            err = ret[u'message']
            if ret.get(u'data') and ret[u'data'].get(u'errorMessage'):
                err += ret[u'data'][u'errorMessage']
                # no exception is raised
        except:
            pass

    def _get_request(self, url, headers, token=None, timeout=None):
        if 'Content-Encoding' in headers:
            del headers['Content-Encoding']
        if 'Content-Length' in headers:
            del headers['Content-Length']

        full_url = u'{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        proxies = SnowflakeRestful.set_proxies(
            self._proxy_host, self._proxy_port, self._proxy_user,
            self._proxy_password
        )
        self.logger.debug(u'url=%s, proxies=%s', full_url, proxies)
        ret = SnowflakeRestful.access_url(
            conn=self._connection,
            session_context=self,
            method=u'get',
            full_url=full_url,
            headers=headers,
            data=None,
            proxies=proxies,
            timeout=(self._connect_timeout, self._connect_timeout, timeout),
            token=token,
            max_connection_pool=self._max_connection_pool)

        if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            self.logger.debug(
                u'ret[code] = {code} after renew_session'.format(
                    code=(ret[u'code'] if u'code' in ret else u'N/A')))
            if u'success' in ret and ret[u'success']:
                return self._get_request(url, headers, token=self._token)

        return ret

    def _post_request(self, url, headers, body, token=None,
                      timeout=None, _no_results=False):
        full_url = u'{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        proxies = SnowflakeRestful.set_proxies(
            self._proxy_host, self._proxy_port, self._proxy_user,
            self._proxy_password)

        ret = SnowflakeRestful.access_url(
            conn=self._connection,
            session_context=self,
            method=u'post',
            full_url=full_url,
            headers=headers,
            data=body,
            proxies=proxies,
            timeout=(
                self._connect_timeout, self._connect_timeout, timeout),
            token=token,
            max_connection_pool=self._max_connection_pool)
        self.logger.debug(
            u'ret[code] = {code}, after post request'.format(
                code=(ret.get(u'code', u'N/A'))))

        if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            self.logger.debug(
                u'ret[code] = {code} after renew_session'.format(
                    code=(ret[u'code'] if u'code' in ret else u'N/A')))
            if u'success' in ret and ret[u'success']:
                return self._post_request(
                    url, headers, body, token=self._token, timeout=timeout)

        is_session_renewed = False
        result_url = None
        if u'code' in ret and ret[
            u'code'] == QUERY_IN_PROGRESS_ASYNC_CODE and _no_results:
            return ret

        while is_session_renewed or u'code' in ret and ret[u'code'] in \
                (QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE):
            if self._injectClientPause > 0:
                self.logger.debug(
                    u'waiting for {inject_client_pause}...'.format(
                        inject_client_pause=self._injectClientPause))
                time.sleep(self._injectClientPause)
            # ping pong
            result_url = ret[u'data'][
                u'getResultUrl'] if not is_session_renewed else result_url
            self.logger.debug(u'ping pong starting...')
            ret = self._get_request(
                result_url, headers, token=self._token, timeout=timeout)
            self.logger.debug(
                u'ret[code] = %s',
                ret[u'code'] if u'code' in ret else u'N/A')
            self.logger.debug(u'ping pong done')
            if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
                ret = self._renew_session()
                self.logger.debug(
                    u'ret[code] = %s after renew_session',
                    ret[u'code'] if u'code' in ret else u'N/A')
                if u'success' in ret and ret[u'success']:
                    is_session_renewed = True
            else:
                is_session_renewed = False

        return ret

    @staticmethod
    def access_url(conn, session_context, method, full_url, headers, data,
                   proxies, timeout=(
                    DEFAULT_CONNECT_TIMEOUT,
                    DEFAULT_CONNECT_TIMEOUT,
                    DEFAULT_REQUEST_TIMEOUT),
                   requests_retry=REQUESTS_RETRY,
                   token=None,
                   is_raw_text=False,
                   catch_okta_unauthorized_error=False,
                   is_raw_binary=False,
                   is_raw_binary_iterator=True,
                   max_connection_pool=MAX_CONNECTION_POOL,
                   use_ijson=False, is_single_thread=False):
        logger = getLogger(__name__)

        connection_timeout = timeout[0:2]
        request_timeout = timeout[2]  # total request timeout
        request_thread_timeout = 60  # one request thread timeout

        def request_thread(result_queue):
            try:
                if session_context._session is None:
                    session_context._session = requests.Session()
                    session_context._session.mount(
                        u'http://',
                        HTTPAdapter(
                            pool_connections=int(max_connection_pool),
                            pool_maxsize=int(max_connection_pool),
                            max_retries=requests_retry))
                    session_context._session.mount(
                        u'https://',
                        HTTPAdapter(
                            pool_connections=int(max_connection_pool),
                            pool_maxsize=int(max_connection_pool),
                            max_retries=requests_retry))

                if not catch_okta_unauthorized_error and data and len(data) > 0:
                    gzdata = BytesIO()
                    gzip.GzipFile(fileobj=gzdata, mode=u'wb').write(
                        data.encode(u'utf-8'))
                    gzdata.seek(0, 0)
                    headers['Content-Encoding'] = 'gzip'
                    input_data = gzdata
                else:
                    input_data = data

                raw_ret = session_context._session.request(
                    method=method,
                    url=full_url,
                    proxies=proxies,
                    headers=headers,
                    data=input_data,
                    timeout=connection_timeout,
                    verify=True,
                    stream=is_raw_binary,
                    auth=SnowflakeAuth(token),
                )

                if raw_ret.status_code == OK:
                    logger.debug(u'SUCCESS')
                    if is_raw_text:
                        ret = raw_ret.text
                    elif is_raw_binary:
                        raw_data = decompress_raw_data(
                            raw_ret.raw, add_bracket=True
                        ).decode('utf-8', 'replace')
                        if not is_raw_binary_iterator:
                            ret = json.loads(raw_data)
                        elif not use_ijson:
                            ret = iter(json.loads(raw_data))
                        else:
                            ret = split_rows_from_stream(StringIO(raw_data))
                    else:
                        ret = raw_ret.json()
                    result_queue.put((ret, False))
                elif raw_ret.status_code in STATUS_TO_EXCEPTION:
                    # retryable exceptions
                    result_queue.put(
                        (STATUS_TO_EXCEPTION[raw_ret.status_code](), True))
                elif raw_ret.status_code == UNAUTHORIZED and \
                        catch_okta_unauthorized_error:
                    # OKTA Unauthorized errors
                    result_queue.put(
                        (DatabaseError(
                            msg=(u'Failed to get '
                                 u'authentication by OKTA: '
                                 u'{status}: {reason}'.format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason,
                            )),
                            errno=ER_FAILED_TO_CONNECT_TO_DB,
                            sqlstate=SQLSTATE_CONNECTION_REJECTED),
                         False))
                else:
                    result_queue.put(
                        (InterfaceError(
                            msg=(u"{status} {reason}: "
                                 u"{method} {url}").format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason,
                                method=method,
                                url=full_url),
                            errno=ER_FAILED_TO_REQUEST,
                            sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                        ), False))
            except (BadStatusLine,
                    SSLError,
                    ProtocolError,
                    OpenSSL.SSL.SysCallError, ValueError) as err:
                logger.exception('who is hitting error?')
                if logger.getEffectiveLevel() <= logging.DEBUG:
                    logger.debug(err)
                if not isinstance(err, OpenSSL.SSL.SysCallError) or \
                                err.args[0] in (
                                errno.ECONNRESET,
                                errno.ETIMEDOUT,
                                errno.EPIPE,
                                -1):
                    result_queue.put((err, True))
                else:
                    # all other OpenSSL errors are not retryable
                    result_queue.put((err, False))
            except ConnectionError as err:
                logger.exception(u'ConnectionError: %s', err)
                result_queue.put((OperationalError(
                    msg=u'Failed to connect: {0}'.format(err),
                    errno=ER_FAILED_TO_SERVER,
                    sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                ), False))
            except ValueError as err:
                logger.exception(u'Return value is not JSON: %s', err)
                result_queue.put((InterfaceError(
                    msg=u"Failed to decode JSON output",
                    errno=ER_FAILED_TO_REQUEST,
                ), False))

        if is_single_thread:
            # This is dedicated code for DELETE SESSION when Python exists.
            request_result_queue = Queue()
            request_thread(request_result_queue)
            try:
                # don't care about the return value, because no retry and
                # no error will show up
                _, _ = request_result_queue.get(timeout=request_timeout)
            except:
                pass
            return None

        retry_cnt = 0
        while True:
            return_object = None
            request_result_queue = Queue()
            th = Thread(name='request_thread', target=request_thread,
                        args=(request_result_queue,))
            th.daemon = True
            th.start()
            try:
                logger.debug('request thread timeout: %s, '
                             'rest of request timeout: %s, '
                             'retry cnt: %s',
                             request_thread_timeout,
                             request_timeout,
                             retry_cnt + 1)
                th.join(timeout=request_thread_timeout)
                logger.debug('request thread joined')
                return_object, retryable = request_result_queue.get(
                    timeout=int(request_thread_timeout / 2))
                logger.debug('request thread returned object')
                if retryable:
                    raise RequestRetry()
                elif isinstance(return_object, Error):
                    Error.errorhandler_wrapper(conn, None, return_object)
                elif isinstance(return_object, Exception):
                    Error.errorhandler_wrapper(
                        conn, None, OperationalError,
                        {
                            u'msg': u'Failed to execute request: {0}'.format(
                                return_object),
                            u'errno': ER_FAILED_TO_REQUEST,
                        })
                break
            except (RequestRetry, AttributeError, EmptyQueue) as e:
                # RequestRetry is raised in case of retryable error
                # Empty is raised if the result queue is empty
                if request_timeout is not None:
                    sleeping_time = min(2 ** retry_cnt,
                                        min(request_timeout, 16))
                else:
                    sleeping_time = min(2 ** retry_cnt, 16)
                if sleeping_time <= 0:
                    # no more sleeping time
                    break
                if request_timeout is not None:
                    request_timeout -= sleeping_time
                logger.info(
                    u'retrying: errorclass=%s, '
                    u'error=%s, '
                    u'return_object=%s, '
                    u'counter=%s, '
                    u'sleeping=%s(s)',
                    type(e),
                    e,
                    return_object,
                    retry_cnt + 1,
                    sleeping_time)
            time.sleep(sleeping_time)
            retry_cnt += 1

        if isinstance(return_object, Error):
            Error.errorhandler_wrapper(conn, None, return_object)
        elif isinstance(return_object, Exception):
            Error.errorhandler_wrapper(
                conn, None, OperationalError,
                {
                    u'msg': u'Failed to execute request: {0}'.format(
                        return_object),
                    u'errno': ER_FAILED_TO_REQUEST,
                })
        return return_object

    def authenticate_by_saml(self, authenticator, account, user, password):
        u"""
        SAML Authentication
        """
        self.logger.info(u'authenticating by SAML')
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": CONTENT_TYPE_APPLICATION_JSON,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        url = u"/session/authenticator-request"
        body = {
            u'data': {
                u"CLIENT_APP_ID": CLIENT_NAME,
                u"CLIENT_APP_VERSION": CLIENT_VERSION,
                u"SVN_REVISION": VERSION[3],
                u"ACCOUNT_NAME": account,
                u"AUTHENTICATOR": authenticator,
            },
        }

        self.logger.debug(
            u'account=%s, authenticator=%s',
            account, authenticator,
        )

        # Get OKTA token
        ret = self._post_request(
            url, headers, json.dumps(body),
            timeout=self._connection._login_timeout)

        if not ret[u'success']:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': (u"failed to connect to DB: {host}:{port}, "
                             u"proxies={proxy_host}:{proxy_port}, "
                             u"proxy_user={proxy_user}, "
                             u"{message}").format(
                        host=self._host,
                        port=self._port,
                        proxy_host=self._proxy_host,
                        proxy_port=self._proxy_port,
                        proxy_user=self._proxy_user,
                        message=ret[u'message'],
                    ),
                    u'errno': ER_FAILED_TO_CONNECT_TO_DB,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })

        data = ret[u'data']
        token_url = data[u'tokenUrl']
        sso_url = data[u'ssoUrl']

        proxies = SnowflakeRestful.set_proxies(
            self._proxy_host, self._proxy_port, self._proxy_user,
            self._proxy_password)
        self.logger.debug(u'token_url=%s, proxies=%s', token_url, proxies)

        data = {
            u'username': user,
            u'password': password,
        }
        self.logger.debug(u'token url: %s', token_url)
        ret = SnowflakeRestful.access_url(
            conn=self._connection,
            session_context=self,
            method=u'post',
            full_url=token_url,
            headers=headers,
            data=json.dumps(data),
            proxies=proxies,
            timeout=(self._connect_timeout,
                     self._connect_timeout,
                     self._connection._login_timeout),
            catch_okta_unauthorized_error=True)

        one_time_token = ret[u'cookieToken']
        url_parameters = {
            u'RelayState': u"/some/deep/link",
            u'onetimetoken': one_time_token,
        }
        sso_url = sso_url + u'?' + urlencode(url_parameters)

        headers = {
            u"Accept": u'*/*',
        }
        self.logger.debug(u'sso url: %s', sso_url)
        ret = SnowflakeRestful.access_url(
            conn=self._connection,
            session_context=self,
            method=u'get',
            full_url=sso_url,
            headers=headers,
            data=None,
            proxies=proxies,
            timeout=(self._connect_timeout,
                     self._connect_timeout,
                     self._connection._login_timeout),
            is_raw_text=True)
        return ret
