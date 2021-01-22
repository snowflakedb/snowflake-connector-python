#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

import collections
import contextlib
import gzip
import itertools
import json
import logging
import time
import traceback
import uuid
from io import BytesIO
from threading import Lock

import OpenSSL.SSL

from . import ssl_wrap_socket
from .compat import (
    BAD_GATEWAY,
    BAD_REQUEST,
    FORBIDDEN,
    GATEWAY_TIMEOUT,
    INTERNAL_SERVER_ERROR,
    METHOD_NOT_ALLOWED,
    OK,
    REQUEST_TIMEOUT,
    SERVICE_UNAVAILABLE,
    UNAUTHORIZED,
    BadStatusLine,
    IncompleteRead,
    urlencode,
    urlparse,
)
from .constants import HTTP_HEADER_ACCEPT, HTTP_HEADER_CONTENT_TYPE, HTTP_HEADER_SERVICE_NAME, HTTP_HEADER_USER_AGENT
from .description import (
    CLIENT_NAME,
    CLIENT_VERSION,
    COMPILER,
    IMPLEMENTATION,
    OPERATING_SYSTEM,
    PLATFORM,
    PYTHON_VERSION,
    SNOWFLAKE_CONNECTOR_VERSION,
)
from .errorcode import (
    ER_CONNECTION_IS_CLOSED,
    ER_FAILED_TO_CONNECT_TO_DB,
    ER_FAILED_TO_RENEW_SESSION,
    ER_FAILED_TO_REQUEST,
)
from .errors import (
    BadGatewayError,
    BadRequest,
    DatabaseError,
    Error,
    ForbiddenError,
    GatewayTimeoutError,
    InterfaceError,
    InternalServerError,
    MethodNotAllowed,
    OperationalError,
    OtherHTTPRetryableError,
    ProgrammingError,
    ServiceUnavailableError,
)
from .sqlstate import (
    SQLSTATE_CONNECTION_NOT_EXISTS,
    SQLSTATE_CONNECTION_REJECTED,
    SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
    SQLSTATE_IO_ERROR,
)
from .telemetry_oob import TelemetryService
from .time_util import DEFAULT_MASTER_VALIDITY_IN_SECONDS, DecorrelateJitterBackoff, get_time_millis
from .tool.probe_connection import probe_connection
from .vendored import requests
from .vendored.requests.adapters import HTTPAdapter
from .vendored.requests.auth import AuthBase
from .vendored.requests.exceptions import ConnectionError, ConnectTimeout, InvalidProxyURL, ReadTimeout, SSLError
from .vendored.requests.utils import prepend_scheme_if_needed, select_proxy
from .vendored.urllib3.exceptions import ProtocolError, ReadTimeoutError
from .vendored.urllib3.util.url import parse_url

logger = logging.getLogger(__name__)

"""
Monkey patch for PyOpenSSL Socket wrapper
"""
ssl_wrap_socket.inject_into_urllib3()

# known applications
APPLICATION_SNOWSQL = 'SnowSQL'

# requests parameters
REQUESTS_RETRY = 1  # requests library builtin retry
DEFAULT_SOCKET_CONNECT_TIMEOUT = 1 * 60  # don't reduce less than 45 seconds

# return codes
QUERY_IN_PROGRESS_CODE = '333333'  # GS code: the query is in progress
QUERY_IN_PROGRESS_ASYNC_CODE = '333334'  # GS code: the query is detached

ID_TOKEN_EXPIRED_GS_CODE = '390110'
SESSION_EXPIRED_GS_CODE = '390112'  # GS code: session expired. need to renew
MASTER_TOKEN_NOTFOUND_GS_CODE = '390113'
MASTER_TOKEN_EXPIRED_GS_CODE = '390114'
MASTER_TOKEN_INVALD_GS_CODE = '390115'
ID_TOKEN_INVALID_LOGIN_REQUEST_GS_CODE = '390195'
BAD_REQUEST_GS_CODE = '390400'

# other constants
CONTENT_TYPE_APPLICATION_JSON = 'application/json'
ACCEPT_TYPE_APPLICATION_SNOWFLAKE = 'application/snowflake'

REQUEST_TYPE_RENEW = 'RENEW'

HEADER_AUTHORIZATION_KEY = "Authorization"
HEADER_SNOWFLAKE_TOKEN = 'Snowflake Token="{token}"'

REQUEST_ID = 'requestId'
REQUEST_GUID = 'request_guid'
SNOWFLAKE_HOST_SUFFIX = '.snowflakecomputing.com'

SNOWFLAKE_CONNECTOR_VERSION = SNOWFLAKE_CONNECTOR_VERSION
PYTHON_VERSION = PYTHON_VERSION
OPERATING_SYSTEM = OPERATING_SYSTEM
PLATFORM = PLATFORM
IMPLEMENTATION = IMPLEMENTATION
COMPILER = COMPILER

CLIENT_NAME = CLIENT_NAME  # don't change!
CLIENT_VERSION = CLIENT_VERSION
PYTHON_CONNECTOR_USER_AGENT = \
    '{name}/{version} ({platform}) {python_implementation}/{python_version}'.format(
        name=CLIENT_NAME,
        version=SNOWFLAKE_CONNECTOR_VERSION,
        python_implementation=IMPLEMENTATION,
        python_version=PYTHON_VERSION,
        platform=PLATFORM)

NO_TOKEN = 'no-token'

STATUS_TO_EXCEPTION = {
    INTERNAL_SERVER_ERROR: InternalServerError,
    FORBIDDEN: ForbiddenError,
    SERVICE_UNAVAILABLE: ServiceUnavailableError,
    GATEWAY_TIMEOUT: GatewayTimeoutError,
    BAD_REQUEST: BadRequest,
    BAD_GATEWAY: BadGatewayError,
    METHOD_NOT_ALLOWED: MethodNotAllowed,
}

DEFAULT_AUTHENTICATOR = 'SNOWFLAKE'  # default authenticator name
EXTERNAL_BROWSER_AUTHENTICATOR = 'EXTERNALBROWSER'
KEY_PAIR_AUTHENTICATOR = 'SNOWFLAKE_JWT'
OAUTH_AUTHENTICATOR = 'OAUTH'
ID_TOKEN_AUTHENTICATOR = 'ID_TOKEN'
USR_PWD_MFA_AUTHENTICATOR = 'USERNAME_PASSWORD_MFA'


def is_retryable_http_code(code: int) -> bool:
    """Decides whether code is a retryable HTTP issue."""
    return 500 <= code < 600 or code in (
        BAD_REQUEST,  # 400
        FORBIDDEN,  # 403
        METHOD_NOT_ALLOWED,  # 405
        REQUEST_TIMEOUT,  # 408
    )


class ProxySupportAdapter(HTTPAdapter):
    """This Adapter creates proper headers for Proxy CONNECT messages."""

    def get_connection(self, url, proxies=None):
        proxy = select_proxy(url, proxies)
        parsed_url = urlparse(url)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, 'http')
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL("Please check proxy URL. It is malformed"
                                      " and could be missing the host.")
            proxy_manager = self.proxy_manager_for(proxy)

            # Add Host to proxy header SNOW-232777
            proxy_manager.proxy_headers['Host'] = parsed_url.hostname
            conn = proxy_manager.connection_from_url(url)
        else:
            # Only scheme should be lower case
            url = parsed_url.geturl()
            conn = self.poolmanager.connection_from_url(url)

        return conn


class RetryRequest(Exception):
    """Signal to retry request."""
    pass


class ReauthenticationRequest(Exception):
    """Signal to reauthenticate."""

    def __init__(self, cause):
        self.cause = cause


class SnowflakeAuth(AuthBase):
    """Attaches HTTP Authorization header for Snowflake."""

    def __init__(self, token):
        # setup any auth-related data here
        self.token = token

    def __call__(self, r):
        """Modifies and returns the request."""
        if HEADER_AUTHORIZATION_KEY in r.headers:
            del r.headers[HEADER_AUTHORIZATION_KEY]
        if self.token != NO_TOKEN:
            r.headers[
                HEADER_AUTHORIZATION_KEY] = HEADER_SNOWFLAKE_TOKEN.format(
                token=self.token)
        return r


class SnowflakeRestful(object):
    """Snowflake Restful class."""

    def __init__(self, host='127.0.0.1', port=8080,
                 protocol='http',
                 inject_client_pause=0,
                 connection=None):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._inject_client_pause = inject_client_pause
        self._connection = connection
        self._lock_token = Lock()
        self._idle_sessions = collections.deque()
        self._active_sessions = set()

        # OCSP mode (OCSPMode.FAIL_OPEN by default)
        ssl_wrap_socket.FEATURE_OCSP_MODE = \
            self._connection and self._connection._ocsp_mode()
        # cache file name (enabled by default)
        ssl_wrap_socket.FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = \
            self._connection and self._connection._ocsp_response_cache_filename

        # This is to address the issue where requests hangs
        _ = 'dummy'.encode('idna').decode('utf-8')  # noqa

    @property
    def token(self):
        return self._token if hasattr(self, '_token') else None

    @property
    def master_token(self):
        return self._master_token if hasattr(self, '_master_token') else None

    @property
    def master_validity_in_seconds(self):
        return self._master_validity_in_seconds \
            if hasattr(self, '_master_validity_in_seconds') and \
               self._master_validity_in_seconds \
            else DEFAULT_MASTER_VALIDITY_IN_SECONDS

    @master_validity_in_seconds.setter
    def master_validity_in_seconds(self, value):
        self._master_validity_in_seconds = value \
            if value else DEFAULT_MASTER_VALIDITY_IN_SECONDS

    @property
    def id_token(self):
        return getattr(self, '_id_token', None)

    @id_token.setter
    def id_token(self, value):
        self._id_token = value

    @property
    def mfa_token(self):
        return getattr(self, '_mfa_token', None)

    @mfa_token.setter
    def mfa_token(self, value):
        self._mfa_token = value

    def close(self):
        if hasattr(self, '_token'):
            del self._token
        if hasattr(self, '_master_token'):
            del self._master_token
        if hasattr(self, '_id_token'):
            del self._id_token
        if hasattr(self, '_mfa_token'):
            del self._mfa_token
        sessions = list(self._active_sessions)
        if sessions:
            logger.debug("Closing %s active sessions", len(sessions))
        sessions.extend(self._idle_sessions)
        self._active_sessions.clear()
        self._idle_sessions.clear()
        for s in sessions:
            try:
                s.close()
            except Exception as e:
                logger.info("Session cleanup failed: %s", e)

    def request(self, url, body=None, method='post', client='sfsql',
                _no_results=False, timeout=None, _include_retry_params=False):
        if body is None:
            body = {}
        if self.master_token is None and self.token is None:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    'msg': "Connection is closed",
                    'errno': ER_CONNECTION_IS_CLOSED,
                    'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        if client == 'sfsql':
            accept_type = ACCEPT_TYPE_APPLICATION_SNOWFLAKE
        else:
            accept_type = CONTENT_TYPE_APPLICATION_JSON

        if timeout is None:
            timeout = self._connection.network_timeout

        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: accept_type,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        if method == 'post':
            return self._post_request(
                url, headers, json.dumps(body),
                token=self.token, _no_results=_no_results,
                timeout=timeout, _include_retry_params=_include_retry_params)
        else:
            return self._get_request(
                url, headers, token=self.token,
                timeout=timeout)

    def update_tokens(self, session_token, master_token,
                      master_validity_in_seconds=None,
                      id_token=None,
                      mfa_token=None):
        """Updates session and master tokens and optionally temporary credential."""
        with self._lock_token:
            self._token = session_token
            self._master_token = master_token
            self._id_token = id_token
            self._mfa_token = mfa_token
            self._master_validity_in_seconds = master_validity_in_seconds

    def _renew_session(self):
        """Renew a session and master token."""
        return self._token_request(REQUEST_TYPE_RENEW)

    def _token_request(self, request_type):
        logger.debug(
            'updating session. master_token: {}'.format('****' if self.master_token else None))
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        request_id = str(uuid.uuid4())
        logger.debug('request_id: %s', request_id)
        url = '/session/token-request?' + urlencode({
            REQUEST_ID: request_id})

        # NOTE: ensure an empty key if master token is not set.
        # This avoids HTTP 400.
        header_token = self.master_token or ""
        body = {
            u"oldSessionToken": self.token,
            u"requestType": request_type,
        }
        ret = self._post_request(
            url, headers, json.dumps(body),
            token=header_token,
            timeout=self._connection.network_timeout)
        if ret.get('success') and ret.get('data', {}).get('sessionToken'):
            logger.debug('success: %s', ret)
            self.update_tokens(
                ret['data']['sessionToken'],
                ret['data'].get('masterToken'),
                master_validity_in_seconds=ret['data'].get(
                    'masterValidityInSeconds'))
            logger.debug('updating session completed')
            return ret
        else:
            logger.debug('failed: %s', ret)
            err = ret.get('message')
            if err is not None and ret.get('data'):
                err += ret['data'].get('errorMessage', '')
            errno = ret.get('code') or ER_FAILED_TO_RENEW_SESSION
            if errno in (
                    ID_TOKEN_EXPIRED_GS_CODE,
                    SESSION_EXPIRED_GS_CODE,
                    MASTER_TOKEN_NOTFOUND_GS_CODE,
                    MASTER_TOKEN_EXPIRED_GS_CODE,
                    MASTER_TOKEN_INVALD_GS_CODE,
                    BAD_REQUEST_GS_CODE):
                raise ReauthenticationRequest(
                    ProgrammingError(
                        msg=err,
                        errno=int(errno),
                        sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED))
            Error.errorhandler_wrapper(
                self._connection, None, ProgrammingError,
                {
                    'msg': err,
                    'errno': int(errno),
                    'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })

    def _heartbeat(self):
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name
        request_id = str(uuid.uuid4())
        logger.debug('request_id: %s', request_id)
        url = '/session/heartbeat?' + urlencode({
            REQUEST_ID: request_id})
        ret = self._post_request(
            url, headers, None,
            token=self.token,
            timeout=self._connection.network_timeout)
        if not ret.get('success'):
            logger.error("Failed to heartbeat. code: %s, url: %s",
                         ret.get('code'), url)

    def delete_session(self, retry=False):
        """Deletes the session."""
        if self.master_token is None:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    'msg': "Connection is closed",
                    'errno': ER_CONNECTION_IS_CLOSED,
                    'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        url = '/session?' + urlencode({'delete': 'true'})
        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if self._connection.service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = self._connection.service_name

        body = {}
        retry_limit = 3 if retry else 1
        num_retries = 0
        should_retry = True
        while should_retry and (num_retries < retry_limit):
            try:
                should_retry = False
                ret = self._post_request(
                    url, headers, json.dumps(body),
                    token=self.token, timeout=5, no_retry=True)
                if not ret:
                    if retry:
                        should_retry = True
                    else:
                        return
                elif ret.get('success'):
                    return
                err = ret.get('message')
                if err is not None and ret.get('data'):
                    err += ret['data'].get('errorMessage', '')
                    # no exception is raised
                logger.debug('error in deleting session. ignoring...: %s', err)
            except Exception as e:
                logger.debug('error in deleting session. ignoring...: %s', e)
            finally:
                num_retries += 1

    def _get_request(self, url, headers, token=None,
                     timeout=None,
                     socket_timeout=DEFAULT_SOCKET_CONNECT_TIMEOUT):
        if 'Content-Encoding' in headers:
            del headers['Content-Encoding']
        if 'Content-Length' in headers:
            del headers['Content-Length']

        full_url = '{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        ret = self.fetch('get', full_url, headers, timeout=timeout,
                         token=token, socket_timeout=socket_timeout)
        if ret.get('code') == SESSION_EXPIRED_GS_CODE:
            try:
                ret = self._renew_session()
            except ReauthenticationRequest as ex:
                if self._connection._authenticator != \
                        EXTERNAL_BROWSER_AUTHENTICATOR:
                    raise ex.cause
                ret = self._connection._reauthenticate_by_webbrowser()
            logger.debug(
                'ret[code] = {code} after renew_session'.format(
                    code=(ret.get('code', 'N/A'))))
            if ret.get('success'):
                return self._get_request(url, headers, token=self.token)

        return ret

    def _post_request(self, url, headers, body, token=None,
                      timeout=None, _no_results=False, no_retry=False,
                      socket_timeout=DEFAULT_SOCKET_CONNECT_TIMEOUT,
                      _include_retry_params=False):
        full_url = '{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        if self._connection._probe_connection:
            from pprint import pprint
            ret = probe_connection(full_url)
            pprint(ret)

        ret = self.fetch('post', full_url, headers, data=body,
                         timeout=timeout, token=token,
                         no_retry=no_retry, socket_timeout=socket_timeout,
                         _include_retry_params=_include_retry_params)
        logger.debug(
            'ret[code] = {code}, after post request'.format(
                code=(ret.get('code', 'N/A'))))

        if ret.get('code') == SESSION_EXPIRED_GS_CODE:
            try:
                ret = self._renew_session()
            except ReauthenticationRequest as ex:
                if self._connection._authenticator != \
                        EXTERNAL_BROWSER_AUTHENTICATOR:
                    raise ex.cause
                ret = self._connection._reauthenticate_by_webbrowser()
            logger.debug(
                'ret[code] = {code} after renew_session'.format(
                    code=(ret.get('code', 'N/A'))))
            if ret.get('success'):
                return self._post_request(
                    url, headers, body, token=self.token, timeout=timeout)

        if ret.get('code') == QUERY_IN_PROGRESS_ASYNC_CODE and _no_results:
            return ret

        while ret.get('code') in \
                (QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE):
            if self._inject_client_pause > 0:
                logger.debug(
                    'waiting for %s...', self._inject_client_pause)
                time.sleep(self._inject_client_pause)
            # ping pong
            result_url = ret['data']['getResultUrl']
            logger.debug('ping pong starting...')
            ret = self._get_request(
                result_url, headers, token=self.token, timeout=timeout)
            logger.debug('ret[code] = %s', ret.get('code', 'N/A'))
            logger.debug('ping pong done')

        return ret

    def fetch(self, method, full_url, headers, data=None, timeout=None,
              **kwargs):
        """Carry out API request with session management."""

        class RetryCtx(object):
            def __init__(self, timeout, _include_retry_params=False):
                self.total_timeout = timeout
                self.timeout = timeout
                self.cnt = 0
                self.sleeping_time = 1
                self.start_time = get_time_millis()
                self._include_retry_params = _include_retry_params
                # backoff between 1 and 16 seconds
                self._backoff = DecorrelateJitterBackoff(1, 16)

            def next_sleep(self):
                self.sleeping_time = self._backoff.next_sleep(
                    self.cnt, self.sleeping_time)
                return self.sleeping_time

            def add_retry_params(self, full_url):
                if self._include_retry_params and self.cnt > 0:
                    suffix = urlencode({
                        'clientStartTime': self.start_time,
                        'retryCount': self.cnt
                    })
                    sep = '&' if urlparse(full_url).query else '?'
                    return full_url + sep + suffix
                else:
                    return full_url

        include_retry_params = kwargs.pop('_include_retry_params', False)

        with self._use_requests_session() as session:
            retry_ctx = RetryCtx(timeout, include_retry_params)
            while True:
                ret = self._request_exec_wrapper(
                    session, method, full_url, headers, data, retry_ctx,
                    **kwargs)
                if ret is not None:
                    return ret

    @staticmethod
    def add_request_guid(full_url):
        """Adds request_guid parameter for HTTP request tracing."""
        parsed_url = urlparse(full_url)
        if not parsed_url.hostname.endswith(SNOWFLAKE_HOST_SUFFIX):
            return full_url
        suffix = urlencode({
            REQUEST_GUID: str(uuid.uuid4())
        })
        sep = '&' if parsed_url.query else '?'
        # url has query string already, just add fields
        return full_url + sep + suffix

    def _request_exec_wrapper(
            self,
            session, method, full_url, headers, data, retry_ctx,
            no_retry=False, token=NO_TOKEN,
            **kwargs):

        conn = self._connection
        logger.debug('remaining request timeout: %s, retry cnt: %s',
                     retry_ctx.timeout, retry_ctx.cnt + 1)

        start_request_thread = time.time()
        full_url = retry_ctx.add_retry_params(full_url)
        full_url = SnowflakeRestful.add_request_guid(full_url)
        try:
            return_object = self._request_exec(
                session=session,
                method=method,
                full_url=full_url,
                headers=headers,
                data=data,
                token=token,
                **kwargs)
            if return_object is not None:
                return return_object
            self._handle_unknown_error(
                method, full_url, headers, data, conn)
            TelemetryService.get_instance().log_http_request_error(
                "HttpRequestUnknownError",
                full_url,
                method,
                SQLSTATE_IO_ERROR,
                ER_FAILED_TO_REQUEST,
                retry_timeout=retry_ctx.total_timeout,
                retry_count=retry_ctx.cnt
            )
            return {}
        except RetryRequest as e:
            if retry_ctx.cnt == TelemetryService.get_instance().num_of_retry_to_trigger_telemetry:
                TelemetryService.get_instance().log_http_request_error(
                    "HttpRequestRetry%dTimes" % retry_ctx.cnt,
                    full_url,
                    method,
                    SQLSTATE_IO_ERROR,
                    ER_FAILED_TO_REQUEST,
                    retry_timeout=retry_ctx.total_timeout,
                    retry_count=retry_ctx.cnt,
                    exception=str(e),
                    stack_trace=traceback.format_exc()
                )
            if no_retry:
                return {}
            cause = e.args[0]
            if retry_ctx.timeout is not None:
                retry_ctx.timeout -= int(time.time() - start_request_thread)
                if retry_ctx.timeout <= 0:
                    logger.error(cause, exc_info=True)
                    TelemetryService.get_instance().log_http_request_error(
                        "HttpRequestRetryTimeout",
                        full_url,
                        method,
                        SQLSTATE_IO_ERROR,
                        ER_FAILED_TO_REQUEST,
                        retry_timeout=retry_ctx.total_timeout,
                        retry_count=retry_ctx.cnt,
                        exception=str(e),
                        stack_trace=traceback.format_exc()
                    )
                    if isinstance(cause, Error):
                        Error.errorhandler_wrapper(conn, None, cause)
                    else:
                        self.handle_invalid_certificate_error(
                            conn, full_url, cause)
                    return {}  # required for tests
            sleeping_time = retry_ctx.next_sleep()
            logger.debug(
                'retrying: errorclass=%s, '
                'error=%s, '
                'counter=%s, '
                'sleeping=%s(s)',
                type(cause),
                cause,
                retry_ctx.cnt + 1,
                sleeping_time)
            time.sleep(sleeping_time)
            retry_ctx.cnt += 1
            if retry_ctx.timeout is not None:
                retry_ctx.timeout -= sleeping_time
            return None  # retry
        except Exception as e:
            if not no_retry:
                raise e
            logger.debug("Ignored error", exc_info=True)
            return {}

    def handle_invalid_certificate_error(self, conn, full_url, cause):
        # all other errors raise exception
        Error.errorhandler_wrapper(
            conn, None, OperationalError,
            {
                'msg': 'Failed to execute request: {}'.format(
                    cause),
                'errno': ER_FAILED_TO_REQUEST,
            })

    def _handle_unknown_error(self, method, full_url, headers, data, conn):
        """Handles unknown errors."""
        if data:
            try:
                decoded_data = json.loads(data)
                if decoded_data.get(
                        'data') and decoded_data['data'].get('PASSWORD'):
                    # masking the password
                    decoded_data['data']['PASSWORD'] = '********'
                    data = json.dumps(decoded_data)
            except Exception:
                logger.info("data is not JSON")
        logger.error(
            'Failed to get the response. Hanging? '
            'method: {method}, url: {url}, headers:{headers}, '
            'data: {data}'.format(
                method=method,
                url=full_url,
                headers=headers,
                data=data,
            )
        )
        Error.errorhandler_wrapper(
            conn, None, OperationalError,
            {
                'msg': 'Failed to get the response. Hanging? '
                        'method: {method}, url: {url}'.format(
                    method=method,
                    url=full_url,
                ),
                'errno': ER_FAILED_TO_REQUEST,
            })

    def _request_exec(
            self,
            session, method, full_url, headers, data,
            token,
            catch_okta_unauthorized_error=False,
            is_raw_text=False,
            is_raw_binary=False,
            binary_data_handler=None,
            socket_timeout=DEFAULT_SOCKET_CONNECT_TIMEOUT):
        if socket_timeout > DEFAULT_SOCKET_CONNECT_TIMEOUT:
            # socket timeout should not be more than the default.
            # A shorter timeout may be specified for login time, but
            # for query, it should be at least 45 seconds.
            socket_timeout = DEFAULT_SOCKET_CONNECT_TIMEOUT
        logger.debug('socket timeout: %s', socket_timeout)
        try:
            if not catch_okta_unauthorized_error and data and len(data) > 0:
                gzdata = BytesIO()
                gzip.GzipFile(fileobj=gzdata, mode='wb').write(
                    data.encode('utf-8'))
                gzdata.seek(0, 0)
                headers['Content-Encoding'] = 'gzip'
                input_data = gzdata
            else:
                input_data = data

            download_start_time = get_time_millis()
            # socket timeout is constant. You should be able to receive
            # the response within the time. If not, ConnectReadTimeout or
            # ReadTimeout is raised.
            raw_ret = session.request(
                method=method,
                url=full_url,
                headers=headers,
                data=input_data,
                timeout=socket_timeout,
                verify=True,
                stream=is_raw_binary,
                auth=SnowflakeAuth(token),
            )
            download_end_time = get_time_millis()

            try:
                if raw_ret.status_code == OK:
                    logger.debug('SUCCESS')
                    if is_raw_text:
                        ret = raw_ret.text
                    elif is_raw_binary:
                        ret = binary_data_handler.to_iterator(raw_ret.raw,
                                                              download_end_time - download_start_time)
                    else:
                        ret = raw_ret.json()
                    return ret

                if is_retryable_http_code(raw_ret.status_code):
                    ex = STATUS_TO_EXCEPTION.get(
                        raw_ret.status_code, OtherHTTPRetryableError)
                    exi = ex(code=raw_ret.status_code)
                    logger.debug('%s. Retrying...', exi)
                    # retryable server exceptions
                    raise RetryRequest(exi)

                elif raw_ret.status_code == UNAUTHORIZED and \
                        catch_okta_unauthorized_error:
                    # OKTA Unauthorized errors
                    Error.errorhandler_wrapper(
                        self._connection, None, DatabaseError,
                        {
                            'msg': ('Failed to get authentication by OKTA: '
                                     '{status}: {reason}').format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason),
                            'errno': ER_FAILED_TO_CONNECT_TO_DB,
                            'sqlstate': SQLSTATE_CONNECTION_REJECTED
                        }
                    )
                    return None  # required for tests
                else:
                    TelemetryService.get_instance().log_http_request_error(
                        "HttpError%s" % str(raw_ret.status_code),
                        full_url,
                        method,
                        SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                        ER_FAILED_TO_REQUEST,
                        response=raw_ret
                    )
                    Error.errorhandler_wrapper(
                        self._connection, None, InterfaceError,
                        {
                            'msg': ("{status} {reason}: "
                                     "{method} {url}").format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason,
                                method=method,
                                url=full_url),
                            'errno': ER_FAILED_TO_REQUEST,
                            'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                        }
                    )
                    return None  # required for tests
            finally:
                raw_ret.close()  # ensure response is closed
        except SSLError as se:
            logger.debug("Hit non-retryable SSL error, %s", str(se))
            TelemetryService.get_instance().log_http_request_error(
                "CertificateException%s" % str(se),
                full_url,
                method,
                SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                ER_FAILED_TO_REQUEST,
                exception=se,
                stack_trace=traceback.format_exc()
            )

        except (ConnectTimeout,
                ReadTimeout,
                BadStatusLine,
                ConnectionError,
                IncompleteRead,
                ProtocolError,  # from urllib3
                ReadTimeoutError,  # from urllib3
                OpenSSL.SSL.SysCallError,
                KeyError,  # SNOW-39175: asn1crypto.keys.PublicKeyInfo
                ValueError,
                RuntimeError,
                AttributeError,  # json decoding error
                ) as err:
            logger.debug(
                "Hit retryable client error. Retrying... Ignore the following "
                "error stack: %s", err,
                exc_info=True)
            raise RetryRequest(err)
        except Exception as err:
            TelemetryService.get_instance().log_http_request_error(
                "HttpException%s" % str(err),
                full_url,
                method,
                SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                ER_FAILED_TO_REQUEST,
                exception=err,
                stack_trace=traceback.format_exc()
            )
            raise err

    def make_requests_session(self):
        s = requests.Session()
        s.mount('http://', ProxySupportAdapter(max_retries=REQUESTS_RETRY))
        s.mount('https://', ProxySupportAdapter(max_retries=REQUESTS_RETRY))
        s._reuse_count = itertools.count()
        return s

    @contextlib.contextmanager
    def _use_requests_session(self):
        """Session caching context manager.

        Notes:
            The session is not closed until close() is called so each session may be used multiple times.
        """
        if self._connection.disable_request_pooling:
            session = self.make_requests_session()
            try:
                yield session
            finally:
                session.close()
        else:
            try:
                session = self._idle_sessions.pop()
            except IndexError:
                session = self.make_requests_session()
            self._active_sessions.add(session)
            logger.debug("Active requests sessions: %s, idle: %s",
                         len(self._active_sessions), len(self._idle_sessions))
            try:
                yield session
            finally:
                self._idle_sessions.appendleft(session)
                try:
                    self._active_sessions.remove(session)
                except KeyError:
                    logger.debug(
                        "session doesn't exist in the active session pool. "
                        "Ignored...")
                logger.debug("Active requests sessions: %s, idle: %s",
                             len(self._active_sessions),
                             len(self._idle_sessions))
