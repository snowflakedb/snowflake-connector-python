#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import collections
import contextlib
import gzip
import itertools
import json
import logging
import platform
import random
import ssl
import sys
import time
import uuid
from io import StringIO, BytesIO
from threading import Lock

import OpenSSL.SSL
from botocore.vendored import requests
from botocore.vendored.requests.adapters import HTTPAdapter
from botocore.vendored.requests.auth import AuthBase
from botocore.vendored.requests.exceptions import (
    ConnectionError, ConnectTimeout, ReadTimeout, SSLError)
from botocore.vendored.requests.packages.urllib3.exceptions import (
    ProtocolError, ReadTimeoutError)
from botocore.vendored.requests.packages.urllib3.exceptions \
    import SSLError as urllib3_SSLError

from . import proxy
from . import ssl_wrap_socket
from .compat import (
    PY2,
    BAD_REQUEST, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT,
    FORBIDDEN, BAD_GATEWAY, REQUEST_TIMEOUT,
    UNAUTHORIZED, INTERNAL_SERVER_ERROR, OK, BadStatusLine)
from .compat import (TO_UNICODE, urlencode)
from .compat import proxy_bypass
from .errorcode import (ER_FAILED_TO_CONNECT_TO_DB, ER_CONNECTION_IS_CLOSED,
                        ER_FAILED_TO_REQUEST, ER_FAILED_TO_RENEW_SESSION,
                        ER_INVALID_CERTIFICATE)
from .errors import (Error, OperationalError, DatabaseError, ProgrammingError,
                     GatewayTimeoutError, ServiceUnavailableError,
                     InterfaceError, InternalServerError, ForbiddenError,
                     BadGatewayError, BadRequest,
                     OtherHTTPRetryableError,
                     ER_MSG_FAILED_TO_VALIDATE_SSL_CERTIFICATE,
                     ER_MSG_FAILED_TO_VALIDATE_SSL_CERTIFICATE_SNOWSQL)
from .gzip_decoder import decompress_raw_data
from .sqlstate import (SQLSTATE_CONNECTION_NOT_EXISTS,
                       SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                       SQLSTATE_CONNECTION_REJECTED)
from .ssl_wrap_socket import (set_proxies)
from .tool.probe_connection import probe_connection
from .util_text import split_rows_from_stream
from .version import VERSION

if PY2:
    from pyasn1.error import PyAsn1Error


logger = logging.getLogger(__name__)

"""
Monkey patch for PyOpenSSL Socket wrapper
"""
ssl_wrap_socket.inject_into_urllib3()

# known applications
APPLICATION_SNOWSQL = u'SnowSQL'

# requests parameters
REQUESTS_RETRY = 1  # requests library builtin retry
DEFAULT_SOCKET_CONNECT_TIMEOUT = 1 * 60  # don't reduce less than 45 seconds

# return codes
QUERY_IN_PROGRESS_CODE = u'333333'  # GS code: the query is in progress
QUERY_IN_PROGRESS_ASYNC_CODE = u'333334'  # GS code: the query is detached
SESSION_EXPIRED_GS_CODE = u'390112'  # GS code: session expired. need to renew

# other constants
CONTENT_TYPE_APPLICATION_JSON = u'application/json'
ACCEPT_TYPE_APPLICATION_SNOWFLAKE = u'application/snowflake'

REQUEST_TYPE_RENEW = u'RENEW'
REQUEST_TYPE_CLONE = u'CLONE'
REQUEST_TYPE_ISSUE = u'ISSUE'

HEADER_AUTHORIZATION_KEY = u"Authorization"
HEADER_SNOWFLAKE_TOKEN = u'Snowflake Token="{token}"'

SNOWFLAKE_CONNECTOR_VERSION = u'.'.join(TO_UNICODE(v) for v in VERSION[0:3])
PYTHON_VERSION = u'.'.join(TO_UNICODE(v) for v in sys.version_info[:3])
OPERATING_SYSTEM = platform.system()
PLATFORM = platform.platform()
IMPLEMENTATION = platform.python_implementation()
COMPILER = platform.python_compiler()

CLIENT_NAME = u"PythonConnector"  # don't change!
CLIENT_VERSION = u'.'.join([TO_UNICODE(v) for v in VERSION[:3]])
PYTHON_CONNECTOR_USER_AGENT = \
    u'{name}/{version}/{python_version}/{platform}'.format(
        name=CLIENT_NAME,
        version=SNOWFLAKE_CONNECTOR_VERSION,
        python_version=PYTHON_VERSION,
        platform=PLATFORM)

NO_TOKEN = u'no-token'

STATUS_TO_EXCEPTION = {
    INTERNAL_SERVER_ERROR: InternalServerError,
    FORBIDDEN: ForbiddenError,
    SERVICE_UNAVAILABLE: ServiceUnavailableError,
    GATEWAY_TIMEOUT: GatewayTimeoutError,
    BAD_REQUEST: BadRequest,
    BAD_GATEWAY: BadGatewayError,
}


def is_retryable_http_code(code):
    """
    Is retryable HTTP code?
    """
    return code >= 500 and code < 600 or code in (
        BAD_REQUEST,  # 400
        FORBIDDEN,  # 403
        REQUEST_TIMEOUT,  # 408
    )


class RetryRequest(Exception):
    """
    Signal to retry request
    """
    pass


class SnowflakeAuth(AuthBase):
    """
    Attaches HTTP Authorization header for Snowflake
    """

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
    """
    Snowflake Restful class
    """

    def __init__(self, host=u'127.0.0.1', port=8080,
                 proxy_host=None,
                 proxy_port=None,
                 proxy_user=None,
                 proxy_password=None,
                 protocol=u'http',
                 inject_client_pause=0,
                 connection=None):
        self._host = host
        self._port = port
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._proxy_user = proxy_user
        self._proxy_password = proxy_password
        self._protocol = protocol
        self._inject_client_pause = inject_client_pause
        self._connection = connection
        self._lock_token = Lock()
        self._idle_sessions = collections.deque()
        self._active_sessions = set()

        # insecure mode (disabled by default)
        ssl_wrap_socket.FEATURE_INSECURE_MODE = \
            self._connection and self._connection._insecure_mode
        # cache file name (enabled by default)
        ssl_wrap_socket.FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = \
            self._connection and self._connection._ocsp_response_cache_filename
        #
        proxy.PROXY_HOST = self._proxy_host
        proxy.PROXY_PORT = self._proxy_port
        proxy.PROXY_USER = self._proxy_user
        proxy.PROXY_PASSWORD = self._proxy_password

        # This is to address the issue where requests hangs
        _ = 'dummy'.encode('idna').decode('utf-8')  # noqa
        proxy_bypass('www.snowflake.net:443')

    @property
    def token(self):
        return self._token if hasattr(self, u'_token') else None

    @property
    def master_token(self):
        return self._master_token if hasattr(self, u'_master_token') else None

    def close(self):
        if hasattr(self, u'_token'):
            del self._token
        if hasattr(self, u'_master_token'):
            del self._master_token
        sessions = list(self._active_sessions)
        if sessions:
            logger.warning("Closing %s active sessions", len(sessions))
        sessions.extend(self._idle_sessions)
        self._active_sessions.clear()
        self._idle_sessions.clear()
        for s in sessions:
            try:
                s.close()
            except Exception as e:
                logger.warning("Session cleanup failed: %s", e)

    def request(self, url, body=None, method=u'post', client=u'sfsql',
                _no_results=False):
        if body is None:
            body = {}
        if self.master_token is None:
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
                timeout=self._connection.network_timeout)
        else:
            return self._get_request(
                url, headers, token=self._token,
                timeout=self._connection.network_timeout)

    def update_tokens(self, session_token, master_token):
        """
        Update session and master tokens
        """
        with self._lock_token:
            self._token = session_token
            self._master_token = master_token

    def _renew_session(self):
        if self.master_token is None:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': u"Connection is closed",
                    u'errno': ER_CONNECTION_IS_CLOSED,
                    u'sqlstate': SQLSTATE_CONNECTION_NOT_EXISTS,
                })

        logger.debug(u'updating session. master_token: %s', self.master_token)
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": CONTENT_TYPE_APPLICATION_JSON,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        request_id = TO_UNICODE(uuid.uuid4())
        logger.debug(u'request_id: %s', request_id)
        url = u'/session/token-request?' + urlencode({
            u'requestId': request_id})

        body = {
            u"oldSessionToken": self._token,
            u"requestType": REQUEST_TYPE_RENEW,
        }
        ret = self._post_request(
            url, headers, json.dumps(body),
            token=self.master_token,
            timeout=self._connection.network_timeout)
        if ret.get(u'success') and u'data' in ret \
                and u'sessionToken' in ret[u'data']:
            logger.debug(u'success: %s', ret)
            self.update_tokens(
                ret[u'data'][u'sessionToken'], ret[u'data'][u'masterToken'])
            logger.debug(u'updating session completed')
            return ret
        else:
            logger.debug(u'failed: %s', ret)
            err = ret.get(u'message')
            if err is not None and ret.get(u'data'):
                err += ret[u'data'].get(u'errorMessage', '')
            Error.errorhandler_wrapper(
                self._connection, None, ProgrammingError,
                {
                    u'msg': err,
                    u'errno': ER_FAILED_TO_RENEW_SESSION,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                })

    def delete_session(self):
        """
        Deletes the session
        """
        if self.master_token is None:
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
                token=self._token, timeout=5, no_retry=True)
            if not ret or ret.get(u'success'):
                return
            err = ret.get(u'message')
            if err is not None and ret.get(u'data'):
                err += ret[u'data'].get(u'errorMessage', '')
                # no exception is raised
            logger.debug('error in deleting session. ignoring...: %s', err)
        except Exception as e:
            logger.debug('error in deleting session. ignoring...: %s', e)

    def _get_request(self, url, headers, token=None,
                     timeout=None,
                     socket_timeout=DEFAULT_SOCKET_CONNECT_TIMEOUT):
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
        ret = self.fetch(u'get', full_url, headers, timeout=timeout,
                         token=token, socket_timeout=socket_timeout)
        if ret.get(u'code') == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            logger.debug(
                u'ret[code] = {code} after renew_session'.format(
                    code=(ret.get(u'code', u'N/A'))))
            if ret.get(u'success'):
                return self._get_request(url, headers, token=self._token)

        return ret

    def _post_request(self, url, headers, body, token=None,
                      timeout=None, _no_results=False, no_retry=False,
                      socket_timeout=DEFAULT_SOCKET_CONNECT_TIMEOUT):
        full_url = u'{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        if self._connection._probe_connection:
            from pprint import pprint
            ret = probe_connection(full_url)
            pprint(ret)

        ret = self.fetch(u'post', full_url, headers, data=body,
                         timeout=timeout, token=token,
                         no_retry=no_retry, socket_timeout=socket_timeout)
        logger.debug(
            u'ret[code] = {code}, after post request'.format(
                code=(ret.get(u'code', u'N/A'))))

        if ret.get(u'code') == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            logger.debug(
                u'ret[code] = {code} after renew_session'.format(
                    code=(ret.get(u'code'u'N/A'))))
            if ret.get(u'success'):
                return self._post_request(
                    url, headers, body, token=self._token, timeout=timeout)

        if ret.get(u'code') == QUERY_IN_PROGRESS_ASYNC_CODE and _no_results:
            return ret

        while ret.get(u'code') in \
                (QUERY_IN_PROGRESS_CODE, QUERY_IN_PROGRESS_ASYNC_CODE):
            if self._inject_client_pause > 0:
                logger.debug(
                    u'waiting for {inject_client_pause}...'.format(
                        inject_client_pause=self._inject_client_pause))
                time.sleep(self._inject_client_pause)
            # ping pong
            result_url = ret[u'data'][u'getResultUrl']
            logger.debug(u'ping pong starting...')
            ret = self._get_request(
                result_url, headers, token=self._token, timeout=timeout)
            logger.debug(u'ret[code] = %s', ret.get(u'code', u'N/A'))
            logger.debug(u'ping pong done')

        return ret

    def fetch(self, method, full_url, headers, data=None, timeout=None,
              **kwargs):
        """ Curried API request with session management. """

        class DecorrelateJitterBackoff(object):
            # Decorrelate Jitter backoff
            # see:
            # https://www.awsarchitectureblog.com/2015/03/backoff.html
            def __init__(self, base, cap):
                self._base = base
                self._cap = cap

            def next_sleep(self, _, sleep):
                return min(self._cap, random.randint(self._base, sleep * 3))

        class RetryCtx(object):
            def __init__(self, timeout):
                self.timeout = timeout
                self.cnt = 0
                self.sleeping_time = 1
                # backoff between 1 and 16 seconds
                self._backoff = DecorrelateJitterBackoff(1, 16)

            def next_sleep(self):
                self.sleeping_time = self._backoff.next_sleep(
                    self.cnt, self.sleeping_time)
                return self.sleeping_time

        with self._use_requests_session() as session:
            retry_ctx = RetryCtx(timeout)
            while True:
                ret = self._request_exec_wrapper(
                    session, method, full_url, headers, data, retry_ctx,
                    **kwargs)
                if ret is not None:
                    return ret

    def _request_exec_wrapper(
            self,
            session, method, full_url, headers, data, retry_ctx,
            no_retry=False, token=NO_TOKEN,
            **kwargs):

        conn = self._connection
        proxies = set_proxies(self._proxy_host, self._proxy_port,
                              self._proxy_user, self._proxy_password)
        logger.debug('remaining request timeout: %s, retry cnt: %s',
                     retry_ctx.timeout, retry_ctx.cnt + 1)

        start_request_thread = time.time()
        try:
            return_object = self._request_exec(
                session=session,
                method=method,
                full_url=full_url,
                headers=headers,
                data=data,
                proxies=proxies,
                token=token,
                **kwargs)
            if return_object is not None:
                return return_object
            self._handle_unknown_error(
                method, full_url, headers, data, conn, proxies)
            return {}
        except RetryRequest as e:
            if no_retry:
                return {}
            cause = e.args[0]
            if retry_ctx.timeout is not None:
                retry_ctx.timeout -= int(time.time() - start_request_thread)
                if retry_ctx.timeout <= 0:
                    logger.error(cause, exc_info=True)
                    if isinstance(cause, Error):
                        Error.errorhandler_wrapper(conn, None, cause)
                    else:
                        self.handle_invalid_certificate_error(
                            conn, full_url, cause)
                    return {}  # required for tests
            sleeping_time = retry_ctx.next_sleep()
            logger.debug(
                u'retrying: errorclass=%s, '
                u'error=%s, '
                u'counter=%s, '
                u'sleeping=%s(s)',
                type(cause),
                cause,
                retry_ctx.cnt + 1,
                sleeping_time)
            time.sleep(sleeping_time)
            if retry_ctx.timeout is not None:
                retry_ctx.timeout -= sleeping_time
                retry_ctx.cnt += 1
            return None  # retry
        except Exception as e:
            if not no_retry:
                raise e
            logger.debug("Ignored error", exc_info=True)
            return {}

    def handle_invalid_certificate_error(self, conn, full_url, cause):
        # checking if the cause is SSL certificate error
        if isinstance(cause, SSLError):
            if isinstance(cause.args[0], urllib3_SSLError):
                if isinstance(
                        cause.args[0].args[0], ssl.SSLError):
                    err = cause.args[0].args[0].args[0]
                    if u'bad handshake' in err and \
                            u'certificate verify failed' in err:
                        if conn.application == APPLICATION_SNOWSQL:
                            # SnowSQL has an option to probe connection.
                            msg = \
                                ER_MSG_FAILED_TO_VALIDATE_SSL_CERTIFICATE_SNOWSQL
                        else:
                            msg = ER_MSG_FAILED_TO_VALIDATE_SSL_CERTIFICATE
                        Error.errorhandler_wrapper(
                            conn, None, OperationalError,
                            {
                                u'errno': ER_INVALID_CERTIFICATE,
                                u'msg': msg.format(full_url),
                                u'error': ER_FAILED_TO_REQUEST,
                            }
                        )
                        return  # required for tests
        # all other errors raise exception
        Error.errorhandler_wrapper(
            conn, None, OperationalError,
            {
                u'msg': u'Failed to execute request: {0}'.format(
                    cause),
                u'errno': ER_FAILED_TO_REQUEST,
            })

    def _handle_unknown_error(
            self, method, full_url, headers, data, conn, proxies):
        """
        Handle unknown error
        """
        if data:
            try:
                decoded_data = json.loads(data)
                if decoded_data.get(
                        'data') and decoded_data['data'].get('PASSWORD'):
                    # masking the password
                    decoded_data['data']['PASSWORD'] = '********'
                    data = json.dumps(decoded_data)
            except:
                logger.info("data is not JSON")
        logger.error(
            u'Failed to get the response. Hanging? '
            u'method: {method}, url: {url}, headers:{headers}, '
            u'data: {data}, proxies: {proxies}'.format(
                method=method,
                url=full_url,
                headers=headers,
                data=data,
                proxies=proxies
            )
        )
        Error.errorhandler_wrapper(
            conn, None, OperationalError,
            {
                u'msg': u'Failed to get the response. Hanging? '
                        u'method: {method}, url: {url}, '
                        u'proxies: {proxies}'.format(
                    method=method,
                    url=full_url,
                    proxies=proxies
                ),
                u'errno': ER_FAILED_TO_REQUEST,
            })

    def _request_exec(
            self,
            session, method, full_url, headers, data,
            proxies,
            token,
            catch_okta_unauthorized_error=False,
            is_raw_text=False,
            is_raw_binary=False,
            is_raw_binary_iterator=True,
            use_ijson=False,
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
                gzip.GzipFile(fileobj=gzdata, mode=u'wb').write(
                    data.encode(u'utf-8'))
                gzdata.seek(0, 0)
                headers['Content-Encoding'] = 'gzip'
                input_data = gzdata
            else:
                input_data = data

            # socket timeout is constant. You should be able to receive
            # the response within the time. If not, ConnectReadTimeout or
            # ReadTimeout is raised.
            raw_ret = session.request(
                method=method,
                url=full_url,
                proxies=proxies,
                headers=headers,
                data=input_data,
                timeout=socket_timeout,
                verify=True,
                stream=is_raw_binary,
                auth=SnowflakeAuth(token),
            )
            try:
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
                    return ret

                if is_retryable_http_code(
                        raw_ret.status_code):
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
                            u'msg': (u'Failed to get authentication by OKTA: '
                                     u'{status}: {reason}').format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason),
                            u'errno': ER_FAILED_TO_CONNECT_TO_DB,
                            u'sqlstate': SQLSTATE_CONNECTION_REJECTED
                        }
                    )
                    return None  # required for tests
                else:
                    Error.errorhandler_wrapper(
                        self._connection, None, InterfaceError,
                        {
                            u'msg': (u"{status} {reason}: "
                                     u"{method} {url}").format(
                                status=raw_ret.status_code,
                                reason=raw_ret.reason,
                                method=method,
                                url=full_url),
                            u'errno': ER_FAILED_TO_REQUEST,
                            u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                        }
                    )
                    return None  # required for tests
            finally:
                raw_ret.close()  # ensure response is closed
        except (ConnectTimeout,
                ReadTimeout,
                BadStatusLine,
                ConnectionError,
                SSLError,
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
            if PY2 and isinstance(err, PyAsn1Error):
                logger.debug(
                    "Hit retryable client error. Retrying... "
                    "Ignore the following error stack: %s", err,
                    exc_info=True)
                raise RetryRequest(err)
            raise err

    def make_requests_session(self):
        s = requests.Session()
        s.mount(u'http://', HTTPAdapter(max_retries=REQUESTS_RETRY))
        s.mount(u'https://', HTTPAdapter(max_retries=REQUESTS_RETRY))
        s._reuse_count = itertools.count()
        return s

    @contextlib.contextmanager
    def _use_requests_session(self):
        """ Session caching context manager.  Note that the session is not
        closed until close() is called so each session may be used multiple
        times. """
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
                         len(self._active_sessions), len(self._idle_sessions))
