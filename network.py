#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import collections
import contextlib
import copy
import gzip
import itertools
import json
import logging
import platform
import sys
import time
import uuid
from io import StringIO, BytesIO
from threading import Thread

import OpenSSL
from botocore.vendored import requests
from botocore.vendored.requests.adapters import HTTPAdapter
from botocore.vendored.requests.auth import AuthBase
from botocore.vendored.requests.exceptions import (ConnectionError, SSLError)
from botocore.vendored.requests.packages.urllib3.exceptions import (
    ProtocolError)

from . import ssl_wrap_socket
from .compat import (
    BAD_REQUEST, SERVICE_UNAVAILABLE, GATEWAY_TIMEOUT,
    FORBIDDEN, BAD_GATEWAY,
    UNAUTHORIZED, INTERNAL_SERVER_ERROR, OK, BadStatusLine,
    urlsplit, unescape)
from .compat import (Queue, EmptyQueue)
from .compat import (TO_UNICODE, urlencode)
from .compat import proxy_bypass
from .errorcode import (ER_FAILED_TO_CONNECT_TO_DB, ER_CONNECTION_IS_CLOSED,
                        ER_FAILED_TO_REQUEST, ER_FAILED_TO_RENEW_SESSION,
                        ER_FAILED_TO_SERVER, ER_IDP_CONNECTION_ERROR,
                        ER_INCORRECT_DESTINATION)
from .errors import (Error, OperationalError, DatabaseError, ProgrammingError,
                     GatewayTimeoutError, ServiceUnavailableError,
                     InterfaceError, InternalServerError, ForbiddenError,
                     BadGatewayError, BadRequest)
from .gzip_decoder import decompress_raw_data
from .sqlstate import (SQLSTATE_CONNECTION_NOT_EXISTS,
                       SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
                       SQLSTATE_CONNECTION_REJECTED)
from .ssl_wrap_socket import set_proxies
from .util_text import split_rows_from_stream
from .version import VERSION

logger = logging.getLogger(__name__)

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


def _is_prefix_equal(url1, url2):
    """
    Checks if URL prefixes are identical. The scheme, hostname and port number
    are compared. If the port number is not specified and the scheme is https,
    the port number is assumed to be 443.
    """
    parsed_url1 = urlsplit(url1)
    parsed_url2 = urlsplit(url2)

    port1 = parsed_url1.port
    if not port1 and parsed_url1.scheme == 'https':
        port1 = '443'
    port2 = parsed_url1.port
    if not port2 and parsed_url2.scheme == 'https':
        port2 = '443'

    return parsed_url1.hostname == parsed_url2.hostname and \
           port1 == port2 and \
           parsed_url1.scheme == parsed_url2.scheme


def _get_post_back_url_from_html(html):
    """
    Gets the post back URL.

    Since the HTML is not well formed, minidom cannot be used to convert to
    DOM. The first discovered form is assumed to be the form to post back
    and the URL is taken from action attributes.
    """
    logger.debug(html)

    idx = html.find('<form')
    start_idx = html.find('action="', idx)
    end_idx = html.find('"', start_idx + 8)
    return unescape(html[start_idx + 8:end_idx])


class RequestRetry(Exception):
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
                 connect_timeout=DEFAULT_CONNECT_TIMEOUT,
                 request_timeout=DEFAULT_REQUEST_TIMEOUT,
                 injectClientPause=0,
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
        self._injectClientPause = injectClientPause
        self._connection = connection
        self._idle_sessions = collections.deque()
        self._active_sessions = set()
        self._request_count = itertools.count()

        # insecure mode (disabled by default)
        ssl_wrap_socket.FEATURE_INSECURE_MODE = \
            self._connection and self._connection._insecure_mode
        # cache file name (enabled by default)
        ssl_wrap_socket.FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME = \
            self._connection and self._connection._ocsp_response_cache_filename
        #
        ssl_wrap_socket.PROXY_HOST = self._proxy_host
        ssl_wrap_socket.PROXY_PORT = self._proxy_port
        ssl_wrap_socket.PROXY_USER = self._proxy_user
        ssl_wrap_socket.PROXY_PASSWORD = self._proxy_password

        # This is to address the issue where requests hangs
        _ = 'dummy'.encode('idna').decode('utf-8')
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
            logger.warn("Closing %s active sessions", len(sessions))
        sessions.extend(self._idle_sessions)
        self._active_sessions.clear()
        self._idle_sessions.clear()
        for s in sessions:
            try:
                s.close()
            except Exception as e:
                logger.warn("Session cleanup failed: %s", e)

    def authenticate(self, account, user, password, master_token=None,
                     token=None, database=None, schema=None,
                     warehouse=None, role=None, passcode=None,
                     passcode_in_password=False, saml_response=None,
                     mfa_callback=None, password_callback=None,
                     session_parameters=None):
        logger.debug(u'authenticate')

        if token and master_token:
            self._token = token
            self._master_token = token
            logger.debug(u'token is given. no authentication was done')
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
        logger.debug(u'saml: %s', saml_response is not None)
        if saml_response:
            body[u'data'][u'RAW_SAML_RESPONSE'] = saml_response
        else:
            body[u'data'][u"LOGIN_NAME"] = user
            body[u'data'][u"PASSWORD"] = password

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

        logger.debug(
            "body['data']: %s",
            {k: v for (k, v) in body[u'data'].items() if k != u'PASSWORD'})

        try:
            ret = self._post_request(
                url, headers, json.dumps(body),
                timeout=self._connection._login_timeout)
        except ForbiddenError as err:
            # HTTP 403
            raise err.__class__(
                msg=(u"Failed to connect to DB. "
                     u"Verify the account name is correct: {host}:{port}, "
                     u"proxies={proxy_host}:{proxy_port}, "
                     u"proxy_user={proxy_user}. {message}").format(
                    host=self._host,
                    port=self._port,
                    proxy_host=self._proxy_host,
                    proxy_port=self._proxy_port,
                    proxy_user=self._proxy_user,
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
                    host=self._host,
                    port=self._port,
                    proxy_host=self._proxy_host,
                    proxy_port=self._proxy_port,
                    proxy_user=self._proxy_user,
                    message=TO_UNICODE(err)
                ),
                errno=ER_FAILED_TO_CONNECT_TO_DB,
                sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)

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

        logger.debug(u'completed authentication')
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
            logger.debug(u'token = %s', self._token)
            logger.debug(u'master_token = %s', self._master_token)
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

        logger.debug(u'updating session')
        logger.debug(u'master_token: %s', self._master_token)
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
        self._session = None  # invalidate session object
        ret = self._post_request(
            url, headers, json.dumps(body),
            token=self._master_token,
            timeout=self._connection._network_timeout)
        if ret[u'success'] and u'data' in ret \
                and u'sessionToken' in ret[u'data']:
            logger.debug(u'success: %s', ret)
            self._token = ret[u'data'][u'sessionToken']
            self._master_token = ret[u'data'][u'masterToken']
            logger.debug(u'updating session completed')
            return ret
        else:
            logger.debug(u'failed: %s', ret)
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
        except Exception as e:
            logger.debug('error in deleting session. ignoring...: %s', e)

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
        ret = self.fetch(u'get', full_url, headers, timeout=timeout,
                         token=token)
        if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            logger.debug(
                u'ret[code] = {code} after renew_session'.format(
                    code=(ret[u'code'] if u'code' in ret else u'N/A')))
            if u'success' in ret and ret[u'success']:
                return self._get_request(url, headers, token=self._token)

        return ret

    def _post_request(self, url, headers, body, token=None,
                      timeout=None, _no_results=False, is_single_thread=False):
        full_url = u'{protocol}://{host}:{port}{url}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
            url=url,
        )
        ret = self.fetch(u'post', full_url, headers, data=body,
                         timeout=timeout, token=token,
                         is_single_thread=is_single_thread)
        logger.debug(
            u'ret[code] = {code}, after post request'.format(
                code=(ret.get(u'code', u'N/A'))))

        if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
            ret = self._renew_session()
            logger.debug(
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
                logger.debug(
                    u'waiting for {inject_client_pause}...'.format(
                        inject_client_pause=self._injectClientPause))
                time.sleep(self._injectClientPause)
            # ping pong
            result_url = ret[u'data'][
                u'getResultUrl'] if not is_session_renewed else result_url
            logger.debug(u'ping pong starting...')
            ret = self._get_request(
                result_url, headers, token=self._token, timeout=timeout)
            logger.debug(
                u'ret[code] = %s',
                ret[u'code'] if u'code' in ret else u'N/A')
            logger.debug(u'ping pong done')
            if u'code' in ret and ret[u'code'] == SESSION_EXPIRED_GS_CODE:
                ret = self._renew_session()
                logger.debug(
                    u'ret[code] = %s after renew_session',
                    ret[u'code'] if u'code' in ret else u'N/A')
                if u'success' in ret and ret[u'success']:
                    is_session_renewed = True
            else:
                is_session_renewed = False

        return ret

    def fetch(self, method, full_url, headers, data=None, timeout=None,
              **kwargs):
        """ Curried API request with session management. """
        if timeout is not None and 'timeouts' in kwargs:
            raise TypeError("Mutually exclusive args: timeout, timeouts")
        if timeout is None:
            timeout = self._request_timeout
        timeouts = kwargs.pop('timeouts', (self._connect_timeout,
                                           self._connect_timeout, timeout))
        proxies = set_proxies(self._proxy_host, self._proxy_port,
                              self._proxy_user, self._proxy_password)
        with self._use_requests_session() as session:
            return self._fetch(session, method, full_url, headers, data,
                               proxies, timeouts, **kwargs)

    def _fetch(self, session, method, full_url, headers, data, proxies,
               timeouts=(DEFAULT_CONNECT_TIMEOUT, DEFAULT_CONNECT_TIMEOUT,
                         DEFAULT_REQUEST_TIMEOUT),
               token=NO_TOKEN,
               is_raw_text=False,
               catch_okta_unauthorized_error=False,
               is_raw_binary=False,
               is_raw_binary_iterator=True,
               use_ijson=False, is_single_thread=False):
        """ This is the lowest level of HTTP handling.  All arguments culminate
        here and the `requests.request` is issued and monitored from this
        call using an inline thread for timeout monitoring. """
        connection_timeout = timeouts[0:2]
        request_timeout = timeouts[2]  # total request timeout
        request_exec_timeout = 60  # one request thread timeout
        conn = self._connection
        proxies = set_proxies(conn.rest._proxy_host, conn.rest._proxy_port,
                              conn.rest._proxy_user, conn.rest._proxy_password)

        def request_exec(result_queue):
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

                raw_ret = session.request(
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
                    OpenSSL.SSL.SysCallError,
                    ValueError,
                    RuntimeError) as err:
                logger.exception('who is hitting error?')
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
                    # no full_url is required in the message
                    # as err includes all information
                    msg=u'Failed to connect: {0}'.format(err),
                    errno=ER_FAILED_TO_SERVER,
                    sqlstate=SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                ), False))

        if is_single_thread:
            # This is dedicated code for DELETE SESSION when Python exists.
            request_result_queue = Queue()
            request_exec(request_result_queue)
            try:
                # don't care about the return value, because no retry and
                # no error will show up
                _, _ = request_result_queue.get(timeout=request_timeout)
            except:
                pass
            return {}

        retry_cnt = 0
        while True:
            return_object = None
            request_result_queue = Queue()
            th = Thread(name='RequestExec-%d' % next(self._request_count),
                        target=request_exec, args=(request_result_queue,))
            th.daemon = True
            th.start()
            try:
                logger.debug('request thread timeout: %s, '
                             'rest of request timeout: %s, '
                             'retry cnt: %s',
                             request_exec_timeout,
                             request_timeout,
                             retry_cnt + 1)
                start_request_thread = time.time()
                th.join(timeout=request_exec_timeout)
                logger.debug('request thread joined')
                if request_timeout is not None:
                    request_timeout -= min(
                        int(time.time() - start_request_thread),
                        request_timeout)
                start_get_queue = time.time()
                return_object, retryable = request_result_queue.get(
                    timeout=int(request_exec_timeout / 4))
                if request_timeout is not None:
                    request_timeout -= min(
                        int(time.time() - start_get_queue), request_timeout)
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

        if return_object is None:
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
        return return_object

    def make_requests_session(self):
        s = requests.Session()
        s.mount(u'http://', HTTPAdapter(max_retries=REQUESTS_RETRY))
        s.mount(u'https://', HTTPAdapter(max_retries=REQUESTS_RETRY))
        s._reuse_count = itertools.count()
        return s

    def authenticate_by_saml(self, authenticator, account, user, password):
        u"""
        SAML Authentication
        1.  query GS to obtain IDP token and SSO url
        2.  IMPORTANT Client side validation:
            validate both token url and sso url contains same prefix
            (protocol + host + port) as the given authenticator url.
            Explanation:
            This provides a way for the user to 'authenticate' the IDP it is
            sending his/her credentials to.  Without such a check, the user could
            be coerced to provide credentials to an IDP impersonator.
        3.  query IDP token url to authenticate and retrieve access token
        4.  given access token, query IDP URL snowflake app to get SAML response
        5.  IMPORTANT Client side validation:
            validate the post back url come back with the SAML response
            contains the same prefix as the Snowflake's server url, which is the
            intended destination url to Snowflake.
        Explanation:
            This emulates the behavior of IDP initiated login flow in the user
            browser where the IDP instructs the browser to POST the SAML
            assertion to the specific SP endpoint.  This is critical in
            preventing a SAML assertion issued to one SP from being sent to
            another SP.
        """
        logger.info(u'authenticating by SAML')
        logger.debug(u'step 1: query GS to obtain IDP token and SSO url')
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

        logger.debug(
            u'account=%s, authenticator=%s',
            account, authenticator,
        )

        ret = self._post_request(
            url, headers, json.dumps(body),
            timeout=self._connection._login_timeout)

        if not ret[u'success']:
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': (u"Failed to connect to DB: {host}:{port}, "
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

        logger.debug(u'step 2: validate Token and SSO URL has the same prefix '
                     u'as authenticator')
        if not _is_prefix_equal(authenticator, token_url) or \
                not _is_prefix_equal(authenticator, sso_url):
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': (u"The specified authenticator is not supported: "
                             u"{authenticator}, token_url: {token_url}, "
                             u"sso_url: {sso_url}".format(
                        authenticator=authenticator,
                        token_url=token_url,
                        sso_url=sso_url,
                    )),
                    u'errno': ER_IDP_CONNECTION_ERROR,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                }
            )

        logger.debug(u'step 3: query IDP token url to authenticate and '
                     u'retrieve access token')
        data = {
            u'username': user,
            u'password': password,
        }
        ret = self.fetch(u'post', token_url, headers, data=json.dumps(data),
                         timeout=self._connection._login_timeout,
                         catch_okta_unauthorized_error=True)
        one_time_token = ret[u'cookieToken']

        logger.debug(u'step 4: query IDP URL snowflake app to get SAML '
                     u'response')
        url_parameters = {
            u'RelayState': u"/some/deep/link",
            u'onetimetoken': one_time_token,
        }
        sso_url = sso_url + u'?' + urlencode(url_parameters)

        headers = {
            u"Accept": u'*/*',
        }
        response_html = self.fetch(u'get', sso_url, headers,
                                   timeout=self._connection._login_timeout,
                                   is_raw_text=True)

        logger.debug(u'step 5: validate post_back_url matches Snowflake URL')
        post_back_url = _get_post_back_url_from_html(response_html)
        full_url = u'{protocol}://{host}:{port}'.format(
            protocol=self._protocol,
            host=self._host,
            port=self._port,
        )
        if not _is_prefix_equal(post_back_url, full_url):
            Error.errorhandler_wrapper(
                self._connection, None, DatabaseError,
                {
                    u'msg': (u"The specified authenticator and destination "
                             u"URL in the SAML assertion do not match: "
                             u"expected: {url}, "
                             u"post back: {post_back_url}".format(
                        url=full_url,
                        post_back_url=post_back_url,
                    )),
                    u'errno': ER_INCORRECT_DESTINATION,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                }
            )
        return response_html

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
