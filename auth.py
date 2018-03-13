#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import copy
import json
import logging
import uuid
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
                      IMPLEMENTATION, COMPILER)
from .sqlstate import (SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED)
from .version import VERSION

logger = logging.getLogger(__name__)

DEFAULT_AUTHENTICATOR = u'SNOWFLAKE'  # default authenticator name
EXTERNAL_BROWSER_AUTHENTICATOR = u'EXTERNALBROWSER'
KEY_PAIR_AUTHENTICATOR = u'SNOWFLAKE_JWT'
OAUTH_AUTHENTICATOR = u'OAUTH'


class AuthByExternalService(object):
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
        """ Handles a failure when connecting to Snowflake to
        get the SSO Url.

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

    def authenticate(self, auth_instance, account, user, password,
                     database=None, schema=None,
                     warehouse=None, role=None, passcode=None,
                     passcode_in_password=False,
                     mfa_callback=None, password_callback=None,
                     session_parameters=None, timeout=120):
        logger.debug(u'authenticate')

        if self._rest.token and self._rest.master_token:
            logger.debug(
                u'token is already set. no further authentication was done.')
            return

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
        if auth_instance is not None:
            # external authenticator may update the request body
            logger.debug(u'assertion content: %s',
                         auth_instance.assertion_content)
            auth_instance.update_body(body)
        elif password:
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
                timeout=self._rest._connection._login_timeout,
                socket_timeout=self._rest._connection._login_timeout)
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
                    timeout=self._rest._connection._login_timeout)

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
                    timeout=self._rest._connection._login_timeout,
                    socket_timeout=self._rest._connection._login_timeout)
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
                return  # required for unit test

        elif ret[u'data'].get(u'nextAction') == u'PWD_CHANGE':
            if callable(password_callback):
                body = copy.deepcopy(body_template)
                body[u'inFlightCtx'] = ret[u'data'][u'inFlightCtx']
                body[u'data'][u"LOGIN_NAME"] = user
                body[u'data'][u"PASSWORD"] = password
                body[u'data'][u'CHOSEN_NEW_PASSWORD'] = password_callback()
                # New Password input
                ret = self._rest._post_request(
                    url, headers, json.dumps(body),
                    timeout=self._rest._connection._login_timeout,
                    socket_timeout=self._rest._connection._login_timeout)

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
                         '******' if ret[u'data'][u'masterToken'] is not None else
                         'NULL')
            self._rest.update_tokens(
                ret[u'data'][u'token'], ret[u'data'][u'masterToken'])
            if u'sessionId' in ret[u'data']:
                self._rest._connection._session_id = ret[u'data'][u'sessionId']
            if u'sessionInfo' in ret[u'data']:
                session_info = ret[u'data'][u'sessionInfo']
                self._validate_default_database(session_info)
                self._validate_default_schema(session_info)
                self._validate_default_role(session_info)
                self._validate_default_warehouse(session_info)
            if u'parameters' in ret[u'data']:
                with self._rest._connection._lock_converter:
                    self._rest._connection.converter.set_parameters(
                        ret[u'data'][u'parameters'])

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
