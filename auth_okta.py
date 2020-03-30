#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#
import json
import logging

from .auth import Auth
from .auth_by_plugin import AuthByPlugin
from .compat import unescape, urlencode, urlsplit
from .constants import HTTP_HEADER_ACCEPT, HTTP_HEADER_CONTENT_TYPE, \
    HTTP_HEADER_SERVICE_NAME, HTTP_HEADER_USER_AGENT
from .errorcode import ER_IDP_CONNECTION_ERROR, ER_INCORRECT_DESTINATION
from .errors import DatabaseError, Error
from .network import CONTENT_TYPE_APPLICATION_JSON, PYTHON_CONNECTOR_USER_AGENT
from .sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED

logger = logging.getLogger(__name__)


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


class AuthByOkta(AuthByPlugin):
    """
    Authenticate user by OKTA
    """

    def __init__(self, rest, application):
        self._rest = rest
        self._saml_response = None
        self._application = application

    @property
    def assertion_content(self):
        return self._saml_response

    def update_body(self, body):
        body[u'data'][u'RAW_SAML_RESPONSE'] = self._saml_response

    def authenticate(
            self, authenticator, service_name, account, user, password):
        """
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
        logger.debug(u'authenticating by SAML')
        headers, sso_url, token_url = self._step1(
            authenticator, service_name, account, user)
        self._step2(authenticator, sso_url, token_url)
        one_time_token = self._step3(headers, token_url, user, password)
        response_html = self._step4(one_time_token, sso_url)
        self._step5(response_html)

    def _step1(self, authenticator, service_name, account, user):
        logger.debug(u'step 1: query GS to obtain IDP token and SSO url')

        headers = {
            HTTP_HEADER_CONTENT_TYPE: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_ACCEPT: CONTENT_TYPE_APPLICATION_JSON,
            HTTP_HEADER_USER_AGENT: PYTHON_CONNECTOR_USER_AGENT,
        }
        if service_name:
            headers[HTTP_HEADER_SERVICE_NAME] = service_name
        url = u"/session/authenticator-request"
        body = Auth.base_auth_data(
            user, account,
            self._rest._connection.application,
            self._rest._connection._internal_application_name,
            self._rest._connection._internal_application_version,
            self._rest._connection._ocsp_mode(),
            self._rest._connection._login_timeout,
            self._rest._connection._network_timeout,
        )

        body[u"data"][u"AUTHENTICATOR"] = authenticator
        logger.debug(
            u'account=%s, authenticator=%s',
            account, authenticator,
        )
        ret = self._rest._post_request(
            url, headers, json.dumps(body),
            timeout=self._rest._connection.login_timeout,
            socket_timeout=self._rest._connection.login_timeout)

        if not ret[u'success']:
            self.handle_failure(ret)

        data = ret[u'data']
        token_url = data[u'tokenUrl']
        sso_url = data[u'ssoUrl']
        return headers, sso_url, token_url

    def _step2(self, authenticator, sso_url, token_url):
        logger.debug(u'step 2: validate Token and SSO URL has the same prefix '
                     u'as authenticator')
        if not _is_prefix_equal(authenticator, token_url) or \
                not _is_prefix_equal(authenticator, sso_url):
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
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

    def _step3(self, headers, token_url, user, password):
        logger.debug(u'step 3: query IDP token url to authenticate and '
                     u'retrieve access token')
        data = {
            u'username': user,
            u'password': password,
        }
        ret = self._rest.fetch(
            u'post', token_url, headers,
            data=json.dumps(data),
            timeout=self._rest._connection.login_timeout,
            socket_timeout=self._rest._connection.login_timeout,
            catch_okta_unauthorized_error=True)
        one_time_token = ret.get(u'cookieToken')
        if not one_time_token:
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
                {
                    u'msg': (u"The authentication failed for {user} "
                             u"by {token_url}.".format(
                        token_url=token_url,
                        user=user,
                    )),
                    u'errno': ER_IDP_CONNECTION_ERROR,
                    u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED
                }
            )
        return one_time_token

    def _step4(self, one_time_token, sso_url):
        logger.debug(u'step 4: query IDP URL snowflake app to get SAML '
                     u'response')
        url_parameters = {
            u'RelayState': u"/some/deep/link",
            u'onetimetoken': one_time_token,
        }
        sso_url = sso_url + u'?' + urlencode(url_parameters)
        headers = {
            HTTP_HEADER_ACCEPT: u'*/*',
        }
        response_html = self._rest.fetch(
            u'get', sso_url, headers,
            timeout=self._rest._connection.login_timeout,
            socket_timeout=self._rest._connection.login_timeout,
            is_raw_text=True)
        return response_html

    def _step5(self, response_html):
        logger.debug(u'step 5: validate post_back_url matches Snowflake URL')
        post_back_url = _get_post_back_url_from_html(response_html)
        full_url = u'{protocol}://{host}:{port}'.format(
            protocol=self._rest._protocol,
            host=self._rest._host,
            port=self._rest._port,
        )
        if not _is_prefix_equal(post_back_url, full_url):
            Error.errorhandler_wrapper(
                self._rest._connection, None, DatabaseError,
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
        self._saml_response = response_html
