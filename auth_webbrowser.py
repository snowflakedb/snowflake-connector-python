#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import json
import logging
import socket
import webbrowser

from .auth import Auth, AuthByExternalService, EXTERNAL_BROWSER_AUTHENTICATOR
from .compat import (unquote)
from .errorcode import (ER_UNABLE_TO_OPEN_BROWSER, ER_IDP_CONNECTION_ERROR)
from .network import (CONTENT_TYPE_APPLICATION_JSON,
                      PYTHON_CONNECTOR_USER_AGENT)

logger = logging.getLogger(__name__)

BUF_SIZE = 16384


# global state of web server that receives the SAML assertion from
# Snowflake server


class AuthByWebBrowser(AuthByExternalService):
    """
    Authenticate user by web browser. Only used for SAML based
    authentication.
    """

    def __init__(self, rest, application,
                 webbrowser_pkg=None, socket_pkg=None):
        self._rest = rest
        self._token = None
        self._application = application
        self._proof_key = None
        self._webbrowser = webbrowser if webbrowser_pkg is None else webbrowser_pkg
        self._socket = socket.socket if socket_pkg is None else socket_pkg

    @property
    def assertion_content(self):
        """ Returns the token."""
        return self._token

    def update_body(self, body):
        """ Used by Auth to update the request that gets sent to
        /v1/login-request.

        Args:
            body: existing request dictionary
        """
        body[u'data'][u'AUTHENTICATOR'] = EXTERNAL_BROWSER_AUTHENTICATOR
        body[u'data'][u'TOKEN'] = self._token
        body[u'data'][u'PROOF_KEY'] = self._proof_key

    def authenticate(self, authenticator, account, user, password):
        """
        Web Browser based Authentication.
        """
        logger.info(u'authenticating by Web Browser')

        # ignore password. user is still needed by GS to verify
        # the assertion.
        _ = password  # noqa: F841

        socket_connection = self._socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket_connection.bind(('localhost', 0))
            socket_connection.listen(0)  # no backlog
            callback_port = socket_connection.getsockname()[1]

            print("Initiating login request with your identity provider. A "
                  "browser window should have opened for you to complete the "
                  "login. If you can't see it, check existing browser windows, "
                  "or your OS settings. Press CTRL+C to abort and try again...")

            logger.debug(u'step 1: query GS to obtain SSO url')
            sso_url = self._get_sso_url(
                account, authenticator, callback_port, user)

            logger.debug(u'step 2: open a browser')
            if not self._webbrowser.open_new(sso_url):
                logger.error(
                    u'Unable to open a browser in this environment.',
                    exc_info=True)
                self.handle_failure({
                    u'code': ER_UNABLE_TO_OPEN_BROWSER,
                    u'message': u"Unable to open a browser in this environment."
                })
                return  # required for test case

            logger.debug(u'step 3: accept SAML token')
            self._receive_saml_token(socket_connection)
        finally:
            socket_connection.close()

    def _receive_saml_token(self, socket_connection):
        """
        Receives SAML token from web browser
        """
        socket_client, _ = socket_connection.accept()
        try:
            # Receive the data in small chunks and retransmit it
            data = socket_client.recv(BUF_SIZE).decode('utf-8').split("\r\n")
            target_lines = \
                [line for line in data if line.startswith("GET ")]
            if len(target_lines) < 1:
                self.handle_failure({
                    u'code': ER_IDP_CONNECTION_ERROR,
                    u'message': u"Invalid HTTP request from web browser. Idp "
                                u"authentication could have failed."
                })
                return  # required for test case
            target_line = target_lines[0]

            user_agent = [line for line in data if line.lower().startswith(
                'user-agent')]
            if len(user_agent) > 0:
                logger.debug(user_agent[0])
            else:
                logger.debug("No User-Agent")

            _, url, _ = target_line.split()
            self._token = unquote(url[len('/?token='):])
            msg = """
<!DOCTYPE html><html><head><meta charset="UTF-8"/>
<title>SAML Response for Snowflake</title></head>
<body>
Your identity was confirmed and propagated to Snowflake {0}.
You can close this window now and go back where you started from.
</body></html>""".format(self._application)
            content = [
                "HTTP/1.0 200 OK",
                "Content-Type: text/html",
                "Content-Length: {0}".format(len(msg)),
                "",
                msg
            ]
            socket_client.sendall('\r\n'.join(content).encode('utf-8'))
        finally:
            socket_client.shutdown(socket.SHUT_RDWR)
            socket_client.close()

    def _get_sso_url(self, account, authenticator, callback_port, user):
        """
        Gets SSO URL from Snowflake
        """
        headers = {
            u'Content-Type': CONTENT_TYPE_APPLICATION_JSON,
            u"accept": CONTENT_TYPE_APPLICATION_JSON,
            u"User-Agent": PYTHON_CONNECTOR_USER_AGENT,
        }
        url = u"/session/authenticator-request"
        body = Auth.base_auth_data(
            user, account,
            self._rest._connection.application,
            self._rest._connection._internal_application_name,
            self._rest._connection._internal_application_version)

        body[u'data'][u'AUTHENTICATOR'] = authenticator
        body[u'data'][u"BROWSER_MODE_REDIRECT_PORT"] = str(callback_port)
        logger.debug(u'account=%s, authenticator=%s, user=%s',
                     account, authenticator, user)
        ret = self._rest._post_request(
            url,
            headers,
            json.dumps(body),
            timeout=self._rest._connection._login_timeout,
            socket_timeout=self._rest._connection._login_timeout)
        if not ret[u'success']:
            self.handle_failure(ret)
        data = ret[u'data']
        sso_url = data[u'ssoUrl']
        self._proof_key = data[u'proofKey']
        return sso_url
