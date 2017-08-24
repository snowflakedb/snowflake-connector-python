#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import json
import logging
import socket
import time
import webbrowser
from threading import Thread

from .auth import AuthByExternalService
from .compat import (BASE_EXCEPTION_CLASS, HTTPServer, BaseHTTPRequestHandler,
                     parse_qs, urlparse)
from .errorcode import (ER_FAILED_TO_CONNECT_TO_DB,
                        ER_UNABLE_TO_OPEN_BROWSER, ER_UNABLE_TO_START_WEBSERVER)
from .network import (CONTENT_TYPE_APPLICATION_JSON,
                      PYTHON_CONNECTOR_USER_AGENT, CLIENT_NAME, CLIENT_VERSION)
from .version import VERSION

logger = logging.getLogger(__name__)

# global state of web server that receives the SAML assertion from
# Snowflake server
force_to_stop = False
token = None


class AuthByWebBrowser(AuthByExternalService):
    """
    Authenticate user by web browser. Only used for SAML based
    authentication.
    """

    def __init__(self, rest, application,
                 webbrowser_pkg=None, webserver_handler=None):
        self._rest = rest
        self._saml_response = None
        self._webserver_status = None
        self._application = application
        self._proof_key = None
        self._webbrowser = webbrowser if webbrowser_pkg is None else webbrowser_pkg
        self._webserver = AuthByWebBrowser._run_webserver if webserver_handler is None \
            else webserver_handler

    @property
    def assertion_content(self):
        return self._saml_response

    def update_body(self, body):
        body[u'data'][u'SAML_RESPONSE'] = self._saml_response
        body[u'data'][u'PROOF_KEY'] = self._proof_key

    def _run_webserver(self, application, port):
        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                global force_to_stop
                global token
                # NOTE: any authentication failure must be detected
                # earlier in the flow, so here it can assume that the user is
                # authorized to gain access to Snowflake db.
                logger.debug("USER-AGENT: %s",
                             self.headers.get('user-agent'))
                parsed_query = parse_qs(urlparse(self.path).query)
                token = parsed_query['token'][0]
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write('''
        <!DOCTYPE html><html><head><meta charset="UTF-8"/>
        <title>SAML Response for Snowflake</title></head>
        <body>
        Your identity was confirmed and propagated to Snowflake {0}. You can close 
        this window now and go back where you started from.
        </body></html>
        '''.format(application).encode('utf-8'))
                force_to_stop = True

            def log_message(self, format, *args):
                logger.debug(format % args)

        global force_to_stop
        self._webserver_status = None
        try:
            httpd = HTTPServer(('localhost', port), RequestHandler)
        except BASE_EXCEPTION_CLASS as e:
            # catch all exceptions as a separate thread cannot propagate it to
            # the main thread.
            logger.debug(e, exc_info=True)
            self._webserver_status = e
            force_to_stop = True
            return
        print("Initiating login request with your identity provider. A "
              "browser window should have opened for you to complete the "
              "login. If you can't see it, check existing browser windows, "
              "or your OS settings. Press CTRL+C to abort and try again...")
        logger.debug("web browser is opened with port {0} for IDP".format(
            port))
        self._webserver_status = True
        while not force_to_stop:
            httpd.handle_request()

    def authenticate(self, authenticator, account, user, password):
        """
        Web Browser based Authentication.
        """
        logger.info(u'authenticating by Web Browser')
        logger.debug(u'step 1: query GS to obtain SSO url')

        # ignore password. user is still needed by GS to verify
        # the assertion.
        _ = password

        def get_open_port():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('localhost', 0))
            s.listen(1)
            port = s.getsockname()[1]
            s.close()
            return port

        force_to_stop = False

        global force_to_stop
        global token
        token = None
        th = None
        for _ in range(10):
            force_to_stop = False
            callback_port = get_open_port()  # get the open port for callback

            th = Thread(name="Auth by WebBrowser Web Server",
                        target=self._webserver,
                        args=[self, self._application, callback_port])
            th.daemon = True
            th.start()

            for _ in range(5):
                # wait for up to 5 seconds to get the web server status back
                if self._webserver_status is not None:
                    break
                time.sleep(1)
            if isinstance(self._webserver_status, bool) and \
                    self._webserver_status:
                logger.debug('web server started')
                break
            th.join(1.0)
            if isinstance(self._webserver_status, IOError) and \
                            self._webserver_status.errno == 98:
                # IOError: Address in Use
                logger.debug('Failed to get the port %s. Retrying...',
                             callback_port)
                time.sleep(1)
            elif isinstance(self._webserver_status, BASE_EXCEPTION_CLASS):
                logger.error(self._webserver_status)
                self.handle_failure({
                    u'code': ER_UNABLE_TO_START_WEBSERVER,
                    u'message': str(self._webserver_status)
                })
                return  # required for test case
        else:
            if th is not None:
                th.join(1.0)
            self.handle_failure({
                u'code': ER_UNABLE_TO_START_WEBSERVER,
                u'message': (u"Failed to start webserver to communicate "
                             u"with SSO server.")
            })
            return  # required for test case

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
                u"LOGIN_NAME": user,
                u"SVN_REVISION": VERSION[3],
                u"ACCOUNT_NAME": account,
                u"AUTHENTICATOR": authenticator,
                u"BROWSER_MODE_REDIRECT_PORT": str(callback_port),
            },
        }
        logger.debug(u'account=%s, authenticator=%s, user=%s',
                     account, authenticator, user)
        ret = self._rest._post_request(
            url,
            headers,
            json.dumps(body),
            timeout=self._rest._connection._login_timeout)
        if not ret[u'success']:
            self.handle_failure(ret)

        data = ret[u'data']
        sso_url = data[u'ssoUrl']
        self._proof_key = data[u'proofKey']

        logger.debug(u'step 2: open a browser')
        if not self._webbrowser.open_new(sso_url):
            force_to_stop = True
            logger.error(
                u'Unable to open a browser in this environment.', exc_info=True)
            self.handle_failure({
                u'code': ER_UNABLE_TO_OPEN_BROWSER,
                u'message': u"Unable to open a browser in this environment."
            })
            return  # required for test case

        while not force_to_stop:
            time.sleep(1)

        if th is not None:
            th.join(1.0)
        self._saml_response = token
