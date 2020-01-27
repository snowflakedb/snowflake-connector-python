#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from .errors import DatabaseError, Error
from .sqlstate import SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED


class AuthByPlugin(object):
    """
    External Authenticator interface.
    """

    @property
    def assertion_content(self):
        raise NotImplementedError

    def update_body(self, body):
        raise NotImplementedError

    def authenticate(
            self, authenticator, service_name, account, user, password):
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
                         u"{message}").format(
                    host=self._rest._host,
                    port=self._rest._port,
                    message=ret[u'message'],
                ),
                u'errno': int(ret.get(u'code', -1)),
                u'sqlstate': SQLSTATE_CONNECTION_WAS_NOT_ESTABLISHED,
            })
