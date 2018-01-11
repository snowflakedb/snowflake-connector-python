#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import botocore.endpoint

from .compat import (TO_UNICODE)

"""
Proxy, shared across all connections
"""
PROXY_HOST = None
PROXY_PORT = None
PROXY_USER = None
PROXY_PASSWORD = None


def set_proxies(proxy_host, proxy_port, proxy_user=None, proxy_password=None):
    """
    Set proxy dict for requests
    """
    PREFIX_HTTP = 'http://'
    PREFIX_HTTPS = 'https://'
    proxies = None
    if proxy_host and proxy_port:
        if proxy_host.startswith(PREFIX_HTTP):
            proxy_host = proxy_host[len(PREFIX_HTTP):]
        elif proxy_host.startswith(PREFIX_HTTPS):
            proxy_host = proxy_host[len(PREFIX_HTTPS):]
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


def _get_proxies(self, url):
    return set_proxies(
        PROXY_HOST,
        PROXY_PORT,
        PROXY_USER,
        PROXY_PASSWORD) or original_get_proxies(self, url)


# Monkey patch for all connections for AWS API. This is mainly for PUT
# and GET commands
original_get_proxies = botocore.endpoint.EndpointCreator._get_proxies
botocore.endpoint.EndpointCreator._get_proxies = _get_proxies
