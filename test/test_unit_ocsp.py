# encoding=utf-8
# !/usr/bin/env python
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import os
from snowflake.connector.ocsp_snowflake import OCSPCache
from snowflake.connector.ocsp_snowflake import OCSPServer


def test_building_retry_url():
    # privatelink retry url
    OCSP_SERVER = OCSPServer()
    OCSPCache.ACTIVATE_SSD = False
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL == \
           'http://ocsp.us-east-1.snowflakecomputing.com/retry/{0}/{1}'

    # privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = False
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com:80/ocsp_response_cache' \
        '.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL == \
           'http://ocsp.us-east-1.snowflakecomputing.com:80/retry/{0}/{1}'

    # non-privatelink retry url
    OCSPCache.ACTIVATE_SSD = False
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None

    # non-privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = False
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com:80/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None

    # ssd enabled for privatelink retry url
    OCSPCache.ACTIVATE_SSD = True
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL == \
           'http://ocsp.us-east-1.snowflakecomputing.com/retry'

    # ssd enabled for privatelink retry url with port
    OCSPCache.ACTIVATE_SSD = True
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.us-east-1.snowflakecomputing.com:80/ocsp_response_cache' \
        '.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL == \
           'http://ocsp.us-east-1.snowflakecomputing.com:80/retry'

    # ssd enabled for non-privatelink
    OCSPCache.ACTIVATE_SSD = True
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None

    # ssd enabled for non-privatelink with port
    OCSPCache.ACTIVATE_SSD = True
    OCSP_SERVER.OCSP_RETRY_URL = None
    OCSP_SERVER.CACHE_SERVER_URL = \
        'http://ocsp.snowflakecomputing.com:80/ocsp_response_cache.json'
    OCSP_SERVER.reset_ocsp_dynamic_cache_server_url(None)
    assert OCSP_SERVER.OCSP_RETRY_URL is None
    #Once SSD is active we would use hostname specific OCSP Endpoints.


def test_building_new_retry():
    OCSP_SERVER = OCSPServer()
    OCSPCache.ACTIVATE_SSD = False
    OCSP_SERVER.OCSP_RETRY_URL = None
    hname = \
        "a1.us-east-1.snowflakecomputing.com"
    os.environ["SF_OCSP_ACTIVATE_NEW_ENDPOINT"] = "true"
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert OCSP_SERVER.CACHE_SERVER_URL == \
        "https://ocspssd.us-east-1.snowflakecomputing.com/ocsp/fetch"

    assert OCSP_SERVER.OCSP_RETRY_URL == "https://ocspssd.us-east-1.snowflakecomputing.com/ocsp/retry"

    hname = "a1-12345.global.snowflakecomputing.com"
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert OCSP_SERVER.CACHE_SERVER_URL == "https://ocspssd-12345.global.snowflakecomputing.com/ocsp/fetch"

    assert OCSP_SERVER.OCSP_RETRY_URL == "https://ocspssd-12345.global.snowflakecomputing.com/ocsp/retry"

    hname = "snowflake.okta.com"
    OCSP_SERVER.reset_ocsp_endpoint(hname)
    assert OCSP_SERVER.CACHE_SERVER_URL == "https://ocspssd.snowflakecomputing.com/ocsp/fetch"

    assert OCSP_SERVER.OCSP_RETRY_URL == "https://ocspssd.snowflakecomputing.com/ocsp/retry"

    del os.environ['SF_OCSP_ACTIVATE_NEW_ENDPOINT']
