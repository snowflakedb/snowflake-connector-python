#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import json
import jwt
import codecs
import time
import platform
import os
import tempfile

from os import path, remove, environ
from datetime import datetime, timedelta
from base64 import b64encode, b64decode
from shutil import copy

from snowflake.connector.compat import PY2
from snowflake.connector.ocsp_snowflake import SnowflakeOCSP
from snowflake.connector.ssd_internal_keys import ret_wildcard_hkey
from snowflake.connector.ssl_wrap_socket import _openssl_connect
from snowflake.connector.errors import RevocationCheckError

if PY2:
    from snowflake.connector.ocsp_pyasn1 import (
        SnowflakeOCSPPyasn1 as SFOCSP
    )
else:
    from snowflake.connector.ocsp_asn1crypto import (
        SnowflakeOCSPAsn1Crypto as SFOCSP
    )

THIS_DIR = path.dirname(path.realpath(__file__))

# Cache directory
CACHE_ROOT_DIR = os.getenv('SF_OCSP_RESPONSE_CACHE_DIR') or \
                 path.expanduser("~") or tempfile.gettempdir()

CACHE_DIR = None
OCSP_CACHE_FILE = 'ocsp_response_cache.json'

if platform.system() == 'Windows':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'AppData', 'Local', 'Snowflake',
                          'Caches')
elif platform.system() == 'Darwin':
    CACHE_DIR = path.join(CACHE_ROOT_DIR, 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(CACHE_ROOT_DIR, '.cache', 'snowflake')

OCSP_RESPONSE_CACHE_URI = path.join(CACHE_DIR, OCSP_CACHE_FILE)


def _get_test_pub_key(dep):

    key_dir = path.join(THIS_DIR, 'data', 'rsa_keys')
    if dep == 1:
        key_dir = path.join(key_dir, "public.pem")
    else:
        key_dir = path.join(key_dir, "publickey2.pem")

    pubkey = open(key_dir, "r").read()
    return pubkey


def _get_test_priv_key(dep):

    key_dir = path.join(THIS_DIR, 'data', 'rsa_keys')
    if dep == 1:
        key_dir = path.join(key_dir, "private.pem")
    else:
        key_dir = path.join(key_dir, "privatekey2.pem")

    return open(key_dir, "r").read()


def _setup_ssd_test(temp_ocsp_file, fail_open=False):

    os.environ['SF_OCSP_ACTIVATE_SSD'] = 'True'
    SnowflakeOCSP.clear_cache()
    ocsp = SFOCSP(ocsp_response_cache_uri='file://'+temp_ocsp_file, use_fail_open=fail_open)
    ocsp.SSD.update_pub_key("dep1", 0.1, _get_test_pub_key(1))

    return ocsp


def _teardown_ssd_test_setup():

    host_spec_path = path.join(CACHE_DIR,"host_spec_bypass_ssd.ssd")
    key_upd_path = path.join(CACHE_DIR,"key_upd_ssd.ssd")

    if path.exists(host_spec_path):
        remove(host_spec_path)

    if path.exists(key_upd_path):
        remove(key_upd_path)

    if 'SF_OCSP_ACTIVATE_SSD' in os.environ:
        del os.environ['SF_OCSP_ACTIVATE_SSD']


def _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key, hostname):

    """
    Create Host Specific OCSP Bypass SSD
    """
    host_spec_path = path.join(ocsp.OCSP_CACHE.CACHE_DIR,"host_spec_bypass_ssd.ssd")

    with open(host_spec_path, "w") as jwt_host_spec_fp:
        tdelta = timedelta(days=1)
        nbf_val = datetime.utcnow()
        exp_val = nbf_val+tdelta
        header = {'ssd_iss':'dep1'}
        payload = {}
        hname_string = " ".join(hostname)
        acc_name = ocsp.get_account_from_hostname(hostname[0])
        payload.update({'sfcEndpoint': hname_string})
        payload.update({'certId': '*'})
        payload.update({'nbf': nbf_val})
        payload.update({'exp': exp_val})
        host_spec_jwt_token = jwt.encode(payload, priv_key, algorithm='RS512', headers=header)
        host_spec_bypass_ssd = {acc_name: host_spec_jwt_token.decode("utf-8")}
        json.dump(host_spec_bypass_ssd, jwt_host_spec_fp)


def test_host_spec_ocsp_bypass_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    copy(OCSP_RESPONSE_CACHE_URI, temp_ocsp_file_path)
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    priv_key = _get_test_priv_key(1)

    hostname = ['sfcsupport.us-east-1.snowflakecomputing.com']
    try:
        _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key, hostname)
    except Exception as ex:
        print("Exception occurred %s" %ex.message)

    ocsp.read_directives()

    acc_name = ocsp.get_account_from_hostname(hostname[0])
    cache_status, cur_host_spec_token = ocsp.SSD.find_in_ssd_cache(acc_name)
    assert cur_host_spec_token is not None, "Failed to read host specific directive"

    try:
        assert ocsp.process_ocsp_bypass_directive(cur_host_spec_token, '*', hostname[0]), \
               "Failed to process host specific bypass ssd"
    except Exception as ex:
        print("Exception while processing SSD :"+str(ex))


def test_host_spec_ocsp_bypass_updated_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    copy(OCSP_RESPONSE_CACHE_URI, temp_ocsp_file_path)
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    priv_key = _get_test_priv_key(1)

    hostname = ['sfcsupport-test12345.global.us-east-1.snowflakecomputing.com',
                'sfcsupport-test67890.global.us-east-1.snowflakecomputing.com',
                'sfcsupport.us-east-1.snowflakecomputing.com',
                'sfcsupport.us-east-2.snowflakecomputing.com']
    try:
        _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key, hostname)
    except Exception as ex:
        print("Exception occurred %s" %ex.message)

    ocsp.read_directives()

    acc_name = ocsp.get_account_from_hostname(hostname[0])
    cache_status, cur_host_spec_token = ocsp.SSD.find_in_ssd_cache(acc_name)
    assert cur_host_spec_token is not None, "Failed to read host specific directive"

    try:
        assert ocsp.process_ocsp_bypass_directive(cur_host_spec_token, '*', hostname[1]),\
            "Failed to process host specific bypass ssd"
    except Exception as ex:
        print("Exception while processing SSD :"+ex)


def test_invalid_host_spec_ocsp_bypass_updated_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    copy(OCSP_RESPONSE_CACHE_URI, temp_ocsp_file_path)
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    priv_key = _get_test_priv_key(1)

    hostname = ['sfcsupport-test12345.global.us-east-1.snowflakecomputing.com',
                'sfcsupport-test67890.global.us-east-1.snowflakecomputing.com',
                'sfcsupport.us-east-1.snowflakecomputing.com',
                'sfcsupport.us-east-2.snowflakecomputing.com']
    try:
        _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key, hostname)
    except Exception as ex:
        print("Exception occurred %s" %ex.message)

    ocsp.read_directives()

    acc_name = ocsp.get_account_from_hostname(hostname[0])
    cache_status, cur_host_spec_token = ocsp.SSD.find_in_ssd_cache(acc_name)
    assert cur_host_spec_token is not None, "Failed to read host specific directive"

    try:
        assert ocsp.process_ocsp_bypass_directive(cur_host_spec_token, '*', "sonytv.snowflakecomputing.com") is False,\
            "SSD should not match hostname specified"
    except Exception as ex:
        print("Exception while processing SSD :"+ex)


def _create_cert_spec_ocsp_bypass_token(priv_key, cid, validity_days=1):

    tdelta = timedelta(days=validity_days)
    nbf_val = datetime.utcnow()
    exp_val = nbf_val + tdelta
    header = {'ssd_iss': 'dep1'}
    payload = {}
    payload.update({'sfcEndpoint': '*'})
    payload.update({'certId': cid})
    payload.update({'nbf': nbf_val})
    payload.update({'exp': exp_val})
    return jwt.encode(payload, priv_key, algorithm='RS512', headers=header)


def test_certid_spec_bypass_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    For convenience we overwrite the local
    OCSP Cache to have SSD instead of OCSP 
    responses for all cert id. This reduces
    the incovenience to find which cert id 
    corresponds to which URL
    """
    js_ssd = {}
    priv_key = _get_test_priv_key(1)
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    with codecs.open(OCSP_RESPONSE_CACHE_URI, "r", encoding='utf-8', errors='ignore') as f:
        js = json.load(f)
        for cid, (ts, ocsp_resp) in js.items():
            ssd = _create_cert_spec_ocsp_bypass_token(priv_key, cid)
            js_ssd.update({cid: [ts, b64encode(ssd).decode('ascii')]})
    with codecs.open(temp_ocsp_file_path, "w", encoding='utf-8', errors='ignore') as f_ssd:
        json.dump(js_ssd, f_ssd)

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    hostname = 'sfcsupport.us-east-1.snowflakecomputing.com'

    connection = _openssl_connect(hostname)
    assert ocsp.validate(hostname, connection), \
        "Failed to validate {} using Cert specific OCSP Bypass SSD".format(hostname)


def test_invalid_certid_spec_bypass_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    For convenience we overwrite the local
    OCSP Cache to have SSD instead of OCSP 
    responses for all cert id. This reduces
    the incovenience to find which cert id 
    corresponds to which URL
    """
    js_ssd = {}
    priv_key = _get_test_priv_key(1)
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    with codecs.open(OCSP_RESPONSE_CACHE_URI, "r", encoding='utf-8', errors='ignore') as f:
        js = json.load(f)
        for cid, (ts, ocsp_resp) in js.items():
            ssd = _create_cert_spec_ocsp_bypass_token(priv_key, cid, 12)
            js_ssd.update({cid: [ts, b64encode(ssd).decode('ascii')]})
    with codecs.open(temp_ocsp_file_path, "w", encoding='utf-8', errors='ignore') as f_ssd:
        json.dump(js_ssd, f_ssd)

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    hostname = 'sfcsupport.us-east-1.snowflakecomputing.com'

    exception_occured = False

    connection = _openssl_connect(hostname)

    try:
        ocsp.validate(hostname, connection)
    except RevocationCheckError:
        exception_occured = True

    assert exception_occured,\
        "No exception raised for bad Server Side Directive"


def test_invalid_certid_spec_bypass_ssd_fail_open():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    For convenience we overwrite the local
    OCSP Cache to have SSD instead of OCSP 
    responses for all cert id. This reduces
    the incovenience to find which cert id 
    corresponds to which URL
    """
    js_ssd = {}
    priv_key = _get_test_priv_key(1)
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    with codecs.open(OCSP_RESPONSE_CACHE_URI, "r", encoding='utf-8', errors='ignore') as f:
        js = json.load(f)
        for cid, (ts, ocsp_resp) in js.items():
            ssd = _create_cert_spec_ocsp_bypass_token(priv_key, cid, 12)
            js_ssd.update({cid: [ts, b64encode(ssd).decode('ascii')]})
    with codecs.open(temp_ocsp_file_path, "w", encoding='utf-8', errors='ignore') as f_ssd:
        json.dump(js_ssd, f_ssd)

    """
    OCSP Fail Open mode via Environment Variable
    """
    os.environ["SF_OCSP_FAIL_OPEN"] = "true"
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    hostname = 'sfcsupport.us-east-1.snowflakecomputing.com'

    connection = _openssl_connect(hostname)

    assert ocsp.validate(hostname, connection), \
        "validation should have succeeded with soft fail enabled\n"
    del os.environ["SF_OCSP_FAIL_OPEN"]

    """
    OCSP Fail Open via parameter passed to SnowflakeOCSP constructor
    """
    ocsp = _setup_ssd_test(temp_ocsp_file_path, fail_open=True)
    assert ocsp.validate(hostname, connection), \
        "validation should have succeeded with soft fail enabled\n"


def test_wildcard_ocsp_bypass_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    priv_key = _get_test_priv_key(1)
    ts = int(time.time())
    hostname = 'sfcsupport.us-east-1.snowflakecomputing.com'
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")

    temp_ocsp_obj = SFOCSP()
    cid = temp_ocsp_obj.encode_cert_id_base64(ret_wildcard_hkey())
    ssd = _create_cert_spec_ocsp_bypass_token(priv_key, cid)

    js_ssd = {}
    with codecs.open(OCSP_RESPONSE_CACHE_URI, "r", encoding='utf-8', errors='ignore') as f:
        js = json.load(f)
        js.update({cid: [ts, b64encode(ssd).decode('ascii')]})
        with codecs.open(temp_ocsp_file_path, "w", encoding='utf-8', errors='ignore') as f_ssd:
            json.dump(js, f_ssd)

    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    connection = _openssl_connect(hostname)
    assert ocsp.validate(hostname, connection), \
        "Failed to validate {0} using Wildcard OCSP Bypass SSD".format(hostname)


def test_key_upd_ssd():

    """
    Clean any skeletons of past tests
    """
    _teardown_ssd_test_setup()

    """
    Setup OCSP instance to use test keys
    for authenticating SSD
    """
    tmp_dir = str(tempfile.gettempdir())
    temp_ocsp_file_path = path.join(tmp_dir, "ocsp_cache_backup.json")
    copy(OCSP_RESPONSE_CACHE_URI, temp_ocsp_file_path)
    ocsp = _setup_ssd_test(temp_ocsp_file_path)
    pub_key_new = _get_test_pub_key(2)
    priv_key = _get_test_priv_key(1)
    hostname = 'sfcsupport.us-east-1.snowflakecomputing.com'
    host_spec_path = path.join(ocsp.OCSP_CACHE.CACHE_DIR,"host_spec_bypass_ssd.ssd")

    """
    Create Key Update SSD using 1st set of
    test key pair and place it where the
    driver can find it.
    """
    key_upd_path = path.join(ocsp.OCSP_CACHE.CACHE_DIR,"key_upd_ssd.ssd")

    with open(key_upd_path, "w") as jwt_key_upd_fp:
        nbf_val = datetime.utcnow()
        header = {'ssd_iss': 'dep1'}
        payload = {}
        payload.update({'keyVer': '0.2'})
        payload.update({'pubKeyTyp': 'RSA'})
        payload.update({'pubKey': pub_key_new})
        payload.update({'nbf': nbf_val}) # Key Update Directives have not expiry, yet

        key_upd_jwt_token = jwt.encode(payload, priv_key, algorithm='RS512', headers=header)
        key_upd_ssd = {'dep1': key_upd_jwt_token.decode("utf-8")}

        json.dump(key_upd_ssd, jwt_key_upd_fp)

    try:
        ocsp.read_directives()
    except Exception as ex:
        print("Exception occurred : "+str(ex))

    ocsp_cur_pub_key = ocsp.SSD.ssd_pub_key_dep1.get_key()
    assert pub_key_new == ocsp_cur_pub_key,\
        "Failed to read Key Update Directive"

    _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key, hostname)

    exception_occured = False
    try:
        ocsp.read_directives()
    except Exception as ex:
        exception_occured = True

    assert exception_occured, "Key Update SSD is erroneous. There should have been an exception"

    remove(host_spec_path)
    remove(key_upd_path)
    priv_key_new = _get_test_priv_key(2)
    _create_host_spec_ocsp_bypass_ssd(ocsp, priv_key_new, hostname)

    try:
        ocsp.read_directives()
    except Exception as ex:
        assert ex is not None, "Key Update SSD is erroneous. Exception should not have occurred"

