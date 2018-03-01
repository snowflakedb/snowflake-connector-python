#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import codecs
import json
import os
import platform
import tempfile
import time
from base64 import b64encode, b64decode
from datetime import datetime
from logging import getLogger
from multiprocessing.pool import ThreadPool
from os import path, environ
from os.path import expanduser
from threading import (Lock)
from time import gmtime, strftime

from Crypto.Hash import SHA256, SHA384, SHA1, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import OctetString, Integer
from asn1crypto.ocsp import CertId, OCSPRequest, TBSRequest, Requests, \
    Request, OCSPResponse, Version
from asn1crypto.x509 import Certificate
from botocore.vendored import requests
from botocore.vendored.requests import adapters

from snowflake.connector.compat import (urlsplit, OK)
from snowflake.connector.errorcode import (
    ER_INVALID_OCSP_RESPONSE,
    ER_SERVER_CERTIFICATE_REVOKED)
from snowflake.connector.errors import OperationalError

logger = getLogger(__name__)

# root certificate cache
ROOT_CERTIFICATES_DICT = {}  # root certificates

# root certificate cache lock
ROOT_CERTIFICATES_DICT_LOCK = Lock()

# OCSP cache
OCSP_VALIDATION_CACHE = {}

# OCSP cache lock
OCSP_VALIDATION_CACHE_LOCK = Lock()

# OCSP cache update flag
OCSP_VALIDATION_CACHE_UPDATED = False

# Tolerable validity date range ratio. The OCSP response is valid up
# to (next update timestap) + (next update timestamp - this update timestap) *
# TOLERABLE_VALIDITY_RANGE_RATIO. This buffer yields some time for Root CA to
# update intermediate CA's certificate OCSP response. In fact, they don't
# update OCSP response in time. In Dec 2016, they left OCSP response expires for
# 5 hours at least, and it caused the connectivity issues in customers.
# With this buffer, about 2 days are given for 180 days validity date.
TOLERABLE_VALIDITY_RANGE_RATIO = 0.01

# Cache Expiration in seconds (24 hours). OCSP validation cache is
# invalidated every 24 hours
CACHE_EXPIRATION = 86400

# Maximum clock skew in seconds (15 minutes) allowed when checking
# validity of OCSP responses
MAX_CLOCK_SKEW = 900

# Epoch time
ZERO_EPOCH = datetime.utcfromtimestamp(0)

# Timestamp format for logging
OUTPUT_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%SZ'

# OCSP response cache file name
OCSP_RESPONSE_CACHE_FILE_NAME = 'ocsp_response_cache.json'

# OCSP cache server URL where Snowflake provides OCSP response cache for
# better availability.
SF_OCSP_RESPONSE_CACHE_SERVER_URL = os.getenv(
    "SF_OCSP_RESPONSE_CACHE_SERVER_URL",
    "http://ocsp.snowflakecomputing.com/{0}".format(
        OCSP_RESPONSE_CACHE_FILE_NAME))
SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED = os.getenv(
    "SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED", "false") != "false"

# already downloaded the cache file from server?
DOWNLOADED_OCSP_RESPONSE_CACHE_FROM_SERVER = False

# Deprecated. for backward compatibility. Will be dropped around the
# end of 2018
PROXIES = None

# map signature algorithm name to digest class
SIGNATURE_ALGORITHM_TO_DIGEST_CLASS = {
    'sha256': SHA256,
    'sha384': SHA384,
    'sha512': SHA512,
}

# Cache directory
HOME_DIR = expanduser("~") or tempfile.gettempdir()
if platform.system() == 'Windows':
    CACHE_DIR = path.join(HOME_DIR, 'AppData', 'Local', 'Snowflake', 'Caches')
elif platform.system() == 'Darwin':
    CACHE_DIR = path.join(HOME_DIR, 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(HOME_DIR, '.cache', 'snowflake')

if not path.exists(CACHE_DIR):
    try:
        os.makedirs(CACHE_DIR, mode=0o700)
    except Exception as ex:
        logger.warning('cannot create a cache directory: [%s], err=[%s]',
                       CACHE_DIR, ex)
        CACHE_DIR = None
logger.debug("cache directory: %s", CACHE_DIR)


def _encode_cert_id_key(hkey):
    issuer_name_hash, issuer_key_hash, serial_number = hkey
    issuer_name_hash = OctetString.load(issuer_name_hash)
    issuer_key_hash = OctetString.load(issuer_key_hash)
    serial_number = Integer.load(serial_number)
    cert_id = CertId({
        'hash_algorithm': DigestAlgorithm({
            'algorithm': u'sha1',
            'parameters': None}),
        'issuer_name_hash': issuer_name_hash,
        'issuer_key_hash': issuer_key_hash,
        'serial_number': serial_number,
    })
    return cert_id


def _decode_cert_id_key(cert_id):
    return (cert_id['issuer_name_hash'].dump(),
            cert_id['issuer_key_hash'].dump(),
            cert_id['serial_number'].dump())


def _decode_ocsp_response_cache(ocsp_response_cache_json, ocsp_response_cache):
    """
    Decodes OCSP response cache from JSON
    """
    current_time = int(time.time())
    for cert_id_base64, (ts, ocsp_response) in ocsp_response_cache_json.items():
        cert_id = CertId.load(b64decode(cert_id_base64))
        hkey = _decode_cert_id_key(cert_id)
        if current_time - CACHE_EXPIRATION <= ts:
            # creation time must be new enough
            ocsp_response_cache[hkey] = (ts, b64decode(ocsp_response))
        elif hkey in ocsp_response_cache:
            # invalidate the cache if exists
            del ocsp_response_cache[hkey]
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True


def _encode_ocsp_response_cache(ocsp_response_cache, ocsp_response_cache_json):
    """
    Encodes OCSP response cache to JSON
    """
    logger.debug('encoding OCSP response cache to JSON')
    for hkey, (current_time, ocsp_response) in ocsp_response_cache.items():
        k = b64encode(_encode_cert_id_key(hkey).dump()).decode('ascii')
        v = b64encode(ocsp_response).decode('ascii')
        ocsp_response_cache_json[k] = (current_time, v)


def _file_timestamp(filename):
    """
    Last created timestamp of the file/dir
    """
    if platform.system() == 'Windows':
        ts = int(path.getctime(filename))
    else:
        stat = os.stat(filename)
        if hasattr(stat, 'st_birthtime'):  # odx
            ts = int(stat.st_birthtime)
        else:
            ts = int(stat.st_mtime)  # linux
    return ts


def check_ocsp_response_cache_lock_dir(filename):
    """
    Checks if the lock directory exists. True if it can update the cache file or
    False when some other process may be updating the cache file.
    """
    current_time = int(time.time())
    lock_dir = filename + '.lck'

    try:
        ts_cache_file = _file_timestamp(filename)
        if not path.exists(lock_dir) and \
                current_time - CACHE_EXPIRATION <= ts_cache_file:
            # use cache only if no lock directory exists and the cache file
            # was created last 24 hours
            return True

        if path.exists(lock_dir):
            # delete lock directory if older 60 seconds
            ts_lock_dir = _file_timestamp(lock_dir)
            if ts_lock_dir < current_time - 60:
                _unlock_cache_file(lock_dir)
                logger.info(
                    "The lock directory is older than 60 seconds. "
                    "Deleted the lock directory and ignoring the cache: %s",
                    lock_dir
                )
            else:
                logger.info(
                    'The lock directory exists. Other process may be updating '
                    'the cache file: %s, %s', filename, lock_dir)
        else:
            os.unlink(filename)
            logger.info(
                "The cache is older than 1 day. "
                "Deleted the cache file: %s", filename)
    except Exception as e:
        logger.info(
            "Failed to check OCSP response cache file. No worry. It will "
            "validate with OCSP server: file: %s, lock directory: %s, error: "
            "%s", filename, lock_dir, e)
    return False


def read_ocsp_response_cache_file(filename, ocsp_validation_cache):
    """
    Reads OCSP Response cache
    """
    if check_ocsp_response_cache_lock_dir(filename) and path.exists(filename):
        with codecs.open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            _decode_ocsp_response_cache(json.load(f), ocsp_validation_cache)
        logger.debug("Read OCSP response cache file: %s, count=%s",
                     filename, len(OCSP_VALIDATION_CACHE))
    else:
        logger.info(
            "Failed to locate OCSP response cache file. "
            "No worry. It will validate with OCSP server: %s",
            filename
        )


def write_ocsp_response_cache_file(filename, ocsp_validation_cache):
    """
    Writes OCSP Response Cache
    """
    logger.debug('writing OCSP response cache file')
    file_cache_data = {}
    _encode_ocsp_response_cache(ocsp_validation_cache, file_cache_data)
    with codecs.open(filename, 'w', encoding='utf-8', errors='ignore') as f:
        json.dump(file_cache_data, f)


def read_cert_bundle(ca_bundle_file, storage=None):
    """
    Reads a certificate file including certificates in PEM format
    """
    from asn1crypto import pem
    if storage is None:
        storage = ROOT_CERTIFICATES_DICT
    logger.debug('reading certificate bundle: %s', ca_bundle_file)
    with open(ca_bundle_file, 'rb') as f:
        all_certs = f.read()

    # don't lock storage
    pem_certs = pem.unarmor(all_certs, multiple=True)
    for type_name, _, der_bytes in pem_certs:
        if type_name == 'CERTIFICATE':
            crt = Certificate.load(der_bytes)
            storage[crt.subject.sha256] = crt


def _lazy_read_ca_bundle():
    """
    Reads the local cabundle file and cache it in memory
    """
    if ROOT_CERTIFICATES_DICT:
        # return if already loaded
        return

    try:
        ca_bundle = (environ.get('REQUESTS_CA_BUNDLE') or
                     environ.get('CURL_CA_BUNDLE'))
        if ca_bundle and path.exists(ca_bundle):
            # if the user/application specifies cabundle.
            read_cert_bundle(ca_bundle)
        else:
            import sys
            from botocore.vendored.requests import certs
            if hasattr(certs, '__file__') and \
                    path.exists(certs.__file__) and \
                    path.exists(path.join(
                        path.dirname(certs.__file__), 'cacert.pem')):
                # if cacert.pem exists next to certs.py in request pacakage
                ca_bundle = path.join(
                    path.dirname(certs.__file__), 'cacert.pem')
                read_cert_bundle(ca_bundle)
            elif hasattr(sys, '_MEIPASS'):
                # if pyinstaller includes cacert.pem
                cabundle_candidates = [
                    ['botocore', 'vendored', 'requests', 'cacert.pem'],
                    ['requests', 'cacert.pem'],
                    ['cacert.pem'],
                ]
                for filename in cabundle_candidates:
                    ca_bundle = path.join(sys._MEIPASS, *filename)
                    if path.exists(ca_bundle):
                        read_cert_bundle(ca_bundle)
                        break
                else:
                    logger.error('No cabundle file is found in _MEIPASS')
            try:
                import certifi
                read_cert_bundle(certifi.where())
            except Exception:
                logger.debug('no certifi is installed. ignored.')

    except Exception as e:
        logger.error('Failed to read ca_bundle: %s', e)

    if not ROOT_CERTIFICATES_DICT:
        logger.error('No CA bundle file is found in the system. '
                     'Set REQUESTS_CA_BUNDLE to the file.')


def _create_ocsp_request(issuer, subject):
    """
    Create CertId and OCSPRequest
    """
    cert_id = CertId({
        'hash_algorithm': DigestAlgorithm({
            'algorithm': u'sha1',
            'parameters': None}),
        'issuer_name_hash': OctetString(subject.issuer.sha1),
        'issuer_key_hash': OctetString(issuer.public_key.sha1),
        'serial_number': subject.serial_number,
    })
    req = OCSPRequest({
        'tbs_request': TBSRequest({
            'version': Version(0),
            'request_list': Requests([
                Request({
                    'req_cert': cert_id,
                })]),
        }),
    })
    return cert_id, req


def _fetch_ocsp_response(req, cert, do_retry=True):
    """
    Fetch OCSP response using OCSPRequest
    """
    urls = cert.ocsp_urls
    parsed_url = urlsplit(urls[0])  # urls is guaranteed to have OCSP URL

    max_retry = 100 if do_retry else 1
    data = req.dump()  # convert to DER
    headers = {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': '{0}'.format(len(data)),
        'Host': parsed_url.hostname,
    }
    ret = None
    with requests.Session() as session:
        session.mount('http://', adapters.HTTPAdapter(max_retries=5))
        session.mount('https://', adapters.HTTPAdapter(max_retries=5))
        global PROXIES
        for attempt in range(max_retry):
            response = session.post(
                urls[0],
                headers=headers,
                proxies=PROXIES,
                data=data,
                timeout=30)
            if response.status_code == OK:
                logger.debug("OCSP response was successfully returned from "
                             "OCSP server.")
                ret = response.content
                break
            elif max_retry > 1:
                wait_time = 2 ** attempt
                wait_time = 16 if wait_time > 16 else wait_time
                logger.debug("OCSP server returned %s. Retrying in %s(s)",
                             response.status_code, wait_time)
                time.sleep(wait_time)
        else:
            logger.error("Failed to get OCSP response after %s attempt.",
                         max_retry)
            raise OperationalError(
                msg="Failed to get OCSP response after {) attempt.".format(
                    max_retry),
                errno=ER_INVALID_OCSP_RESPONSE
            )

    return ret


def _calculate_tolerable_validity(this_update, next_update):
    return max(int(TOLERABLE_VALIDITY_RANGE_RATIO * (
            next_update - this_update)), MAX_CLOCK_SKEW)


def _is_validaity_range(current_time, this_update, next_update):
    tolerable_validity = _calculate_tolerable_validity(this_update, next_update)
    logger.debug(u'Tolerable Validity range for OCSP response: +%s(s)',
                 tolerable_validity)
    return this_update - MAX_CLOCK_SKEW <= \
           current_time <= next_update + tolerable_validity


def _validity_error_message(current_time, this_update, next_update):
    tolerable_validity = _calculate_tolerable_validity(this_update, next_update)
    return (u"Response is unreliable. Its validity "
            u"date is out of range: current_time={0}, "
            u"this_update={1}, next_update={2}, "
            u"tolerable next_update={3}. A potential cause is "
            u"client clock is skewed, CA fails to update OCSP "
            u"response in time.".format(
        strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(current_time)),
        strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(this_update)),
        strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(next_update)),
        strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(
            next_update + tolerable_validity))))


def _process_good_status(single_response, cert_id, ocsp_response):
    """
    Process GOOD status
    """
    current_time = int(time.time())
    this_update_native = single_response['this_update'].native
    next_update_native = single_response['next_update'].native

    if this_update_native is None or next_update_native is None:
        raise OperationalError(
            msg=u"Either this update or next "
                u"update is None. this_update: {}, next_update: {}".format(
                this_update_native, next_update_native),
            errno=ER_INVALID_OCSP_RESPONSE)

    this_update = (this_update_native.replace(
        tzinfo=None) - ZERO_EPOCH).total_seconds()
    next_update = (next_update_native.replace(
        tzinfo=None) - ZERO_EPOCH).total_seconds()
    if not _is_validaity_range(current_time, this_update, next_update):
        raise OperationalError(
            msg=_validity_error_message(
                current_time, this_update, next_update),
            errno=ER_INVALID_OCSP_RESPONSE)
    with OCSP_VALIDATION_CACHE_LOCK:
        hkey = _decode_cert_id_key(cert_id)
        if hkey not in OCSP_VALIDATION_CACHE:
            OCSP_VALIDATION_CACHE[hkey] = (
                current_time, ocsp_response)
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True


def _process_revoked_status(single_response, cert_id):
    """
    Process REVOKED status
    """
    current_time = int(time.time())
    with OCSP_VALIDATION_CACHE_LOCK:
        hkey = _decode_cert_id_key(cert_id)
        if hkey in OCSP_VALIDATION_CACHE:
            del OCSP_VALIDATION_CACHE[hkey]
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True
    revoked_info = single_response['cert_status']
    revocation_time = revoked_info.native['revocation_time']
    revocation_reason = revoked_info.native['revocation_reason']
    raise OperationalError(
        msg="The certificate has been revoked: current_time={0}, "
            "revocation_time={1}, reason={2}".format(
            strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(current_time)),
            revocation_time.strftime(OUTPUT_TIMESTAMP_FORMAT),
            revocation_reason),
        errno=ER_SERVER_CERTIFICATE_REVOKED
    )


def _process_unknown_status(cert_id):
    """
    Process UNKNOWN status
    """
    with OCSP_VALIDATION_CACHE_LOCK:
        hkey = _decode_cert_id_key(cert_id)
        if hkey in OCSP_VALIDATION_CACHE:
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True
            del OCSP_VALIDATION_CACHE[hkey]
    raise OperationalError(
        msg=u"The certificate is in UNKNOWN revocation status.",
        errno=ER_SERVER_CERTIFICATE_REVOKED,
    )


def _process_ocsp_response(issuer, cert_id, ocsp_response):
    res = OCSPResponse.load(ocsp_response)

    if res['response_status'].native != 'successful':
        raise OperationalError(
            msg="Invalid Status: {0}".format(res['response_status'].native),
            errno=ER_INVALID_OCSP_RESPONSE)

    basic_ocsp_response = res.basic_ocsp_response
    if basic_ocsp_response['certs'].native:
        logger.debug("Certificate is attached in Basic OCSP Response")
        ocsp_cert = basic_ocsp_response['certs'][0]
        logger.debug("Verifying the attached certificate is signed by "
                     "the issuer")
        _verify_signature(
            ocsp_cert.hash_algo,
            ocsp_cert.signature,
            issuer,
            ocsp_cert['tbs_certificate']
        )
    else:
        logger.debug("Certificate is NOT attached in Basic OCSP Response. "
                     "Using issuer's certificate")
        ocsp_cert = issuer

    tbs_response_data = basic_ocsp_response['tbs_response_data']

    logger.debug("Verifying the OCSP response is signed by the issuer.")
    _verify_signature(
        basic_ocsp_response['signature_algorithm'].hash_algo,
        basic_ocsp_response['signature'].native,
        ocsp_cert,
        tbs_response_data)

    single_response = tbs_response_data['responses'][0]
    cert_status = single_response['cert_status'].name
    if cert_status == 'good':
        _process_good_status(single_response, cert_id, ocsp_response)
    elif cert_status == 'revoked':
        _process_revoked_status(single_response, cert_id)
    elif cert_status == 'unknown':
        _process_unknown_status(cert_id)
    else:
        raise OperationalError(
            msg="Unknown revocation status was returned. OCSP response "
                "may be malformed: {0}".format(cert_status),
            errno=ER_INVALID_OCSP_RESPONSE
        )


def _verify_signature(signature_algorithm, signature, cert, data):
    rsakey = RSA.importKey(cert.public_key.unwrap().dump())
    signer = PKCS1_v1_5.new(rsakey)
    if signature_algorithm in SIGNATURE_ALGORITHM_TO_DIGEST_CLASS:
        digest = SIGNATURE_ALGORITHM_TO_DIGEST_CLASS[signature_algorithm].new()
    else:
        # the last resort. should not happen.
        digest = SHA1.new()
    digest.update(data.dump())
    if not signer.verify(digest, signature):
        raise OperationalError(
            msg="Failed to verify the signature",
            errno=ER_INVALID_OCSP_RESPONSE)


def _lock_cache_file(fname):
    """
    Lock a cache file by creating a directory.
    """
    try:
        os.mkdir(fname)
        return True
    except IOError:
        return False


def _unlock_cache_file(fname):
    """
    Unlock a cache file by deleting a directory
    """
    try:
        os.rmdir(fname)
        return True
    except IOError:
        return False


def update_ocsp_response_cache_file(ocsp_response_cache_uri):
    """
    Updates OCSP Response Cache
    """
    lock_dir = None
    if ocsp_response_cache_uri is not None:
        try:
            parsed_url = urlsplit(ocsp_response_cache_uri)
            if parsed_url.scheme == 'file':
                filename = path.join(parsed_url.netloc, parsed_url.path)
                lock_dir = filename + '.lck'
                for _ in range(100):
                    # wait until the lck file has been removed
                    # or up to 1 second (0.01 x 100)
                    if _lock_cache_file(lock_dir):
                        break
                    time.sleep(0.01)
                try:
                    write_ocsp_response_cache_file(
                        filename,
                        OCSP_VALIDATION_CACHE)
                finally:
                    _unlock_cache_file(lock_dir)
                    lock_dir = None
            else:
                logger.info(
                    "No OCSP response cache file is written, because the "
                    "given URI is not a file: %s. Ignoring...",
                    ocsp_response_cache_uri)
        except Exception as e:
            logger.info(
                "Failed to write OCSP response cache "
                "file. file: %s, error: %s, Ignoring...",
                ocsp_response_cache_uri, e, exc_info=True)

    if lock_dir is not None and os.path.exists(lock_dir):
        # final attempt to delete the lock directory
        if not _unlock_cache_file(lock_dir):
            logger.debug(
                "Failed to remove OCSP response cache lock directory. "
                "Ignoring..."
            )


def is_cert_id_in_cache(issuer, subject):
    global OCSP_VALIDATION_CACHE
    global OCSP_VALIDATION_CACHE_UPDATED

    cert_id, req = _create_ocsp_request(issuer, subject)
    hkey = _decode_cert_id_key(cert_id)
    with OCSP_VALIDATION_CACHE_LOCK:
        current_time = int(time.time())
        if hkey in OCSP_VALIDATION_CACHE:
            ts, cache = OCSP_VALIDATION_CACHE[hkey]
            if current_time - CACHE_EXPIRATION <= ts:
                logger.debug('hit cache for subject: %s',
                             subject.subject.native)
                return True, req, cert_id, cache
            else:
                del OCSP_VALIDATION_CACHE[hkey]
                OCSP_VALIDATION_CACHE_UPDATED = True
    logger.debug('not hit cache for subject: %s', subject.subject.native)
    return False, req, cert_id, None


def _read_ocsp_response_cache(ocsp_response_cache_uri):
    if ocsp_response_cache_uri is not None:
        try:
            with OCSP_VALIDATION_CACHE_LOCK:
                parsed_url = urlsplit(ocsp_response_cache_uri)
                if parsed_url.scheme == 'file':
                    read_ocsp_response_cache_file(
                        path.join(parsed_url.netloc, parsed_url.path),
                        OCSP_VALIDATION_CACHE)
                else:
                    raise Exception(
                        "Unsupported OCSP URI: %s",
                        ocsp_response_cache_uri)
        except Exception as e:
            logger.debug(
                "Failed to read OCSP response cache file %s: %s, "
                "No worry. It will validate with OCSP server. "
                "Ignoring...",
                ocsp_response_cache_uri, e, exc_info=True)


def validate_by_direct_connection(issuer, subject, do_retry=True):
    cache_status, req, cert_id, ocsp_response = is_cert_id_in_cache(
        issuer, subject)
    err = None
    max_retry = 100 if do_retry else 1
    for retry in range(max_retry):
        try:
            if not cache_status:
                logger.debug("getting OCSP response from CA's OCSP server")
                ocsp_response = _fetch_ocsp_response(req, subject)
            else:
                logger.debug("using OCSP response cache")
            _process_ocsp_response(issuer, cert_id, ocsp_response)
            err = None
            break
        except Exception as ex:
            logger.warning(
                "Failed to get OCSP response; %s, "
                "Retrying... %s/%s", ex, retry + 1, max_retry)
            err = ex
            cache_status = False
    if err:
        raise err

    return True, cert_id, ocsp_response


def _download_ocsp_response_cache(url, do_retry=True):
    global PROXIES
    max_retry = 100 if do_retry else 1
    ocsp_validation_cache = {}
    try:
        start_time = time.time()
        logger.debug("started downloading OCSP response cache file")
        with requests.Session() as session:
            session.mount('http://', adapters.HTTPAdapter(max_retries=5))
            session.mount('https://', adapters.HTTPAdapter(max_retries=5))
            for attempt in range(max_retry):
                response = session.request(
                    method=u'get',
                    url=url,
                    proxies=PROXIES,
                    timeout=10,  # socket timeout
                    verify=True,  # for HTTPS (future use)
                )
                if response.status_code == OK:
                    _decode_ocsp_response_cache(response.json(),
                                                ocsp_validation_cache)
                    elapsed_time = time.time() - start_time
                    logger.debug("ended downloading OCSP response cache file. "
                                 "elapsed time: %ss", elapsed_time)
                    global DOWNLOADED_OCSP_RESPONSE_CACHE_FROM_SERVER
                    DOWNLOADED_OCSP_RESPONSE_CACHE_FROM_SERVER = True
                    break
                elif max_retry > 1:
                    wait_time = 2 ** attempt
                    wait_time = 16 if wait_time > 16 else wait_time
                    logger.debug("OCSP server returned %s. Retrying in %s(s)",
                                 response.status_code, wait_time)
                    time.sleep(wait_time)
            else:
                logger.error("Failed to get OCSP response after %s attempt.",
                             max_retry)

    except Exception as e:
        logger.debug("Failed to get OCSP response cache from %s: %s",
                     url, e)
    return ocsp_validation_cache


def _validate_certificates_parallel(cert_data, do_retry=True):
    pool = ThreadPool(len(cert_data))
    results = []
    try:
        _check_ocsp_response_cacher_ser(cert_data)
        for issuer, subject in cert_data:
            r = pool.apply_async(
                validate_by_direct_connection,
                [issuer, subject, do_retry])
            results.append(r)
    finally:
        pool.close()
        pool.join()
        for r in results:
            if not r.successful():
                raise OperationalError(
                    msg="Failed to validate the certificate "
                        "revocation status: err={0}".format(r.get()))
    return results


def _validate_certificates_sequential(cert_data, do_retry=True):
    results = []
    _check_ocsp_response_cacher_ser(cert_data)
    for issuer, subject in cert_data:
        r = validate_by_direct_connection(issuer, subject, do_retry)
        results.append(r)
    return results


def _check_ocsp_response_cacher_ser(cert_data):
    global OCSP_VALIDATION_CACHE
    global SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED
    global DOWNLOADED_OCSP_RESPONSE_CACHE_FROM_SERVER
    global SF_OCSP_RESPONSE_CACHE_SERVER_URL
    if DOWNLOADED_OCSP_RESPONSE_CACHE_FROM_SERVER:
        # download cache once per process
        return
    current_time = int(time.time())
    in_cache = True
    for issuer, subject in cert_data:
        # check if OCSP response is in cache
        cert_id, _ = _create_ocsp_request(issuer, subject)
        hkey = _decode_cert_id_key(cert_id)
        if hkey not in OCSP_VALIDATION_CACHE:
            in_cache = False
            break
    if not in_cache and SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED:
        # if any of them is not cache, download the cache file from
        # OCSP response cache server.
        downloaded_cache = _download_ocsp_response_cache(
            SF_OCSP_RESPONSE_CACHE_SERVER_URL)
        logger.debug("downloaded OCSP response cache file from %s",
                     SF_OCSP_RESPONSE_CACHE_SERVER_URL)
        with OCSP_VALIDATION_CACHE_LOCK:
            for hkey, (ts, cache) in downloaded_cache.items():
                if current_time - CACHE_EXPIRATION <= ts:
                    OCSP_VALIDATION_CACHE[hkey] = ts, cache
                    global OCSP_VALIDATION_CACHE_UPDATED
                    OCSP_VALIDATION_CACHE_UPDATED = True
        logger.debug("# of certificates: %s", len(OCSP_VALIDATION_CACHE))


def _extract_certificate_chain(connection):
    """
    Gets certificate chain and extract the key info from OpenSSL connection
    """
    from OpenSSL.crypto import dump_certificate, FILETYPE_ASN1
    cert_map = {}
    logger.debug(
        "# of certificates: %s",
        len(connection.get_peer_cert_chain()))

    for cert_openssl in connection.get_peer_cert_chain():
        cert_der = dump_certificate(FILETYPE_ASN1, cert_openssl)
        cert = Certificate.load(cert_der)
        logger.debug(
            u'subject: %s, issuer: %s', cert.subject.native, cert.issuer.native)
        cert_map[cert.subject.sha256] = cert

    return _create_pair_issuer_subject(cert_map)


def _create_pair_issuer_subject(cert_map):
    """
    Creates pairs of issuer and subject certificates
    """
    issuer_subject = []
    for subject_der in cert_map:
        subject = cert_map[subject_der]
        if subject.ca and not subject.ocsp_urls:
            # Root certificate will not be validated
            # but it is used to validate the subject certificate
            continue
        issuer_hash = subject.issuer.sha256
        if issuer_hash not in cert_map:
            # IF NO ROOT certificate is attached in the certificate chain
            # read it from the local disk
            with ROOT_CERTIFICATES_DICT_LOCK:
                _lazy_read_ca_bundle()
            logger.debug('not found issuer_der: %s', subject.issuer.native)
            if issuer_hash not in ROOT_CERTIFICATES_DICT:
                raise OperationalError(
                    msg="CA certificate is NOT found in the root "
                        "certificate list. Make sure you use the latest "
                        "Python Connector package and the URL is valid.")
            issuer = ROOT_CERTIFICATES_DICT[issuer_hash]
        else:
            issuer = cert_map[issuer_hash]

        issuer_subject.append((issuer, subject))
    return issuer_subject


def merge_cache(previous_cache_filename, current_cache_filename,
                output_filename):
    """
    Merge two cache files into one cache and save to the output.
    current_cache takes precedence over previous_cache.
    """
    previous_cache = {}
    if previous_cache_filename:
        read_ocsp_response_cache_file(previous_cache_filename, previous_cache)
    current_cache = {}
    read_ocsp_response_cache_file(current_cache_filename, current_cache)
    # merge cache
    previous_cache.update(current_cache)
    write_ocsp_response_cache_file(output_filename, previous_cache)


class SnowflakeOCSP(object):
    """
    OCSP validator using PyOpenSSL and ans1crypto
    """

    def __init__(self, ocsp_response_cache_uri=None,
                 proxies=None,
                 use_ocsp_cache_server=False,
                 force_update=False):
        self._force_update = force_update
        global PROXIES
        PROXIES = proxies
        if ocsp_response_cache_uri is None and CACHE_DIR is not None:
            self._ocsp_response_cache_uri = 'file://' + path.join(
                CACHE_DIR, OCSP_RESPONSE_CACHE_FILE_NAME)
        else:
            self._ocsp_response_cache_uri = ocsp_response_cache_uri

        if self._ocsp_response_cache_uri is not None:
            # normalize URI, is this good enough?
            self._ocsp_response_cache_uri = self._ocsp_response_cache_uri.replace(
                '\\', '/')

        global SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED
        global SF_OCSP_RESPONSE_CACHE_SERVER_URL
        if use_ocsp_cache_server:
            SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED = True
        if SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED:
            logger.debug("OCSP response cache server is enabled: %s",
                         SF_OCSP_RESPONSE_CACHE_SERVER_URL)

        logger.debug("ocsp_response_cache_uri: %s",
                     self._ocsp_response_cache_uri)
        logger.debug(
            "OCSP_VALIDATION_CACHE size: %s", len(OCSP_VALIDATION_CACHE))

        _read_ocsp_response_cache(self._ocsp_response_cache_uri)
        'test'.encode("charmap")

    def validate_certfile(self, cert_filename):
        """
        Validates the certificate is NOT revoked
        """
        cert_map = {}
        read_cert_bundle(cert_filename, cert_map)
        cert_data = _create_pair_issuer_subject(cert_map)
        return self._validate(None, cert_data, do_retry=False)

    def validate(self, hostname, connection, ignore_no_ocsp=False):
        """
        Validates the certificate is not revoked using OCSP
        """
        logger.debug(u'validating certificate: %s', hostname)
        if ignore_no_ocsp:
            logger.debug(u'validation was skipped.')
            return True

        cert_data = _extract_certificate_chain(connection)
        return self._validate(hostname, cert_data)

    def _validate(self, hostname, cert_data, do_retry=True):
        global OCSP_VALIDATION_CACHE_UPDATED
        global OCSP_VALIDATION_CACHE
        global SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED

        if SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED:
            # Validate certs sequentially if OCSP response cache server is used
            results = _validate_certificates_sequential(cert_data, do_retry)
        else:
            results = _validate_certificates_parallel(cert_data, do_retry)

        with OCSP_VALIDATION_CACHE_LOCK:
            if OCSP_VALIDATION_CACHE_UPDATED:
                update_ocsp_response_cache_file(
                    self._ocsp_response_cache_uri)
            OCSP_VALIDATION_CACHE_UPDATED = False

        if len(results) != len(cert_data):
            raise OperationalError(
                msg="Failed to validate the certificate "
                    "revocation status. The number of validation "
                    "didn't match: hostname={0}, results={1}, "
                    "cert_data={2}".format(hostname, len(results),
                                           len(cert_data)),
                errno=ER_INVALID_OCSP_RESPONSE
            )
        logger.debug('ok')
        return True
