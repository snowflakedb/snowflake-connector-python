#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

import codecs
import json
import os
import platform
import re
import tempfile
import time
from base64 import b64decode, b64encode
from copy import deepcopy
from datetime import datetime
from logging import getLogger
from os import path, environ
from os.path import expanduser
from threading import (Lock)
from time import gmtime, strftime

from botocore.vendored import requests
from botocore.vendored.requests import adapters

from snowflake.connector.compat import (urlsplit, OK)
from snowflake.connector.errorcode import (
    ER_INVALID_OCSP_RESPONSE,
    ER_SERVER_CERTIFICATE_UNKNOWN,
    ER_SERVER_CERTIFICATE_REVOKED,
)
from snowflake.connector.errors import OperationalError
from snowflake.connector.time_util import DecorrelateJitterBackoff

logger = getLogger(__name__)


class OCSPCache(object):
    # OCSP cache
    CACHE = {}

    # OCSP cache lock
    CACHE_LOCK = Lock()

    # OCSP cache update flag
    CACHE_UPDATED = False

    # Cache Expiration in seconds (24 hours). OCSP validation cache is
    # invalidated every 24 hours
    CACHE_EXPIRATION = 86400

    # OCSP Response Cache URI
    OCSP_RESPONSE_CACHE_URI = None

    # OCSP response cache file name
    OCSP_RESPONSE_CACHE_FILE_NAME = 'ocsp_response_cache.json'

    # Default OCSP Response cache server URL
    DEFAULT_CACHE_SERVER_URL = "http://ocsp.snowflakecomputing.com"

    # OCSP cache server URL where Snowflake provides OCSP response cache for
    # better availability.
    CACHE_SERVER_URL = os.getenv(
        "SF_OCSP_RESPONSE_CACHE_SERVER_URL",
        "{0}/{1}".format(
            DEFAULT_CACHE_SERVER_URL,
            OCSP_RESPONSE_CACHE_FILE_NAME))
    CACHE_SERVER_ENABLED = os.getenv(
        "SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED", "true") != "false"

    # OCSP dynamic cache server URL pattern lock
    RETRY_URL_PATTERN_LOCK = Lock()

    # OCSP dynamic cache server URL pattern
    RETRY_URL_PATTERN = None

    # Cache directory
    CACHE_ROOT_DIR = os.getenv('SF_OCSP_RESPONSE_CACHE_DIR') or \
                     expanduser("~") or tempfile.gettempdir()
    CACHE_DIR = None
    if platform.system() == 'Windows':
        CACHE_DIR = path.join(CACHE_ROOT_DIR, 'AppData', 'Local', 'Snowflake',
                              'Caches')
    elif platform.system() == 'Darwin':
        CACHE_DIR = path.join(CACHE_ROOT_DIR, 'Library', 'Caches', 'Snowflake')
    else:
        CACHE_DIR = path.join(CACHE_ROOT_DIR, '.cache', 'snowflake')

    if not path.exists(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR, mode=0o700)
        except Exception as ex:
            logger.debug('cannot create a cache directory: [%s], err=[%s]',
                           CACHE_DIR, ex)
            CACHE_DIR = None
    logger.debug("cache directory: %s", CACHE_DIR)

    @staticmethod
    def reset_ocsp_response_cache_uri(
            ocsp_response_cache_uri, use_ocsp_cache_server):
        if ocsp_response_cache_uri is None and OCSPCache.CACHE_DIR is not None:
            OCSPCache.OCSP_RESPONSE_CACHE_URI = 'file://' + path.join(
                OCSPCache.CACHE_DIR,
                OCSPCache.OCSP_RESPONSE_CACHE_FILE_NAME)
        else:
            OCSPCache.OCSP_RESPONSE_CACHE_URI = ocsp_response_cache_uri

        if OCSPCache.OCSP_RESPONSE_CACHE_URI is not None:
            # normalize URI for Windows
            OCSPCache.OCSP_RESPONSE_CACHE_URI = \
                OCSPCache.OCSP_RESPONSE_CACHE_URI.replace('\\', '/')
        if use_ocsp_cache_server is not None:
            OCSPCache.CACHE_SERVER_ENABLED = \
                use_ocsp_cache_server

        if OCSPCache.CACHE_SERVER_ENABLED:
            logger.debug("OCSP response cache server is enabled: %s",
                         OCSPCache.CACHE_SERVER_URL)
        else:
            logger.debug("OCSP response cache server is disabled")

        logger.debug("ocsp_response_cache_uri: %s",
                     OCSPCache.OCSP_RESPONSE_CACHE_URI)
        logger.debug(
            "OCSP_VALIDATION_CACHE size: %s", len(OCSPCache.CACHE))

        OCSPCache._reset_ocsp_dynamic_cache_server_url()

    @staticmethod
    def _reset_ocsp_dynamic_cache_server_url():
        """
        Reset OCSP dynamic cache server url pattern.

        This is used only when OCSP cache server is updated.
        """
        with OCSPCache.RETRY_URL_PATTERN_LOCK:
            if OCSPCache.RETRY_URL_PATTERN is None and \
                    not OCSPCache.CACHE_SERVER_URL.startswith(
                        OCSPCache.DEFAULT_CACHE_SERVER_URL):
                # only if custom OCSP cache server is used.
                parsed_url = urlsplit(
                    OCSPCache.CACHE_SERVER_URL)
                if parsed_url.port:
                    OCSPCache.RETRY_URL_PATTERN = \
                        u"{0}://{1}:{2}/retry/".format(
                            parsed_url.scheme, parsed_url.hostname,
                            parsed_url.port) + u"{0}/{1}"
                else:
                    OCSPCache.RETRY_URL_PATTERN = \
                        u"{0}://{1}/retry/".format(
                            parsed_url.scheme, parsed_url.hostname) + u"{0}/{1}"
            logger.debug(
                "OCSP dynamic cache server URL pattern: %s",
                OCSPCache.RETRY_URL_PATTERN)

    @staticmethod
    def generate_get_url(ocsp_url, b64data):
        if OCSPCache.RETRY_URL_PATTERN:
            parsed_url = urlsplit(ocsp_url)
            target_url = OCSPCache.RETRY_URL_PATTERN.format(
                parsed_url.hostname, b64data
            )
        else:
            target_url = u"{0}/{1}".format(ocsp_url, b64data)
        return target_url

    @staticmethod
    def read_file(ocsp):
        """
        Read OCSP Response cache data from the URI, which is very likely a file.
        """
        try:
            parsed_url = urlsplit(OCSPCache.OCSP_RESPONSE_CACHE_URI)
            if parsed_url.scheme == 'file':
                OCSPCache.read_ocsp_response_cache_file(
                    ocsp,
                    path.join(parsed_url.netloc, parsed_url.path))
            else:
                raise Exception(
                    "Unsupported OCSP URI: %s",
                    OCSPCache.OCSP_RESPONSE_CACHE_URI)
        except Exception as e:
            logger.debug(
                "Failed to read OCSP response cache file %s: %s, "
                "No worry. It will validate with OCSP server. "
                "Ignoring...",
                OCSPCache.OCSP_RESPONSE_CACHE_URI, e, exc_info=True)

    @staticmethod
    def read_ocsp_response_cache_file(ocsp, filename):
        """
        Reads OCSP Response cache
        """
        if OCSPCache.check_ocsp_response_cache_lock_dir(filename) and \
                path.exists(filename):
            with codecs.open(filename, 'r', encoding='utf-8',
                             errors='ignore') as f:
                ocsp.decode_ocsp_response_cache(json.load(f))
            logger.debug("Read OCSP response cache file: %s, count=%s",
                         filename, len(OCSPCache.CACHE))
        else:
            logger.debug(
                "Failed to locate OCSP response cache file. "
                "No worry. It will validate with OCSP server: %s",
                filename
            )

    @staticmethod
    def update_file(ocsp):
        """
        Update OCSP Respone Cache file
        """
        with OCSPCache.CACHE_LOCK:
            if OCSPCache.CACHE_UPDATED:
                OCSPCache.update_ocsp_response_cache_file(
                    ocsp,
                    OCSPCache.OCSP_RESPONSE_CACHE_URI)
                OCSPCache.CACHE_UPDATED = False

    @staticmethod
    def update_ocsp_response_cache_file(ocsp, ocsp_response_cache_uri):
        """
        Updates OCSP Response Cache
        """
        if ocsp_response_cache_uri is not None:
            try:
                parsed_url = urlsplit(ocsp_response_cache_uri)
                if parsed_url.scheme == 'file':
                    filename = path.join(parsed_url.netloc, parsed_url.path)
                    lock_dir = filename + '.lck'
                    for _ in range(100):
                        # wait until the lck file has been removed
                        # or up to 1 second (0.01 x 100)
                        if OCSPCache.lock_cache_file(lock_dir):
                            break
                        time.sleep(0.01)
                    try:
                        OCSPCache.write_ocsp_response_cache_file(
                            ocsp,
                            filename)
                    finally:
                        OCSPCache.unlock_cache_file(lock_dir)
                else:
                    logger.debug(
                        "No OCSP response cache file is written, because the "
                        "given URI is not a file: %s. Ignoring...",
                        ocsp_response_cache_uri)
            except Exception as e:
                logger.debug(
                    "Failed to write OCSP response cache "
                    "file. file: %s, error: %s, Ignoring...",
                    ocsp_response_cache_uri, e, exc_info=True)

    @staticmethod
    def write_ocsp_response_cache_file(ocsp, filename):
        """
        Writes OCSP Response Cache
        """
        logger.debug('writing OCSP response cache file')
        file_cache_data = {}
        ocsp.encode_ocsp_response_cache(file_cache_data)
        with codecs.open(filename, 'w', encoding='utf-8', errors='ignore') as f:
            json.dump(file_cache_data, f)

    @staticmethod
    def check_ocsp_response_cache_lock_dir(filename):
        """
        Checks if the lock directory exists. True if it can update the cache
        file or False when some other process may be updating the cache file.
        """
        current_time = int(time.time())
        lock_dir = filename + '.lck'

        try:
            ts_cache_file = OCSPCache._file_timestamp(filename)
            if not path.exists(lock_dir) and \
                    current_time - OCSPCache.CACHE_EXPIRATION <= ts_cache_file:
                # use cache only if no lock directory exists and the cache file
                # was created last 24 hours
                return True

            if path.exists(lock_dir):
                # delete lock directory if older 60 seconds
                ts_lock_dir = OCSPCache._file_timestamp(lock_dir)
                if ts_lock_dir < current_time - 60:
                    OCSPCache.unlock_cache_file(lock_dir)
                    logger.debug(
                        "The lock directory is older than 60 seconds. "
                        "Deleted the lock directory and ignoring the cache: %s",
                        lock_dir
                    )
                else:
                    logger.debug(
                        'The lock directory exists. Other process may be '
                        'updating the cache file: %s, %s', filename, lock_dir)
            else:
                os.unlink(filename)
                logger.debug(
                    "The cache is older than 1 day. "
                    "Deleted the cache file: %s", filename)
        except Exception as e:
            logger.debug(
                "Failed to check OCSP response cache file. No worry. It will "
                "validate with OCSP server: file: %s, lock directory: %s, "
                "error: %s", filename, lock_dir, e)
        return False

    @staticmethod
    def find_cache(ocsp, cert_id, subject):
        subject_name = ocsp.subject_name(subject) if subject else None
        current_time = int(time.time())
        hkey = ocsp.decode_cert_id_key(cert_id)
        with OCSPCache.CACHE_LOCK:
            if hkey in OCSPCache.CACHE:
                ts, cache = OCSPCache.CACHE[hkey]
                if current_time - OCSPCache.CACHE_EXPIRATION <= ts:
                    if subject_name:
                        logger.debug(
                            'hit cache for subject: %s', subject_name)
                    return True, cache
                else:
                    del OCSPCache.CACHE[hkey]
                    OCSPCache.CACHE_UPDATED = True
        if subject_name:
            logger.debug('not hit cache for subject: %s', subject_name)
        return False, None

    @staticmethod
    def download_cache_from_server(ocsp):
        if OCSPCache.CACHE_SERVER_ENABLED:
            # if any of them is not cache, download the cache file from
            # OCSP response cache server.
            OCSPCache._download_ocsp_response_cache(
                ocsp,
                OCSPCache.CACHE_SERVER_URL)
            logger.debug("downloaded OCSP response cache file from %s",
                         OCSPCache.CACHE_SERVER_URL)
            logger.debug("# of certificates: %s", len(OCSPCache.CACHE))

    @staticmethod
    def _download_ocsp_response_cache(ocsp, url, do_retry=True):
        """
        Download OCSP response cache from the cache server
        :param url: OCSP response cache server
        :param do_retry: retry if connection fails up to N times
        """
        try:
            start_time = time.time()
            logger.debug("started downloading OCSP response cache file")
            with requests.Session() as session:
                session.mount('http://', adapters.HTTPAdapter(max_retries=5))
                session.mount('https://', adapters.HTTPAdapter(max_retries=5))
                max_retry = 30 if do_retry else 1
                sleep_time = 1
                backoff = DecorrelateJitterBackoff(sleep_time, 16)
                for attempt in range(max_retry):
                    response = session.get(
                        url,
                        timeout=10,  # socket timeout
                    )
                    if response.status_code == OK:
                        ocsp.decode_ocsp_response_cache(response.json())
                        elapsed_time = time.time() - start_time
                        logger.debug(
                            "ended downloading OCSP response cache file. "
                            "elapsed time: %ss", elapsed_time)
                        break
                    elif max_retry > 1:
                        sleep_time = backoff.next_sleep(sleep_time)
                        logger.debug(
                            "OCSP server returned %s. Retrying in %s(s)",
                            response.status_code, sleep_time)
                    time.sleep(sleep_time)
                else:
                    logger.error(
                        "Failed to get OCSP response after %s attempt.",
                        max_retry)

        except Exception as e:
            logger.debug("Failed to get OCSP response cache from %s: %s", url,
                         e)

    @staticmethod
    def update_or_delete_cache(ocsp, cert_id, ocsp_response, ts):
        current_time = int(time.time())
        found, _ = OCSPCache.find_cache(ocsp, cert_id, None)
        if current_time - OCSPCache.CACHE_EXPIRATION <= ts:
            # creation time must be new enough
            OCSPCache.update_cache(ocsp, cert_id, ocsp_response)
        elif found:
            # invalidate the cache if exists
            OCSPCache.delete_cache(ocsp, cert_id)

    @staticmethod
    def iterate_cache():
        for rec in OCSPCache.CACHE.items():
            yield rec

    @staticmethod
    def update_cache(ocsp, cert_id, ocsp_response):
        current_time = int(time.time())
        with OCSPCache.CACHE_LOCK:
            hkey = ocsp.decode_cert_id_key(cert_id)
            if hkey not in OCSPCache.CACHE:
                OCSPCache.CACHE[hkey] = (current_time, ocsp_response)
                OCSPCache.CACHE_UPDATED = True

    @staticmethod
    def delete_cache(ocsp, cert_id):
        with OCSPCache.CACHE_LOCK:
            hkey = ocsp.decode_cert_id_key(cert_id)
            if hkey in OCSPCache.CACHE:
                del OCSPCache.CACHE[hkey]
                OCSPCache.CACHE_UPDATED = True

    @staticmethod
    def merge_cache(ocsp, previous_cache_filename, current_cache_filename,
                    output_filename):
        """
        Merge two cache files into one cache and save to the output.
        current_cache takes precedence over previous_cache.
        """
        OCSPCache.clear_cache()
        if previous_cache_filename:
            OCSPCache.read_ocsp_response_cache_file(
                ocsp, previous_cache_filename)
        previous_cache = deepcopy(OCSPCache.CACHE)

        OCSPCache.clear_cache()
        OCSPCache.read_ocsp_response_cache_file(ocsp, current_cache_filename)
        current_cache = deepcopy(OCSPCache.CACHE)

        # overwrite the previous one with the current one
        previous_cache.update(current_cache)

        OCSPCache.CACHE = previous_cache
        OCSPCache.write_ocsp_response_cache_file(ocsp, output_filename)

    @staticmethod
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

    @staticmethod
    def lock_cache_file(fname):
        """
        Lock a cache file by creating a directory.
        """
        try:
            os.mkdir(fname)
            return True
        except IOError:
            return False

    @staticmethod
    def unlock_cache_file(fname):
        """
        Unlock a cache file by deleting a directory
        """
        try:
            os.rmdir(fname)
            return True
        except IOError:
            return False

    @staticmethod
    def delete_cache_file():
        """
        Delete the cache file. Used by tests only
        """
        parsed_url = urlsplit(OCSPCache.OCSP_RESPONSE_CACHE_URI)
        fname = path.join(parsed_url.netloc, parsed_url.path)
        OCSPCache.lock_cache_file(fname)
        try:
            os.unlink(fname)
        finally:
            OCSPCache.unlock_cache_file(fname)

    @staticmethod
    def clear_cache():
        """
        Clear cache
        """
        with OCSPCache.CACHE_LOCK:
            OCSPCache.CACHE = {}

    @staticmethod
    def cache_size():
        """
        Cache size
        """
        with OCSPCache.CACHE_LOCK:
            return len(OCSPCache.CACHE)


class SnowflakeOCSP(object):
    """
    OCSP validator using PyOpenSSL and asn1crypto/pyasn1
    """

    # root certificate cache
    ROOT_CERTIFICATES_DICT = {}  # root certificates

    # root certificate cache lock
    ROOT_CERTIFICATES_DICT_LOCK = Lock()

    # cache object
    OCSP_CACHE = OCSPCache()

    OCSP_WHITELIST = re.compile(
        r'^'
        r'(.*\.snowflakecomputing\.com$'
        r'|(?:|.*\.)s3.*\.amazonaws\.com$'  # start with s3 or .s3 in the middle
        r'|.*\.okta\.com$'
        r'|.*\.blob\.core\.windows\.net$)')

    # Tolerable validity date range ratio. The OCSP response is valid up
    # to (next update timestap) + (next update timestamp -
    # this update timestap) * TOLERABLE_VALIDITY_RANGE_RATIO. This buffer
    # yields some time for Root CA to update intermediate CA's certificate
    # OCSP response. In fact, they don't update OCSP response in time. In Dec
    # 2016, they left OCSP response expires for 5 hours at least, and it
    # caused the connectivity issues in customers.
    # With this buffer, about 2 days are given for 180 days validity date.
    TOLERABLE_VALIDITY_RANGE_RATIO = 0.01

    # Maximum clock skew in seconds (15 minutes) allowed when checking
    # validity of OCSP responses
    MAX_CLOCK_SKEW = 900

    # Epoch time
    ZERO_EPOCH = datetime.utcfromtimestamp(0)

    # Timestamp format for logging
    OUTPUT_TIMESTAMP_FORMAT = '%Y-%m-%d %H:%M:%SZ'

    def __init__(
            self,
            ocsp_response_cache_uri=None,
            use_ocsp_cache_server=None,
            use_post_method=False):
        self._use_post_method = use_post_method
        SnowflakeOCSP.OCSP_CACHE.reset_ocsp_response_cache_uri(
            ocsp_response_cache_uri, use_ocsp_cache_server)

        SnowflakeOCSP.OCSP_CACHE.read_file(self)

    def validate_certfile(self, cert_filename, no_exception=False):
        """
        Validates the certificate is NOT revoked
        """
        cert_map = {}
        self.read_cert_bundle(cert_filename, cert_map)
        cert_data = self.create_pair_issuer_subject(cert_map)
        return self._validate(
            None, cert_data, do_retry=False, no_exception=no_exception)

    def validate(self, hostname, connection, no_exception=False):
        """
        Validates the certificate is not revoked using OCSP
        """
        logger.debug(u'validating certificate: %s', hostname)
        m = not SnowflakeOCSP.OCSP_WHITELIST.match(hostname)
        if m:
            logger.debug(u'skipping OCSP check: %s', hostname)
            return [None, None, None, None, None]

        cert_data = self.extract_certificate_chain(connection)
        return self._validate(hostname, cert_data, no_exception=no_exception)

    def _validate(
            self, hostname, cert_data, do_retry=True, no_exception=False):
        # Validate certs sequentially if OCSP response cache server is used
        results = self._validate_certificates_sequential(
            cert_data, do_retry=do_retry)

        SnowflakeOCSP.OCSP_CACHE.update_file(self)

        any_err = False
        for err, issuer, subject, cert_id, ocsp_response in results:
            if isinstance(err, OperationalError):
                err.msg += u' for {}'.format(hostname)
            if not no_exception and err is not None:
                raise err
            elif err is not None:
                any_err = True

        logger.debug('ok' if not any_err else 'failed')
        return results

    def is_cert_id_in_cache(self, issuer, subject):
        """
        Is OCSP CertID in cache?
        :param issuer: issuer certificate
        :param subject: subject certificate
        :return: True if in cache otherwise False, followed by OCSP Request,
        OCSP CertID and the cached OCSP Response
        """
        cert_id, req = self.create_ocsp_request(issuer, subject)
        found, cache = SnowflakeOCSP.OCSP_CACHE.find_cache(
            self, cert_id, subject)
        return found, req, cert_id, cache

    def validate_by_direct_connection(self, issuer, subject, do_retry=True):
        cache_status, req, cert_id, ocsp_response = \
            self.is_cert_id_in_cache(issuer, subject)
        err = None
        max_retry = 30 if do_retry else 1
        for retry in range(max_retry):
            try:
                if not cache_status:
                    logger.debug("getting OCSP response from CA's OCSP server")
                    ocsp_response = self._fetch_ocsp_response(req, subject)
                else:
                    logger.debug("using OCSP response cache")
                if not ocsp_response:
                    logger.debug('No OCSP URL is found.')
                    return None, issuer, subject, cert_id, ocsp_response
                self.process_ocsp_response(issuer, cert_id, ocsp_response)
                err = None
                break
            except Exception as ex:
                logger.debug(
                    "Failed to get OCSP response; %s, "
                    "Retrying... %s/%s", ex, retry + 1, max_retry)
                err = ex
                cache_status = False

        return err, issuer, subject, cert_id, ocsp_response

    def _validate_certificates_sequential(self, cert_data, do_retry=True):
        results = []
        self._check_ocsp_response_cache_server(cert_data)
        for issuer, subject in cert_data:
            r = self.validate_by_direct_connection(
                issuer, subject, do_retry=do_retry)
            results.append(r)
        return results

    def _check_ocsp_response_cache_server(self, cert_data):
        """
        Checks if OCSP response is in cache, and if not download the OCSP
        response cache from the server.
        :param cert_data: pairs of issuer and subject certificates
        """
        in_cache = False
        for issuer, subject in cert_data:
            # check if any OCSP response is NOT in cache
            cert_id, _ = self.create_ocsp_request(issuer, subject)
            in_cache, cache = SnowflakeOCSP.OCSP_CACHE.find_cache(
                self, cert_id, subject)
            if not in_cache:
                # not found any
                break

        if not in_cache:
            SnowflakeOCSP.OCSP_CACHE.download_cache_from_server(self)

    def _lazy_read_ca_bundle(self):
        """
        Reads the local cabundle file and cache it in memory
        """
        with SnowflakeOCSP.ROOT_CERTIFICATES_DICT_LOCK:
            if SnowflakeOCSP.ROOT_CERTIFICATES_DICT:
                # return if already loaded
                return

            try:
                ca_bundle = (environ.get('REQUESTS_CA_BUNDLE') or
                             environ.get('CURL_CA_BUNDLE'))
                if ca_bundle and path.exists(ca_bundle):
                    # if the user/application specifies cabundle.
                    self.read_cert_bundle(ca_bundle)
                else:
                    import sys
                    from botocore.vendored.requests import certs
                    if hasattr(certs, '__file__') and \
                            path.exists(certs.__file__) and \
                            path.exists(path.join(
                                path.dirname(certs.__file__), 'cacert.pem')):
                        # if cacert.pem exists next to certs.py in request
                        # package.
                        ca_bundle = path.join(
                            path.dirname(certs.__file__), 'cacert.pem')
                        self.read_cert_bundle(ca_bundle)
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
                                self.read_cert_bundle(ca_bundle)
                                break
                        else:
                            logger.error(
                                'No cabundle file is found in _MEIPASS')
                    try:
                        import certifi
                        self.read_cert_bundle(certifi.where())
                    except Exception:
                        logger.debug('no certifi is installed. ignored.')

            except Exception as e:
                logger.error('Failed to read ca_bundle: %s', e)

            if not SnowflakeOCSP.ROOT_CERTIFICATES_DICT:
                logger.error('No CA bundle file is found in the system. '
                             'Set REQUESTS_CA_BUNDLE to the file.')

    @staticmethod
    def _calculate_tolerable_validity(this_update, next_update):
        return max(int(SnowflakeOCSP.TOLERABLE_VALIDITY_RANGE_RATIO * (
                next_update - this_update)), SnowflakeOCSP.MAX_CLOCK_SKEW)

    @staticmethod
    def _is_validaity_range(current_time, this_update, next_update):
        tolerable_validity = SnowflakeOCSP._calculate_tolerable_validity(
            this_update, next_update)
        logger.debug(u'Tolerable Validity range for OCSP response: +%s(s)',
                     tolerable_validity)
        return this_update - SnowflakeOCSP.MAX_CLOCK_SKEW <= \
               current_time <= next_update + tolerable_validity

    @staticmethod
    def _validity_error_message(current_time, this_update, next_update):
        tolerable_validity = SnowflakeOCSP._calculate_tolerable_validity(
            this_update, next_update)
        return (u"Response is unreliable. Its validity "
                u"date is out of range: current_time={0}, "
                u"this_update={1}, next_update={2}, "
                u"tolerable next_update={3}. A potential cause is "
                u"client clock is skewed, CA fails to update OCSP "
                u"response in time.".format(
            strftime(SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT,
                     gmtime(current_time)),
            strftime(SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT,
                     gmtime(this_update)),
            strftime(SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT,
                     gmtime(next_update)),
            strftime(SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT,
                     gmtime(next_update + tolerable_validity))))

    @staticmethod
    def clear_cache():
        SnowflakeOCSP.OCSP_CACHE.clear_cache()

    @staticmethod
    def cache_size():
        return SnowflakeOCSP.OCSP_CACHE.cache_size()

    @staticmethod
    def delete_cache_file():
        SnowflakeOCSP.OCSP_CACHE.delete_cache_file()

    def _fetch_ocsp_response(self, ocsp_request, cert, do_retry=True):
        """
        Fetch OCSP response using OCSPRequest
        """
        ocsp_url = self.extract_ocsp_url(cert)
        if not ocsp_url:
            return None

        actual_method = 'post' if self._use_post_method else 'get'
        if SnowflakeOCSP.OCSP_CACHE.RETRY_URL_PATTERN:
            # no POST is supported for Retry URL at the moment.
            actual_method = 'get'

        if actual_method == 'get':
            b64data = self.decode_ocsp_request_b64(ocsp_request)
            target_url = SnowflakeOCSP.OCSP_CACHE.generate_get_url(
                ocsp_url, b64data)
            payload = None
            headers = None
        else:
            target_url = ocsp_url
            payload = self.decode_ocsp_request(ocsp_request)
            headers = {'Content-Type': 'application/ocsp-request'}

        ret = None
        logger.debug('url: %s', target_url)
        with requests.Session() as session:
            session.mount('http://', adapters.HTTPAdapter(max_retries=5))
            session.mount('https://', adapters.HTTPAdapter(max_retries=5))
            max_retry = 30 if do_retry else 1
            sleep_time = 1
            backoff = DecorrelateJitterBackoff(sleep_time, 16)
            for attempt in range(max_retry):
                response = session.request(
                    headers=headers,
                    method=actual_method,
                    url=target_url,
                    timeout=30,
                    data=payload,
                )
                if response.status_code == OK:
                    logger.debug(
                        "OCSP response was successfully returned from OCSP "
                        "server.")
                    ret = response.content
                    break
                elif max_retry > 1:
                    sleep_time = backoff.next_sleep(sleep_time)
                    logger.debug("OCSP server returned %s. Retrying in %s(s)",
                                 response.status_code, sleep_time)
                time.sleep(sleep_time)
            else:
                logger.error(
                    "Failed to get OCSP response after %s attempt.", max_retry)
                raise OperationalError(
                    msg="Failed to get OCSP response after {) attempt.".format(
                        max_retry),
                    errno=ER_INVALID_OCSP_RESPONSE
                )

        return ret

    def _process_good_status(self, single_response, cert_id, ocsp_response):
        """
        Process GOOD status
        """
        current_time = int(time.time())
        this_update_native, next_update_native = \
            self.extract_good_status(single_response)

        if this_update_native is None or next_update_native is None:
            raise OperationalError(
                msg=u"Either this update or next "
                    u"update is None. this_update: {}, next_update: {}".format(
                    this_update_native, next_update_native),
                errno=ER_INVALID_OCSP_RESPONSE)

        this_update = (this_update_native.replace(
            tzinfo=None) - SnowflakeOCSP.ZERO_EPOCH).total_seconds()
        next_update = (next_update_native.replace(
            tzinfo=None) - SnowflakeOCSP.ZERO_EPOCH).total_seconds()
        if not SnowflakeOCSP._is_validaity_range(
                current_time, this_update, next_update):
            raise OperationalError(
                msg=SnowflakeOCSP._validity_error_message(
                    current_time, this_update, next_update),
                errno=ER_INVALID_OCSP_RESPONSE)
        SnowflakeOCSP.OCSP_CACHE.update_cache(self, cert_id, ocsp_response)

    def _process_revoked_status(self, single_response, cert_id):
        """
        Process REVOKED status
        """
        current_time = int(time.time())
        SnowflakeOCSP.OCSP_CACHE.delete_cache(self, cert_id)
        revocation_time, revocation_reason = self.extract_revoked_status(
            single_response)
        raise OperationalError(
            msg="The certificate has been revoked: current_time={0}, "
                "revocation_time={1}, reason={2}".format(
                strftime(
                    SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT,
                    gmtime(current_time)),
                revocation_time.strftime(
                    SnowflakeOCSP.OUTPUT_TIMESTAMP_FORMAT),
                revocation_reason),
            errno=ER_SERVER_CERTIFICATE_REVOKED
        )

    def _process_unknown_status(self, cert_id):
        """
        Process UNKNOWN status
        """
        SnowflakeOCSP.OCSP_CACHE.delete_cache(self, cert_id)
        raise OperationalError(
            msg=u"The certificate is in UNKNOWN revocation status.",
            errno=ER_SERVER_CERTIFICATE_UNKNOWN,
        )

    def decode_ocsp_response_cache(self, ocsp_response_cache_json):
        """
        Decodes OCSP response cache from JSON
        """
        for cert_id_base64, (
                ts, ocsp_response) in ocsp_response_cache_json.items():
            cert_id = self.decode_cert_id_base64(cert_id_base64)
            SnowflakeOCSP.OCSP_CACHE.update_or_delete_cache(
                self, cert_id, b64decode(ocsp_response), ts)

    def encode_ocsp_response_cache(self, ocsp_response_cache_json):
        """
        Encodes OCSP response cache to JSON
        """
        logger.debug('encoding OCSP response cache to JSON')
        for hkey, (current_time, ocsp_response) in \
                SnowflakeOCSP.OCSP_CACHE.iterate_cache():
            k = self.encode_cert_id_base64(hkey)
            v = b64encode(ocsp_response).decode('ascii')
            ocsp_response_cache_json[k] = (current_time, v)

    def read_cert_bundle(self, ca_bundle_file, storage=None):
        """
        Reads a certificate file including certificates in PEM format
        """
        raise NotImplementedError

    def encode_cert_id_key(self, _):
        """
        Encode Cert ID key to native CertID
        """
        raise NotImplementedError

    def decode_cert_id_key(self, _):
        """
        Decode name CertID to Cert ID key
        """
        raise NotImplementedError

    def encode_cert_id_base64(self, hkey):
        """
        Encode native CertID to base64 Cert ID
        """
        raise NotImplementedError

    def decode_cert_id_base64(self, cert_id_base64):
        """
        Decode base64 Cert ID to native CertID
        """
        raise NotImplementedError

    def create_ocsp_request(self, issuer, subject):
        """
        Create CertId and OCSPRequest
        """
        raise NotImplementedError

    def extract_ocsp_url(self, cert):
        """
        Extract OCSP URL from Certificate
        """
        raise NotImplementedError

    def decode_ocsp_request(self, ocsp_request):
        """
        Decode OCSP request to DER
        """
        raise NotImplementedError

    def decode_ocsp_request_b64(self, ocsp_request):
        """
        Decode OCSP Request object to b64
        """
        raise NotImplementedError

    def extract_good_status(self, single_response):
        """
        Extract Revocation Status GOOD
        """
        raise NotImplementedError

    def extract_revoked_status(self, single_response):
        """
        Extract Revocation Status REVOKED
        """
        raise NotImplementedError

    def process_ocsp_response(self, issuer, cert_id, ocsp_response):
        """
        Process OCSP response
        """
        raise NotImplementedError

    def verify_signature(self, signature_algorithm, signature, cert, data):
        """
        Verify signature
        """
        raise NotImplementedError

    def extract_certificate_chain(self, connection):
        """
        Gets certificate chain and extract the key info from OpenSSL connection
        """
        raise NotImplementedError

    def create_pair_issuer_subject(self, cert_map):
        """
        Creates pairs of issuer and subject certificates
        """
        raise NotImplementedError

    def subject_name(self, subject):
        """
        Human readable Subject name
        """
        raise NotImplementedError
