#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#

"""
Use openssl command line to validate the certification revocation status
using OCSP.
"""
import calendar
import codecs
import hashlib
import json
import logging
import os
import platform
import re
import tempfile
import time
from base64 import b64encode, b64decode
from logging import getLogger
from multiprocessing.pool import ThreadPool
from os import path
from os.path import expanduser
from threading import (Lock)
from time import gmtime, strftime, strptime

from OpenSSL.crypto import (dump_certificate, FILETYPE_PEM, FILETYPE_ASN1,
                            load_certificate, dump_publickey)
from OpenSSL.crypto import verify as crypto_verify
from botocore.vendored import requests
from botocore.vendored.requests.adapters import HTTPAdapter
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.type import (univ, tag)
from pyasn1_modules import (rfc2459, rfc2437, rfc2560)

from .compat import (PY2, urlsplit, OK)
from .errorcode import (ER_FAILED_TO_GET_OCSP_URI,
                        ER_INVALID_OCSP_RESPONSE,
                        ER_SERVER_CERTIFICATE_REVOKED,
                        ER_CA_CERTIFICATE_NOT_FOUND)
from .errors import (OperationalError)
from .rfc6960 import (OCSPRequest, OCSPResponse, TBSRequest, CertID, Request,
                      Version, BasicOCSPResponse,
                      OCSPResponseStatus)

OCSP_RESPONSE_CACHE_FILE_NAME = 'ocsp_response_cache.json'

PYASN1_VERSION_LOCK = Lock()

PYASN1_VERSION = None  # be init once

ROOT_CERTIFICATES_DICT_LOCK = Lock()

ROOT_CERTIFICATES_DICT = {}  # root certificates

logger = getLogger(__name__)


def _get_pyasn1_version():
    global PYASN1_VERSION_LOCK
    global PYASN1_VERSION
    with PYASN1_VERSION_LOCK:
        if PYASN1_VERSION is None:
            import pyasn1
            v = pyasn1.__version__
            vv = [int(x, 10) for x in v.split('.')]
            vv.reverse()
            PYASN1_VERSION = sum(x * (1000 ** i) for i, x in enumerate(vv))


def read_cert_bundle(ca_bundle_file, storage=None):
    """
    Reads a certificate file including certificates in PEM format
    """
    if storage is None:
        storage = ROOT_CERTIFICATES_DICT
    logger = getLogger(__name__)
    logger.debug('reading certificate bundle: %s', ca_bundle_file)
    # cabundle file encoding varies. Tries reading it in utf-8 but ignore
    # all errors
    all_certs = codecs.open(
        ca_bundle_file, 'r', encoding='utf-8', errors='ignore').read()
    state = 0
    contents = []
    for line in all_certs.split('\n'):
        if state == 0 and line.startswith('-----BEGIN CERTIFICATE-----'):
            state = 1
            contents.append(line)
        elif state == 1:
            contents.append(line)
            if line.startswith('-----END CERTIFICATE-----'):
                cert = load_certificate(
                    FILETYPE_PEM,
                    '\n'.join(contents).encode('utf-8'))
                storage[cert.get_subject().der()] = cert
                state = 0
                contents = []


def _lazy_read_ca_bundle():
    """
    Reads the local cabundle file and cache it in memory
    """
    if len(ROOT_CERTIFICATES_DICT) > 0:
        return

    logger = getLogger(__name__)
    try:
        ca_bundle = (os.environ.get('REQUESTS_CA_BUNDLE') or
                     os.environ.get('CURL_CA_BUNDLE'))
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
            except:
                logger.debug('no certifi is installed. ignored.')

    except Exception as e:
        logger.error('Failed to read ca_bundle: %s', e)

    if len(ROOT_CERTIFICATES_DICT) == 0:
        logger.error('No CA bundle file is found in the system. '
                     'Set REQUESTS_CA_BUNDLE to the file.')


def octet_string_to_bytearray(octet_string):
    """
    Converts Octet string to bytearray
    """
    ret = []
    for ch in octet_string:
        ret.append(ch)
    return bytearray(ret)


def bit_string_to_bytearray(bit_string):
    """
    Converts Bitstring to bytearray
    """
    ret = []
    for idx in range(int(len(bit_string) / 8)):
        v = 0
        for idx0, bit in enumerate(bit_string[idx * 8:idx * 8 + 8]):
            v = v | (bit << (7 - idx0))
        ret.append(v)
    return bytearray(ret)


def _get_pubickey_sha1_hash(cert):
    """
    Gets pubkey sha1 hash
    """
    pkey = cert.get_pubkey()
    pkey_asn1 = dump_publickey(FILETYPE_ASN1, pkey)
    decoded_pkey, _ = der_decoder.decode(
        pkey_asn1, rfc2459.SubjectPublicKeyInfo())
    pubkey = bit_string_to_bytearray(decoded_pkey['subjectPublicKey'])
    # algorithm = decoded_pkey['algorithm'] # RSA encryption
    sha1_hash = hashlib.sha1()
    sha1_hash.update(pubkey)
    return sha1_hash


def _extract_values_from_certificate(cert):
    """
    Gets Serial Number, DN and Public Key Hashes. Currently SHA1 is used
    to generate hashes for DN and Public Key.
    """
    logger = getLogger(__name__)
    # cert and serial number
    data = {
        u'cert': cert,
        u'issuer': cert.get_issuer().der(),
        u'serial_number': cert.get_serial_number(),
        u'algorithm': rfc2437.id_sha1,
        u'algorithm_parameter': univ.Any(hexValue='0500')  # magic number
    }
    # DN Hash
    data[u'name'] = cert.get_subject()
    cert_der = data[u'name'].der()
    sha1_hash = hashlib.sha1()
    sha1_hash.update(cert_der)
    data[u'name_hash'] = sha1_hash.hexdigest()

    # public key Hash
    data['key_hash'] = _get_pubickey_sha1_hash(cert).hexdigest()

    # CRL and OCSP
    data['crl'] = None
    ocsp_uris0 = []
    for idx in range(cert.get_extension_count()):
        e = cert.get_extension(idx)
        if e.get_short_name() == b'authorityInfoAccess':
            for line in str(e).split(u"\n"):
                m = OCSP_RE.match(line)
                if m:
                    logger.debug(u'OCSP URL: %s', m.group(1))
                    ocsp_uris0.append(m.group(1))
        elif e.get_short_name() == b'crlDistributionPoints':
            for line in str(e).split(u"\n"):
                m = CRL_RE.match(line)
                if m:
                    logger.debug(u"CRL: %s", m.group(1))
                    data['crl'] = m.group(1)

    if len(ocsp_uris0) == 1:
        data['ocsp_uri'] = ocsp_uris0[0]
    elif len(ocsp_uris0) == 0:
        data['ocsp_uri'] = u''
    else:
        raise OperationalError(
            msg=u'More than one OCSP URI entries are specified in '
                u'the certificate',
            errno=ER_FAILED_TO_GET_OCSP_URI,
        )
    data[u'is_root_ca'] = cert.get_subject() == cert.get_issuer()
    return data


def _extract_certificate_chain(connection):
    """
    Gets certificate chain and extract the key info from certificate
    """
    logger = getLogger(__name__)
    cert_data = {}
    logger.debug(
        "# of certificates: %s",
        len(connection.get_peer_cert_chain()))

    for cert in connection.get_peer_cert_chain():
        logger.debug(
            u'subject: %s, issuer: %s', cert.get_subject(),
            cert.get_issuer())
        data = _extract_values_from_certificate(cert)
        logger.debug('is_root_ca: %s', data[u'is_root_ca'])
        cert_data[cert.get_subject().der()] = data
    return _create_pair_issuer_subject(cert_data)


def _create_pair_issuer_subject(cert_data):
    issuer_and_subject = []
    for subject_der in cert_data:
        if not cert_data[subject_der][u'is_root_ca']:
            # Root certificate will not be validated
            # but it is used to validate the subject certificate
            issuer_der = cert_data[subject_der]['issuer']
            if issuer_der not in cert_data:
                # IF NO ROOT certificate is attached in the certificate chain
                # read it from the local disk
                with ROOT_CERTIFICATES_DICT_LOCK:
                    _lazy_read_ca_bundle()
                logger.debug('not found issuer_der: %s', issuer_der)
                if issuer_der in ROOT_CERTIFICATES_DICT:
                    issuer = _extract_values_from_certificate(
                        ROOT_CERTIFICATES_DICT[issuer_der])
                    issuer[u'is_root_ca'] = True
                else:
                    raise OperationalError(
                        msg=u"CA certificate is not found in the root "
                            u"certificate list. Make sure you use the latest "
                            u"Python Connector package.",
                        errno=ER_CA_CERTIFICATE_NOT_FOUND,
                    )
            else:
                issuer = cert_data[issuer_der]

            issuer_and_subject.append({
                'subject': cert_data[subject_der],
                'issuer': issuer,
            })
    return issuer_and_subject


def _verify_signature(
        cert, signature_algorithm_seq, signature, data):
    """
    Verifies the signature
    """
    logger = getLogger(__name__)
    value = bit_string_to_bytearray(signature)
    if PY2:
        value = str(value)
    else:
        value = value.decode('latin-1').encode('latin-1')

    algorithm = signature_algorithm_seq[0]
    if algorithm in SIGNATURE_HASH_ALGO_TO_NAME:
        algorithm_name = SIGNATURE_HASH_ALGO_TO_NAME[algorithm]
    else:
        logger.exception(
            "Unsupported Signature Algorithm: %s", algorithm)
        return Exception("Unsupported Signature Algorithm: %s", algorithm)

    data_der = der_encoder.encode(data)
    try:
        crypto_verify(cert, value, data_der, algorithm_name)
        return None
    except Exception as e:
        logger.exception("Failed to verify the signature", e)
        return e


def _has_certs_in_ocsp_response(certs):
    """
    Check if the certificate is attached to OCSP response
    """
    global PYASN1_VERSION
    if PYASN1_VERSION <= 3000:
        return certs is not None
    else:
        return certs is not None and certs.hasValue() and certs[0].hasValue()


def process_ocsp_response(response, ocsp_issuer):
    """
    process OCSP response
    """
    logger = getLogger(__name__)
    ocsp_response, _ = der_decoder.decode(response, OCSPResponse())
    if ocsp_response['responseStatus'] != OCSPResponseStatus(
            'successful'):
        raise OperationalError(
            msg="Invalid Status: {0}".format(
                OCSP_RESPONSE_STATUS[int(ocsp_response['responseStatus'])]),
            errno=ER_INVALID_OCSP_RESPONSE)

    response_bytes = ocsp_response['responseBytes']
    response_type = response_bytes['responseType']

    if response_type != rfc2560.id_pkix_ocsp_basic:
        logger.error("Invalid Response Type: %s", response_type)
        raise OperationalError(
            msg="Invaid Response Type: {0}".format(response_type),
            errno=ER_INVALID_OCSP_RESPONSE)

    basic_ocsp_response, _ = der_decoder.decode(
        response_bytes['response'],
        BasicOCSPResponse())

    if _has_certs_in_ocsp_response(basic_ocsp_response['certs']):
        logger.debug("Certificate is attached in Basic OCSP Response")
        cert_der = der_encoder.encode(basic_ocsp_response['certs'][0])
        ocsp_cert = load_certificate(FILETYPE_ASN1, cert_der)
    else:
        logger.debug("Certificate is NOT attached in Basic OCSP Response. "
                     "Using issuer's certificate")
        ocsp_cert = ocsp_issuer['cert']

    tbs_response_data = basic_ocsp_response['tbsResponseData']

    if tbs_response_data['version'] != 0:
        raise OperationalError(
            msg='Invalid ResponseData Version: {0}'.format(
                tbs_response_data['version']),
            errno=ER_INVALID_OCSP_RESPONSE)

    produced_at = tbs_response_data['producedAt']
    logger.debug('Produced At: %s', produced_at)

    if tbs_response_data['responseExtensions']:
        logger.debug('Response Extensions: %s',
                     tbs_response_data['responseExtensions'])

    ocsp_no_check = False
    if ocsp_issuer['cert'] != ocsp_cert:
        if ocsp_issuer['cert'].get_subject() != ocsp_cert.get_issuer():
            raise OperationalError(
                msg=u"Failed to match the issuer of the certificate "
                    u"attached in OCSP response with the issuer' "
                    u"certificate.",
                errno=ER_INVALID_OCSP_RESPONSE)
        is_for_ocsp = False
        for cnt in range(ocsp_cert.get_extension_count()):
            ex = ocsp_cert.get_extension(cnt)
            if ex.get_short_name() == b'extendedKeyUsage':
                # ensure the purpose is OCSP signing
                der_data, _ = der_decoder.decode(ex.get_data())
                for idx in range(len(der_data)):
                    if der_data[idx] == OCSP_SIGNING:
                        is_for_ocsp = True
                        break
            elif ex.get_short_name() == b'noCheck':
                # check if CA wants to skip ocsp_checking
                der_data, _ = der_decoder.decode(ex.get_data())
                if str(der_data) != '':  # non empty value means no check
                    ocsp_no_check = True

        if not is_for_ocsp:
            raise OperationalError(
                msg=u'The certificate attached is not for OCSP signing.',
                errno=ER_INVALID_OCSP_RESPONSE)

        ocsp_cert_object, _ = der_decoder.decode(
            dump_certificate(FILETYPE_ASN1, ocsp_cert),
            rfc2459.Certificate())

        err = _verify_signature(
            ocsp_issuer['cert'],
            ocsp_cert_object['signatureAlgorithm'],
            ocsp_cert_object['signatureValue'],
            ocsp_cert_object['tbsCertificate']
        )
        if err:
            raise OperationalError(
                msg=u"Signature in the certificate included in the "
                    u"OCSP response could NOT be verified by the "
                    u"issuer's certificate: err={0}".format(err),
                errno=ER_INVALID_OCSP_RESPONSE)

    if not ocsp_no_check:
        err = _verify_signature(
            ocsp_cert,
            basic_ocsp_response['signatureAlgorithm'],
            basic_ocsp_response['signature'],
            tbs_response_data
        )
        if err:
            raise OperationalError(
                msg=u'Signature in the OCSP response could NOT be '
                    u'verified: err={0}'.format(err),
                errno=ER_INVALID_OCSP_RESPONSE)
    else:
        logger.debug(
            u'No OCSP validation was made as the certificate '
            u'indicates noCheck')

    single_response_map = {}
    for single_response in tbs_response_data['responses']:
        cert_id = single_response['certID']
        cert_status = single_response['certStatus']
        hkey = _decode_cert_id_key(cert_id)
        if cert_status['good'] is not None:
            logger.debug('ok')
            this_update = strptime(str(single_response['thisUpdate']),
                                   '%Y%m%d%H%M%SZ')
            next_update = strptime(str(single_response['nextUpdate']),
                                   '%Y%m%d%H%M%SZ')
            this_update = calendar.timegm(this_update)
            next_update = calendar.timegm(next_update)
            single_response_map[hkey] = {
                'status': 'good',
                'this_update': this_update,
                'next_update': next_update,
            }
        elif cert_status['revoked'] is not None:
            logger.info('revoked: %s', cert_status['revoked'])
            # revocation
            revocation_time = cert_status['revoked']['revocationTime']
            revocation_reason = cert_status['revoked']['revocationReason']
            single_response_map[hkey] = {
                'status': 'revoked',
                'time': revocation_time,
                'reason': revocation_reason,
            }
        else:
            logger.info('unknown')
            single_response_map[hkey] = {
                'status': 'unknown',
            }
    return single_response_map


def execute_ocsp_request(ocsp_uri, cert_id, proxies=None, do_retry=True):
    """
    Executes OCSP request for the given cert id
    """
    logger = getLogger(__name__)
    request = Request()
    request['reqCert'] = cert_id

    request_list = univ.SequenceOf(componentType=Request())
    request_list[0] = request

    tbs_request = TBSRequest()
    tbs_request['requestList'] = request_list
    tbs_request['version'] = Version(0).subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple,
                            0))

    ocsp_request = OCSPRequest()
    ocsp_request['tbsRequest'] = tbs_request

    # no signature for the client
    # no nonce is set, because not all OCSP resopnder implements it yet

    # transform objects into data in requests
    data = der_encoder.encode(ocsp_request)
    parsed_url = urlsplit(ocsp_uri)

    max_retry = 100 if do_retry else 1
    # NOTE: This retry is to retry getting HTTP 200.
    headers = {
        'Content-Type': 'application/ocsp-request',
        'Content-Length': '{0}'.format(len(data)),
        'Host': parsed_url.hostname,
    }
    logger.debug('url: %s, headers: %s, proxies: %s',
                 ocsp_uri, headers, proxies)
    with requests.Session() as session:
        session.mount('http://', HTTPAdapter(max_retries=5))
        session.mount('https://', HTTPAdapter(max_retries=5))
        for attempt in range(max_retry):
            response = session.post(
                ocsp_uri,
                headers=headers,
                proxies=proxies,
                data=data,
                timeout=60)
            if response.status_code == OK:
                logger.debug("OCSP response was successfully returned")
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
    return response.content


def is_cert_id_in_cache(ocsp_issuer, ocsp_subject, use_cache=True):
    u"""
    checks if cert_id is in the cache
    """
    global SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED
    global SF_OCSP_RESPONSE_CACHE_SERVER_URL
    global OCSP_VALIDATION_CACHE_UPDATED

    logger = getLogger(__name__)
    cert_id = CertID()
    cert_id[
        'hashAlgorithm'] = rfc2459.AlgorithmIdentifier().setComponentByName(
        'algorithm', ocsp_issuer[u'algorithm']).setComponentByName(
        'parameters', ocsp_issuer[u'algorithm_parameter'])
    cert_id['issuerNameHash'] = univ.OctetString(
        hexValue=ocsp_issuer[u'name_hash'])
    cert_id['issuerKeyHash'] = univ.OctetString(
        hexValue=ocsp_issuer[u'key_hash'])
    cert_id['serialNumber'] = rfc2459.CertificateSerialNumber(
        ocsp_subject[u'serial_number'])

    if logger.getEffectiveLevel() == logging.DEBUG:
        base64_name_hash = b64encode(
            octet_string_to_bytearray(cert_id['issuerNameHash']))
    else:
        base64_name_hash = None

    with OCSP_VALIDATION_CACHE_LOCK:
        current_time = int(time.time())
        for idx in range(2):
            hkey = _decode_cert_id_key(cert_id)
            if use_cache and hkey in OCSP_VALIDATION_CACHE:
                ts, cache = OCSP_VALIDATION_CACHE[hkey]
                if ts - CACHE_EXPIRATION <= current_time <= ts + CACHE_EXPIRATION:
                    # cache value is OCSP response
                    logger.debug(
                        u'hit cache. issuer name: %s, is '
                        u'subject root: %s',
                        ocsp_issuer['name'],
                        ocsp_issuer[u'is_root_ca'])
                    return True, cert_id, cache
                else:
                    # more than 24 hours difference
                    del OCSP_VALIDATION_CACHE[hkey]
                    OCSP_VALIDATION_CACHE_UPDATED = True

            if idx == 1:
                # No second attempt to download the OCSP response cache.
                break
            # download OCSP response cache once
            if SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED:
                downloaded_cache = download_ocsp_response_cache(
                    SF_OCSP_RESPONSE_CACHE_SERVER_URL)
                logger.debug('downloaded OCSP response cache file from %s',
                             SF_OCSP_RESPONSE_CACHE_SERVER_URL)
                for hkey, (ts, cache) in downloaded_cache.items():
                    if ts - CACHE_EXPIRATION <= current_time <= ts + CACHE_EXPIRATION:
                        OCSP_VALIDATION_CACHE[hkey] = ts, cache
                        OCSP_VALIDATION_CACHE_UPDATED = True
            else:
                logger.debug("OCSP response cache service is not enabled. Set "
                             "the environment variable "
                             "SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED=true to "
                             "enable it.")

    if logger.getEffectiveLevel() == logging.DEBUG:
        logger.debug(
            u'not hit cache. issuer name hash: %s, issuer name: %s, is subject '
            u'root: %s, issuer name hash algorithm: %s, '
            u'issuer key hash: %s, subject serial number: %s',
            base64_name_hash, ocsp_issuer['name'], ocsp_issuer[u'is_root_ca'],
            cert_id['hashAlgorithm'],
            b64encode(octet_string_to_bytearray(cert_id['issuerKeyHash'])),
            cert_id['serialNumber'])

    return False, cert_id, None


def _encode_cert_id_key(hkey):
    issuer_name_hash, issuer_key_hash, serial_number = hkey
    issuer_name_hash, _ = der_decoder.decode(issuer_name_hash)
    issuer_key_hash, _ = der_decoder.decode(issuer_key_hash)
    serial_number, _ = der_decoder.decode(serial_number)
    cert_id = CertID()
    cert_id['hashAlgorithm'] = rfc2459.AlgorithmIdentifier().setComponentByName(
        'algorithm', rfc2437.id_sha1)
    cert_id['issuerNameHash'] = issuer_name_hash
    cert_id['issuerKeyHash'] = issuer_key_hash
    cert_id['serialNumber'] = serial_number
    return cert_id


def _decode_cert_id_key(cert_id):
    return (der_encoder.encode(cert_id['issuerNameHash']),
            der_encoder.encode(cert_id['issuerKeyHash']),
            der_encoder.encode(cert_id['serialNumber']))


def _decode_ocsp_response_cache(ocsp_response_cache_json, ocsp_response_cache):
    """
    Decodes OCSP response cache from JSON
    """
    current_time = int(time.time())
    for cert_id_base64, (ts, ocsp_response) in ocsp_response_cache_json.items():
        cert_id, _ = der_decoder.decode(b64decode(cert_id_base64), CertID())
        hkey = _decode_cert_id_key(cert_id)
        if ts - CACHE_EXPIRATION <= current_time <= ts + CACHE_EXPIRATION:
            ocsp_response_cache[hkey] = (ts, b64decode(ocsp_response))
        elif hkey in ocsp_response_cache:
            # invalidate the cache if exists
            del ocsp_response_cache[hkey]


def _encode_ocsp_response_cache(ocsp_response_cache, ocsp_response_cache_json):
    """
    Encodes OCSP response cache to JSON
    """
    logger = getLogger(__name__)
    logger.debug('encoding OCSP reponse cache to JSON')
    for hkey, (current_time, ocsp_response) in \
            ocsp_response_cache.items():
        k = b64encode(der_encoder.encode(_encode_cert_id_key(hkey))).decode(
            'ascii')
        v = b64encode(ocsp_response).decode('ascii')
        ocsp_response_cache_json[k] = (current_time, v)


def touch(fname, times=None):
    """
    Touch a file
    """
    with open(fname, 'a'):
        os.utime(fname, times)


def file_timestamp(filename):
    if platform.system() == 'Windows':
        ts = int(path.getctime(filename))
    else:
        stat = os.stat(filename)
        if hasattr(stat, 'st_birthtime'):  # odx
            ts = int(stat.st_birthtime)
        else:
            ts = int(stat.st_mtime)  # linux
    return ts


def check_ocsp_response_cache_lock_file(filename):
    logger = getLogger(__name__)
    current_time = int(time.time())
    lock_file = filename + '.lck'

    try:
        ts_cache_file = file_timestamp(filename)
        if not path.exists(lock_file) and ts_cache_file >= current_time - \
                CACHE_EXPIRATION:
            # use cache only if no lock file exists and the cache file
            # was created last 24 hours
            return True

        if path.exists(lock_file):
            # delete lock file if older 60 seconds
            ts_lock_file = file_timestamp(lock_file)
            if ts_lock_file < current_time - 60:
                os.unlink(lock_file)
                logger.info(
                    "The lock file is older than 60 seconds. "
                    "Deleted the lock file and ignoring the cache: %s",
                    lock_file
                )
            else:
                logger.info(
                    'The lock file exists. Other process may be updating the '
                    'cache file: %s, %s', filename, lock_file)
        else:
            os.unlink(filename)
            logger.info(
                "The cache is older than 1 day. "
                "Deleted the cache file: %s", filename
            )
    except Exception as e:
        logger.info(
            "Failed to check OCSP response cache file. No worry. It will "
            "validate with OCSP server: file: %s, lock file: %s, error: %s",
            filename, lock_file, e
        )
    return False


def read_ocsp_response_cache_file(filename, ocsp_validation_cache):
    """
    Reads OCSP Response cache
    """
    logger = getLogger(__name__)
    if check_ocsp_response_cache_lock_file(filename) and path.exists(filename):
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
    logger = getLogger(__name__)
    logger.debug('writing OCSP response cache file')
    file_cache_data = {}
    _encode_ocsp_response_cache(ocsp_validation_cache, file_cache_data)
    with codecs.open(filename, 'w', encoding='utf-8', errors='ignore') as f:
        json.dump(file_cache_data, f)


def update_ocsp_response_cache_file(ocsp_response_cache_uri):
    """
    Updates OCSP Response Cache
    """
    logger = getLogger(__name__)
    lock_file = None
    if ocsp_response_cache_uri is not None:
        try:
            parsed_url = urlsplit(ocsp_response_cache_uri)
            if parsed_url.scheme == 'file':
                filename = path.join(parsed_url.netloc, parsed_url.path)
                lock_file = filename + '.lck'
                for _ in range(100):
                    # wait until the lck file has been removed
                    # or up to 1 second (0.01 x 100)
                    if not path.exists(lock_file):
                        break
                    time.sleep(0.01)
                if not path.exists(lock_file):
                    touch(lock_file)
                    try:
                        write_ocsp_response_cache_file(
                            filename,
                            OCSP_VALIDATION_CACHE)
                    finally:
                        os.unlink(lock_file)
                        lock_file = None
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

    if lock_file is not None and os.path.exists(lock_file):
        try:
            os.unlink(lock_file)
        except Exception as e:
            logger.debug(
                "Failed to unlink OCS response cache lock file. Ignoring..."
            )


def download_ocsp_response_cache(url):
    """
    Downloads OCSP response cache from Snowflake.
    """
    logger = getLogger(__name__)
    ocsp_validation_cache = {}
    import binascii
    try:
        with requests.Session() as session:
            session.mount('http://', HTTPAdapter(max_retries=5))
            session.mount('https://', HTTPAdapter(max_retries=5))

            response = session.request(
                method=u'get',
                url=url,
                timeout=10,  # socket timeout
                verify=True,  # for HTTPS (future use)
            )
        if response.status_code == OK:
            try:
                _decode_ocsp_response_cache(response.json(),
                                            ocsp_validation_cache)
            except (ValueError, binascii.Error) as err:
                logger.debug(
                    'Failed to convert OCSP cache server response to '
                    'JSON. The cache was corrupted. No worry. It will'
                    'validate with OCSP server: %s', err)
        else:
            logger.debug("Failed to get OCSP response cache from %s: %s",
                         url, response.status_code)
    except Exception as e:
        logger.debug("Failed to get OCSP response cache from %s: %s",
                     url, e)
    return ocsp_validation_cache


def check_ocsp_response_status(single_response_map, ocsp_response):
    """
    Checks the OCSP response status
    """
    ret = []
    for hkey, data in single_response_map.items():
        if data['status'] == 'good':
            ret.append(_process_good_status(
                hkey, data, ocsp_response))
        elif data['status'] == 'revoked':  # revoked
            _process_revoked_status(hkey, data)
        else:  # unknown
            _process_unknown_status(hkey)
    if len(ret) != len(single_response_map):
        raise OperationalError(
            msg=u"Not all OCSP Response was returned",
            errno=ER_INVALID_OCSP_RESPONSE,
        )


def _calculate_tolerable_validity(this_update, next_update):
    return max(int(TOLERABLE_VALIDITY_RANGE_RATIO * (
            next_update - this_update)), MAX_CLOCK_SKEW)


def _is_validaity_range(current_time, this_update, next_update):
    logger = getLogger(__name__)
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
        strftime('%Y%m%d%H%M%SZ', gmtime(current_time)),
        strftime('%Y%m%d%H%M%SZ', gmtime(this_update)),
        strftime('%Y%m%d%H%M%SZ', gmtime(next_update)),
        strftime('%Y%m%d%H%M%SZ', gmtime(
            next_update + tolerable_validity))))


def _process_good_status(hkey, data, ocsp_response):
    """
    Process Good status
    """
    current_time = int(time.time())
    this_update = data['this_update']
    next_update = data['next_update']
    if _is_validaity_range(current_time, this_update, next_update):
        with OCSP_VALIDATION_CACHE_LOCK:
            if hkey not in OCSP_VALIDATION_CACHE:
                OCSP_VALIDATION_CACHE[hkey] = (current_time, ocsp_response)
                global OCSP_VALIDATION_CACHE_UPDATED
                OCSP_VALIDATION_CACHE_UPDATED = True
        return True
    else:
        raise OperationalError(
            msg=_validity_error_message(current_time, this_update, next_update),
            errno=ER_INVALID_OCSP_RESPONSE
        )


def _process_revoked_status(hkey, data):
    """
    Process Revoked status
    """
    with OCSP_VALIDATION_CACHE_LOCK:
        if hkey in OCSP_VALIDATION_CACHE:
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True
            del OCSP_VALIDATION_CACHE[hkey]
    current_time = int(time.time())
    revocation_time = data['time']
    revocation_reason = data['reason']
    raise OperationalError(
        msg=u"The certificate has been revoked: current_time={0}, "
            u"time={1}, reason={2}".format(
            strftime('%Y%m%d%H%M%SZ', gmtime(current_time)),
            revocation_time,
            revocation_reason),
        errno=ER_SERVER_CERTIFICATE_REVOKED,
    )


def _process_unknown_status(hkey):
    """
    Process Unknown status
    """
    with OCSP_VALIDATION_CACHE_LOCK:
        if hkey in OCSP_VALIDATION_CACHE:
            global OCSP_VALIDATION_CACHE_UPDATED
            OCSP_VALIDATION_CACHE_UPDATED = True
            del OCSP_VALIDATION_CACHE[hkey]
    raise OperationalError(
        msg=u"The certificate is in UNKNOWN revocation status.",
        errno=ER_SERVER_CERTIFICATE_REVOKED,
    )


# Signature Hash Algorithm
sha1WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
sha256WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
sha384WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.12')
sha512WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.13')

SIGNATURE_HASH_ALGO_TO_NAME = {
    sha1WithRSAEncryption: 'sha1',
    sha256WithRSAEncryption: 'sha256',
    sha384WithRSAEncryption: 'sha384',
    sha512WithRSAEncryption: 'sha512',
}

# OCSP SIGNING flag
OCSP_SIGNING = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.9')

# Maximum clock skew in seconds (15 minutes) allowed when checking
# validity of OCSP responses
MAX_CLOCK_SKEW = 900

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

# Known certificates that can skip OCSP validation
KNOWN_HOSTNAMES = {
    '',
}

# CRL string match
CRL_RE = re.compile(r'^\s*URI:(.*)$')

# OCSP cache
OCSP_VALIDATION_CACHE = {}

# OCSP cache lock
OCSP_VALIDATION_CACHE_LOCK = Lock()

# OCSP cache update flag
OCSP_VALIDATION_CACHE_UPDATED = False

# OCSP string match
OCSP_RE = re.compile(r'^OCSP\s+\-\s+URI:(.*)$')

# OCSP response mapping
OCSP_RESPONSE_STATUS = {
    0: 'successful',
    1: 'malformedRequest',
    2: 'internalError',
    3: 'tryLater',
    4: 'not used',
    5: 'sigRequired',
    6: 'unauthorized'
}

# OCSP cache server URL where Snowflake provides OCSP response cache for
# better availability.
SF_OCSP_RESPONSE_CACHE_SERVER_URL = os.getenv(
    "SF_OCSP_RESPONSE_CACHE_SERVER_URL",
    "http://ocsp.snowflakecomputing.com/{0}".format(
        OCSP_RESPONSE_CACHE_FILE_NAME))
SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED = os.getenv(
    "SF_OCSP_RESPONSE_CACHE_SERVER_ENABLED", "false") != "false"

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
    except Exception as e:
        logger = getLogger(__name__)
        logger.warn('cannot create a cache directory: %s', CACHE_DIR)
        CACHE_DIR = None


class SnowflakeOCSP(object):
    """
    OCSP validator using PyOpenSSL.
    """

    def __init__(self, must_use_cache=False,
                 proxies=None,
                 ocsp_response_cache_uri=None):
        """
        :param must_use_cache: Test purpose. must use cache or raises an error
        :param ocsp_response_cache_uri: the location of cache file
        """
        self._must_use_cache = must_use_cache
        self._proxies = proxies
        if ocsp_response_cache_uri is None and CACHE_DIR is not None:
            self._ocsp_response_cache_uri = 'file://' + path.join(
                CACHE_DIR, OCSP_RESPONSE_CACHE_FILE_NAME)
        else:
            self._ocsp_response_cache_uri = ocsp_response_cache_uri

        if self._ocsp_response_cache_uri is not None:
            self._ocsp_response_cache_uri = self._ocsp_response_cache_uri.replace(
                '\\', '/')

        logger.debug("ocsp_response_cache_uri: %s",
                     self._ocsp_response_cache_uri)
        logger.debug(
            "OCSP_VALIDATION_CACHE size: %s", len(OCSP_VALIDATION_CACHE))

        if self._ocsp_response_cache_uri is not None:
            try:
                with OCSP_VALIDATION_CACHE_LOCK:
                    parsed_url = urlsplit(self._ocsp_response_cache_uri)
                    if parsed_url.scheme == 'file':
                        read_ocsp_response_cache_file(
                            path.join(parsed_url.netloc, parsed_url.path),
                            OCSP_VALIDATION_CACHE)
                    else:
                        raise Exception(
                            "Unsupported OCSP URI: %s",
                            self._ocsp_response_cache_uri)
            except Exception as e:
                logger.debug(
                    "Failed to read OCSP response cache file %s: %s, "
                    "No worry. It will validate with OCSP server. "
                    "Ignoring...",
                    self._ocsp_response_cache_uri, e, exc_info=True)
        #
        # load 'charmap' encoding here so that
        # no load concurrency issue happens later
        #
        'test'.encode("charmap")
        _get_pyasn1_version()

    def validate(self, hostname, connection,
                 ignore_no_ocsp=False):
        u"""
        Validates the certificate is not revoked using OCSP
        """
        global OCSP_VALIDATION_CACHE_UPDATED
        logger.debug(u'validating certificate: %s', hostname)
        if ignore_no_ocsp:
            logger.debug(u'validation was skipped.')
            return True

        if hostname in KNOWN_HOSTNAMES:  # skip OCSP validation if known
            logger.debug(
                'validation was skipped, because hostname %s is known',
                hostname)
            return True

        cert_data = _extract_certificate_chain(connection)

        pool = ThreadPool(len(cert_data))
        results = []
        try:
            for issuer_and_subject in cert_data:
                ocsp_uri = issuer_and_subject['subject'][
                    'ocsp_uri']  # issuer's ocsp uri
                ocsp_subject = issuer_and_subject['subject']
                ocsp_issuer = issuer_and_subject['issuer']
                logger.debug('ocsp_uri: %s', ocsp_uri)
                if ocsp_uri:
                    r = pool.apply_async(
                        self.validate_by_direct_connection_simple,
                        [ocsp_uri, ocsp_issuer, ocsp_subject])
                    results.append(r)
                else:
                    raise OperationalError(
                        msg=(u'NO OCSP URI was found: '
                             u'hostname={0}, subject={1}').format(
                            hostname, ocsp_subject),
                        errno=ER_FAILED_TO_GET_OCSP_URI,
                    )
        finally:
            pool.close()
            pool.join()
            for r in results:
                if not r.successful():
                    raise OperationalError(
                        msg=(u'Failed to validate the certificate '
                             u'revocation status: '
                             u'hostname={0}, err={1}', hostname, r.get()))
            with OCSP_VALIDATION_CACHE_LOCK:
                if OCSP_VALIDATION_CACHE_UPDATED:
                    update_ocsp_response_cache_file(
                        self._ocsp_response_cache_uri)
                OCSP_VALIDATION_CACHE_UPDATED = False

            if len(results) != len(cert_data):
                raise OperationalError(
                    msg=u"Failed to validate the certificate "
                        u"revocation status. The number of validation "
                        u"didn't match: hostname={0}, retsults={1}, "
                        u"cert_data={2}".format(hostname, len(results),
                                                len(cert_data)),
                    errno=ER_INVALID_OCSP_RESPONSE)
        logger.debug(u'ok')
        # any failure must be an exception
        return True

    def validate_by_direct_connection_simple(
            self, ocsp_uri, ocsp_issuer, ocsp_subject):
        ret, _, _ = self.validate_by_direct_connection(
            ocsp_uri, ocsp_issuer, ocsp_subject)
        return ret

    def validate_by_direct_connection(
            self, ocsp_uri, ocsp_issuer, ocsp_subject,
            do_retry=True, use_cache=True):
        """
        Validates the certificate using requests package
        """
        cache_status, cert_id, ocsp_response = is_cert_id_in_cache(
            ocsp_issuer, ocsp_subject, use_cache=use_cache)

        logger.debug('must_use_cache: %s, cache_status: %s',
                     self._must_use_cache, cache_status)

        # Disabled assert. If two distinct certificates are used
        # for the same URL, e.g., AWS S3 endpoint, one cannot hit
        # other in the cache.
        #
        # assert not self._must_use_cache or \
        #       self._must_use_cache and cache_status, \
        #       'Test: Must use cache! must_use_cache: {0}, '
        #       'cache_status: {1}'.format(self._must_use_cache, cache_status)

        err = None
        max_retry = 100 if do_retry else 1
        # NOTE: this retry is connection error retry
        for retry in range(max_retry):
            try:
                if not cache_status:
                    # not cached or invalid
                    logger.debug('getting OCSP response from remote')
                    ocsp_response = execute_ocsp_request(
                        ocsp_uri, cert_id,
                        proxies=self._proxies,
                        do_retry=do_retry)
                else:
                    logger.debug('using OCSP response cache')
                single_response_map = process_ocsp_response(
                    ocsp_response, ocsp_issuer)
                check_ocsp_response_status(
                    single_response_map,
                    ocsp_response)
                err = None
                break
            except Exception as e:
                logger.warning(
                    'Failed to get OCSP response: %s. '
                    'Retrying...%s/%s .', e, retry + 1, max_retry)
                err = e
                if max_retry == 1:
                    raise err
                # if fails, it always attempts to access the OCSP server
                # to get the fresh status
                cache_status = False
        if err:
            raise err

        return True, cert_id, ocsp_response

    def generate_cert_id_response(
            self, hostname, connection, do_retry=True):
        cert_data = _extract_certificate_chain(connection)
        return self.generate_cert_id_response0(
            hostname, cert_data, do_retry=do_retry, use_cache=False)

    def generate_cert_id_response0(
            self, hostname, cert_data, do_retry=True, use_cache=False):
        current_time = int(time.time())
        results = {}
        for issuer_and_subject in cert_data:
            ocsp_uri = issuer_and_subject['subject'][
                'ocsp_uri']  # issuer's ocsp uri
            ocsp_subject = issuer_and_subject['subject']
            ocsp_issuer = issuer_and_subject['issuer']
            logger.debug('ocsp_uri: %s', ocsp_uri)
            if ocsp_uri:
                ret, cert_id, ocsp_response = \
                    self.validate_by_direct_connection(
                        ocsp_uri, ocsp_issuer, ocsp_subject,
                        do_retry=do_retry, use_cache=use_cache)
                if ret and cert_id and ocsp_response:
                    cert_id_der = der_encoder.encode(cert_id)
                    results[cert_id_der] = (
                        current_time,
                        ocsp_issuer,
                        ocsp_subject,
                        ocsp_response)
            else:
                raise OperationalError(
                    msg=(u'NO OCSP URI was found: '
                         u'hostname={0}, subject={1}').format(
                        hostname, ocsp_subject),
                    errno=ER_FAILED_TO_GET_OCSP_URI,
                )
        logger.debug(u'ok')
        return results
