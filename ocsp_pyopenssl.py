#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#

"""
Use openssl command line to validate the certification revocation status
using OCSP.
"""
import base64
import calendar
import codecs
import hashlib
import json
import logging
import os
import platform
import re
import socket
import time
from logging import getLogger
from multiprocessing.pool import ThreadPool
from os import path
from threading import (Lock)
from time import gmtime, strftime, strptime

import OpenSSL
from OpenSSL.crypto import (dump_certificate, FILETYPE_PEM, FILETYPE_ASN1,
                            load_certificate)
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

ROOT_CERTIFICATES_DICT_LOCK = Lock()

ROOT_CERTIFICATES_DICT = {}  # root certificates


def _read_ca_bundle(ca_bundle_file):
    """
    Reads a cabundle file including certificates in PEM format
    """
    logger = getLogger(__name__)
    logger.debug('reading ca cabundle: %s', ca_bundle_file)
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
                ROOT_CERTIFICATES_DICT[cert.get_subject().der()] = cert
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
            _read_ca_bundle(ca_bundle)
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
                _read_ca_bundle(ca_bundle)
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
                        _read_ca_bundle(ca_bundle)
                        break
                else:
                    logger.error('No cabundle file is found in _MEIPASS')
            try:
                import certifi
                _read_ca_bundle(certifi.where())
            except:
                logger.debug('no certifi is installed. ignored.')

    except Exception as e:
        logger.error('Failed to read ca_bundle: %s', e)

    if len(ROOT_CERTIFICATES_DICT) == 0:
        logger.error('No CA bundle file is found in the system. '
                     'Set REQUESTS_CA_BUNDLE to the file.')


def dump_publickey(type, pkey):
    """
    COPIED FROM the latest PyOpenSSL code. Remove this PyOpenSSL 1.6+

    Dump a public key to a buffer.
    :param type: The file type (one of :data:`FILETYPE_PEM` or
        :data:`FILETYPE_ASN1`).
    :param PKey pkey: The public key to dump
    :return: The buffer with the dumped key in it.
    :rtype: bytes
    """
    bio = OpenSSL.crypto._new_mem_buf()
    if type == FILETYPE_PEM:
        write_bio = OpenSSL.crypto._lib.PEM_write_bio_PUBKEY
    elif type == OpenSSL.crypto.FILETYPE_ASN1:
        write_bio = OpenSSL.crypto._lib.i2d_PUBKEY_bio
    else:
        raise ValueError("type argument must be FILETYPE_PEM or FILETYPE_ASN1")

    result_code = write_bio(bio, pkey._pkey)
    if result_code != 1:  # pragma: no cover
        OpenSSL.crypto._raise_current_error()

    return OpenSSL.crypto._bio_to_string(bio)


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
    cert_der = cert.get_subject().der()
    sha1_hash = hashlib.sha1()
    sha1_hash.update(cert_der)
    data[u'name_hash'] = sha1_hash.hexdigest()

    # public key Hash
    data['key_hash'] = _get_pubickey_sha1_hash(cert).hexdigest()

    # ocsp uri
    ocsp_uris0 = []
    for idx in range(cert.get_extension_count()):
        e = cert.get_extension(idx)
        if e.get_short_name() == b'authorityInfoAccess':
            for line in str(e).split(u"\n"):
                m = OCSP_RE.match(line)
                if m:
                    logger.debug(u'OCSP URL: %s', m.group(1))
                    ocsp_uris0.append(m.group(1))

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
        data[u'is_root_ca'] = cert.get_subject() == cert.get_issuer()
        logger.debug('is_root_ca: %s', data[u'is_root_ca'])
        cert_data[cert.get_subject().der()] = data

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

    if basic_ocsp_response['certs'] is not None:
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

    if tbs_response_data['responderID']['byName']:
        # Noop
        logger.debug(
            'Responder Name: %s',
            tbs_response_data['responderID']['byName'])
    elif tbs_response_data['responderID']['byKey']:
        # verify the public key
        # But I don't know how much value of this checking
        # because pubkey must have been known to anybody
        # MITM can replicate it.
        sha1_cert = _get_pubickey_sha1_hash(ocsp_cert).digest()
        sha1_ocsp = tbs_response_data['responderID']['byKey']
        sha1_ocsp = octet_string_to_bytearray(sha1_ocsp).decode(
            'latin-1').encode('latin-1')

        if sha1_cert != sha1_ocsp:
            raise OperationalError(
                msg=u"The responder id didn't match the public key"
                    u"of the issuer certificate/leaf certificate",
                errno=ER_INVALID_OCSP_RESPONSE
            )
        if logger.getEffectiveLevel() == logging.DEBUG:
            logger.debug(
                'Responder PublicKey: %s',
                base64.b64encode(octet_string_to_bytearray(
                    tbs_response_data['responderID']['byKey'])))
    else:
        raise OperationalError(
            msg='Invalid Responder ID: {0}'.format(
                tbs_response_data['responderID']),
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
        cert_id_der = der_encoder.encode(cert_id)
        if cert_status['good'] is not None:
            logger.debug('ok')
            this_update = strptime(str(single_response['thisUpdate']),
                                   '%Y%m%d%H%M%SZ')
            next_update = strptime(str(single_response['nextUpdate']),
                                   '%Y%m%d%H%M%SZ')
            this_update = calendar.timegm(this_update)
            next_update = calendar.timegm(next_update)
            single_response_map[cert_id_der] = {
                'status': 'good',
                'this_update': this_update,
                'next_update': next_update,
            }
        elif cert_status['revoked'] is not None:
            logger.info('revoked: %s', cert_status['revoked'])
            # revocation
            revocation_time = cert_status['revoked']['revocationTime']
            revocation_reason = cert_status['revoked']['revocationReason']
            single_response_map[cert_id_der] = {
                'status': 'revoked',
                'time': revocation_time,
                'reason': revocation_reason,
            }
        else:
            logger.info('unknown')
            single_response_map[cert_id_der] = {
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
        'Content-Length': '{0}'.format(
            len(data)),
        'Host': parsed_url.hostname.encode(
            'utf-8'),
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

    cert_id_der = der_encoder.encode(cert_id)

    if logger.getEffectiveLevel() == logging.DEBUG:
        base64_issuer_name_hash = base64.b64encode(
            octet_string_to_bytearray(cert_id['issuerNameHash']))
    else:
        base64_issuer_name_hash = None

    with OCSP_VALIDATION_CACHE_LOCK:
        if use_cache and cert_id_der in OCSP_VALIDATION_CACHE:
            current_time = int(time.time())
            ts, cache = OCSP_VALIDATION_CACHE[cert_id_der]
            if ts - CACHE_EXPIRATION <= current_time <= ts + CACHE_EXPIRATION:
                # cache value is OCSP response
                logger.debug(u'hit cache: %s', base64_issuer_name_hash)
                return True, cert_id, cache
            else:
                # more than 24 hours difference
                del OCSP_VALIDATION_CACHE[cert_id_der]

    logger.debug(u'not hit cache: %s', base64_issuer_name_hash)
    return False, cert_id, None


def _decode_ocsp_response_cache(ocsp_response_cache_json,
                                ocsp_response_cache):
    """
    Decodes OCSP response cache from JSON
    """
    from base64 import b64decode
    current_time = int(time.time())
    for cert_id, (ts, ocsp_response) in ocsp_response_cache_json.items():
        cert_id_der = b64decode(cert_id)
        if ts - CACHE_EXPIRATION <= current_time <= ts + CACHE_EXPIRATION:
            ocsp_response_cache[cert_id_der] = (ts, b64decode(
                ocsp_response))
        elif cert_id_der in ocsp_response_cache:
            # invalidate the cache if exists
            del ocsp_response_cache[cert_id_der]


def _encode_ocsp_response_cache(ocsp_response_cache,
                                ocsp_response_cache_json):
    """
    Encodes OCSP response cache to JSON
    """
    logger = getLogger(__name__)
    logger.debug('encoding OCSP reponse cache to JSON')
    for cert_id_der, (current_time, ocsp_response) in \
            ocsp_response_cache.items():
        k = base64.b64encode(cert_id_der).decode('ascii')
        v = base64.b64encode(ocsp_response).decode('ascii')
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
            "validate with OCSP server.: %s, %s, %s",
            filename, lock_file, e
        )
    return False


def read_ocsp_response_cache_file(filename, ocsp_validation_cache):
    """
    Reads OCSP Response cache
    """
    logger = getLogger(__name__)
    if check_ocsp_response_cache_lock_file(filename) and path.exists(filename):
        _decode_ocsp_response_cache(
            json.load(
                codecs.open(
                    filename, 'r', encoding='utf-8', errors='ignore')),
            ocsp_validation_cache)
        logger.debug("Read OCSP response cache file: %s", filename)
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
    _encode_ocsp_response_cache(
        ocsp_validation_cache,
        file_cache_data
    )
    with codecs.open(filename, 'w', encoding='utf-8', errors='ignore') as f:
        json.dump(file_cache_data, f)


def update_ocsp_response_cache_file(ocsp_response_cache_url):
    """
    Updates OCSP Response Cache
    """
    logger = getLogger(__name__)
    lock_file = None
    if ocsp_response_cache_url is not None:
        try:
            parsed_url = urlsplit(ocsp_response_cache_url)
            if parsed_url.scheme == 'file':
                filename = path.join(parsed_url.netloc, parsed_url.path)
                lock_file = filename + '.lck'
                if not path.exists(lock_file):
                    touch(lock_file)
                    try:
                        write_ocsp_response_cache_file(
                            filename,
                            OCSP_VALIDATION_CACHE)
                        logger.info(
                            "Wrote OCSP response cache file: %s",
                            ocsp_response_cache_url)
                    finally:
                        os.unlink(lock_file)
                        lock_file = None
            else:
                logger.info(
                    "No OCSP response cache file is written, because the "
                    "given URI is not a file: %s. Ignoring...",
                    ocsp_response_cache_url)
        except Exception as e:
            logger.info(
                "Failed to write OCSP response cache "
                "file: %s: %s, Ignoring...",
                ocsp_response_cache_url, e, exc_info=True)

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
    import binascii
    with requests.Session() as session:
        session.mount('http://', HTTPAdapter(max_retries=5))
        session.mount('https://', HTTPAdapter(max_retries=5))
        response = session.get(url)
    if response.status_code == OK:
        try:
            _decode_ocsp_response_cache(response.json(), OCSP_VALIDATION_CACHE)
        except (ValueError, binascii.Error) as err:
            logger = getLogger(__name__)
            logger.info(
                'Failed to convert OCSP cache server response to '
                'JSON. The cache was corrupted. No worry. It will'
                'validate with OCSP server: %s', err)
    else:
        logger = getLogger(__name__)
        logger.info("Failed to get OCSP response cache from %s: %s",
                    url, response.status_code)


def check_ocsp_response_status(
        single_response_map,
        ocsp_response, ocsp_response_cache_url):
    """
    Checks the OCSP response status
    """
    ret = []
    for cert_id_der, data in single_response_map.items():
        if data['status'] == 'good':
            ret.append(_process_good_status(
                cert_id_der, data, ocsp_response,
                ocsp_response_cache_url))
        elif data['status'] == 'revoked':  # revoked
            _process_revoked_status(cert_id_der, data)
        else:  # unknown
            _process_unknown_status(cert_id_der)
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


def _process_good_status(
        cert_id_der, data, ocsp_response, ocsp_response_cache_url):
    """
    Process Good status
    """
    logger = getLogger(__name__)
    current_time = int(time.time())
    this_update = data['this_update']
    next_update = data['next_update']
    if _is_validaity_range(current_time, this_update, next_update):
        with OCSP_VALIDATION_CACHE_LOCK:
            if cert_id_der not in OCSP_VALIDATION_CACHE:
                OCSP_VALIDATION_CACHE[cert_id_der] = (
                    current_time, ocsp_response)
                update_ocsp_response_cache_file(
                    ocsp_response_cache_url)
                if logger.getEffectiveLevel() == logging.DEBUG:
                    cert_id, _ = der_decoder.decode(
                        cert_id_der, asn1Spec=CertID())
                    logger.debug(
                        u'store cache: %s, this_update: %s, '
                        u'next_update: %s',
                        base64.b64encode(
                            octet_string_to_bytearray(
                                cert_id['issuerNameHash'])),
                        this_update, next_update)
        return True
    else:
        raise OperationalError(
            msg=_validity_error_message(current_time, this_update, next_update),
            errno=ER_INVALID_OCSP_RESPONSE
        )


def _process_revoked_status(cert_id_der, data):
    """
    Process Revoked status
    """
    with OCSP_VALIDATION_CACHE_LOCK:
        if cert_id_der in OCSP_VALIDATION_CACHE:
            del OCSP_VALIDATION_CACHE[cert_id_der]
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


def _process_unknown_status(cert_id_der):
    """
    Process Unknown status
    """
    with OCSP_VALIDATION_CACHE_LOCK:
        if cert_id_der in OCSP_VALIDATION_CACHE:
            del OCSP_VALIDATION_CACHE[cert_id_der]
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

# OCSP cache
OCSP_VALIDATION_CACHE = {}

# OCSP cache lock
OCSP_VALIDATION_CACHE_LOCK = Lock()

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

# Cache directory
if platform.system() == 'Windows':
    CACHE_DIR = path.join(
        os.getenv('USERPROFILE'), 'AppData', 'Local',
        'Snowflake', 'Caches')
elif platform.system() == 'Darwin':
    CACHE_DIR = path.join(
        os.getenv('HOME'), 'Library', 'Caches', 'Snowflake')
else:
    CACHE_DIR = path.join(
        os.getenv('HOME', '/tmp'), '.cache', 'snowflake')

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
                 proxies=None, ocsp_response_cache_url=None):
        """
        :param must_use_cache: Test purpose. must use cache or raises an error
        :param ocsp_response_cache_url: the location of cache file
        """
        self.logger = getLogger(__name__)
        self._must_use_cache = must_use_cache
        self._proxies = proxies
        if ocsp_response_cache_url is None and CACHE_DIR is not None:
            self._ocsp_response_cache_url = 'file://' + path.join(
                CACHE_DIR, 'ocsp_response_cache')
        else:
            self._ocsp_response_cache_url = ocsp_response_cache_url

        if self._ocsp_response_cache_url is not None:
            self._ocsp_response_cache_url = self._ocsp_response_cache_url.replace(
                '\\', '/')

        self.logger.debug("ocsp_response_cache_url: %s",
                         self._ocsp_response_cache_url)
        self.logger.debug(
            "OCSP_VALIDATION_CACHE size: %s", len(OCSP_VALIDATION_CACHE))

        if self._ocsp_response_cache_url is not None and \
                        len(OCSP_VALIDATION_CACHE) == 0:
            try:
                with OCSP_VALIDATION_CACHE_LOCK:
                    parsed_url = urlsplit(self._ocsp_response_cache_url)
                    if parsed_url.scheme == 'file':
                        read_ocsp_response_cache_file(
                            path.join(parsed_url.netloc, parsed_url.path),
                            OCSP_VALIDATION_CACHE)
                    elif parsed_url.schema in ('http', 'https'):
                        download_ocsp_response_cache(ocsp_response_cache_url)
            except Exception as e:
                self.logger.info(
                    "Failed to read OCSP response cache file %s: %s, "
                    "No worry. It will validate with OCSP server. "
                    "Ignoring...",
                    self._ocsp_response_cache_url, e)
                self.logger.exception(e)
        #
        # load 'charmap' encoding here so that 
        # no load concurrency issue happens later
        #
        'test'.encode("charmap")

    def validate(self, hostname, connection,
                 ignore_no_ocsp=False):
        u"""
        Validates the certificate is not revoked using OCSP
        """
        self.logger.debug(u'validating certificate: %s', hostname)
        if ignore_no_ocsp:
            self.logger.debug(u'validation was skipped.')
            return True

        if hostname in KNOWN_HOSTNAMES:  # skip OCSP validation if known
            self.logger.debug(
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
                self.logger.debug('ocsp_uri: %s', ocsp_uri)
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
            if len(results) != len(cert_data):
                raise OperationalError(
                    msg=u"Failed to validate the certificate "
                        u"revocation status. The number of validation "
                        u"didn't match: hostname={0}, retsults={1}, "
                        u"cert_data={2}".format(hostname, len(results),
                                                len(cert_data)),
                    errno=ER_INVALID_OCSP_RESPONSE)
        self.logger.debug(u'ok')
        # any failure must be an exception
        return True

    def validate_by_direct_connection_simple(
            self, ocsp_uri, ocsp_issuer, ocsp_subject):
        ret, _, _ = self.validate_by_direct_connection(
            ocsp_uri, ocsp_issuer, ocsp_subject)
        return ret

    def validate_by_direct_connection(
            self, ocsp_uri, ocsp_issuer, ocsp_subject, do_retry=True):
        u"""
        Validates the certificate using requests package
        """
        # If we do retry, use cache
        use_cache = do_retry
        cache_status, cert_id, ocsp_response = is_cert_id_in_cache(
            ocsp_issuer, ocsp_subject, use_cache=use_cache)

        assert not self._must_use_cache or \
               self._must_use_cache and cache_status, 'Test: Must use cache!'

        err = None
        max_retry = 100 if do_retry else 1
        # NOTE: this retry is connection error retry
        for retry in range(max_retry):
            # retry up to three times
            try:
                if not cache_status:
                    # not cached or invalid
                    self.logger.debug('getting OCSP response from remote')
                    ocsp_response = execute_ocsp_request(
                        ocsp_uri, cert_id,
                        proxies=self._proxies,
                        do_retry=do_retry)
                else:
                    self.logger.debug('using OCSP response cache')
                single_response_map = process_ocsp_response(
                    ocsp_response, ocsp_issuer)
                check_ocsp_response_status(
                    single_response_map,
                    ocsp_response,
                    self._ocsp_response_cache_url)
                err = None
                break
            except Exception as e:
                self.logger.warning(
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
            self, hostname, connection, proxies=None, do_retry=True):
        current_time = int(time.time())
        cert_data = _extract_certificate_chain(connection)
        results = {}
        for issuer_and_subject in cert_data:
            ocsp_uri = issuer_and_subject['subject'][
                'ocsp_uri']  # issuer's ocsp uri
            ocsp_subject = issuer_and_subject['subject']
            ocsp_issuer = issuer_and_subject['issuer']
            self.logger.debug('ocsp_uri: %s', ocsp_uri)
            if ocsp_uri:
                ret, cert_id, ocsp_response = \
                    self.validate_by_direct_connection(
                        ocsp_uri, ocsp_issuer, ocsp_subject,
                        do_retry=do_retry)
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
        self.logger.debug(u'ok')
        return results


def cli_ocsp_dump_response():
    """
    Internal Tool: OCSP response dumper
    """
    from OpenSSL.SSL import SSLv23_METHOD, Context, Connection

    def _openssl_connect(hostname, port=443):
        client = socket.socket()
        client.connect((hostname, port))
        client_ssl = Connection(Context(SSLv23_METHOD), client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(hostname.encode('utf-8'))
        client_ssl.do_handshake()
        return client_ssl

    import sys
    url = len(sys.argv) > 1 and sys.argv[1] or ''
    if url in ('-h', ''):
        print(
            "OCSP Response dumper. This tools dumps key information in OCSP "
            "response for the given URL and validates the certificate "
            "revocation status. The output is subject to change.")
        print("""
Usage: {0} <url>
""".format(path.basename(sys.argv[0])))
        sys.exit(2)
    elif url.startswith('https://'):
        parsed_url = urlsplit(url)
        url = parsed_url.hostname
        port = int(parsed_url.port or 443)
    else:
        port = 443

    ocsp = SnowflakeOCSP()
    connection = _openssl_connect(url, port)
    results = ocsp.generate_cert_id_response(url, connection, proxies=None)
    current_Time = int(time.time())
    print("Target URL: https://{0}:{1}/".format(url, port))
    print("Current Time: {0}".format(
        strftime('%Y%m%d%H%M%SZ', gmtime(current_Time))))
    for cert_id, (current_time, issuer, subject, ocsp_response) in \
            results.items():
        cert_id, _ = der_decoder.decode(cert_id, CertID())
        ocsp_response, _ = der_decoder.decode(ocsp_response, OCSPResponse())
        print("------------------------------------------------------------")
        print("Issuer Name: {0}".format(issuer['cert'].get_subject()))
        print("Subject Name: {0}".format(subject['cert'].get_subject()))
        print("OCSP URI: {0}".format(subject['ocsp_uri']))
        print("Issuer Name Hash: {0}".format(
            octet_string_to_bytearray(cert_id['issuerNameHash']).decode(
                'latin-1').encode('latin-1')))
        print("Issuer Key Hash: {0}".format(
            octet_string_to_bytearray(cert_id['issuerKeyHash']).decode(
                'latin-1').encode('latin-1')))
        print("Serial Number: {0}".format(cert_id['serialNumber']))
        if ocsp_response['responseStatus'] == OCSPResponseStatus('successful'):
            status = "successful"
        elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                'malformedRequest'):
            status = "malformedRequest"
        elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                'internalError'):
            status = "internalError"
        elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                'tryLater'):
            status = "tryLater"
        elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                'sigRequired'):
            status = "sigRequired"
        elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                'unauthorized'):
            status = "unauthorized"
        else:
            status = "Unknown"
        print("Response Status: {0}".format(status))
        response_bytes = ocsp_response['responseBytes']
        basic_ocsp_response, _ = der_decoder.decode(
            response_bytes['response'],
            BasicOCSPResponse())
        tbs_response_data = basic_ocsp_response['tbsResponseData']
        if tbs_response_data['responderID']['byName']:
            print("Responder Name: {0}".format(
                tbs_response_data['responderID']['byName']))
        elif tbs_response_data['responderID']['byKey']:
            sha1_ocsp = tbs_response_data['responderID']['byKey']
            sha1_ocsp = octet_string_to_bytearray(sha1_ocsp).decode(
                'latin-1').encode('latin-1')
            print("Responder Key: {0}".format(sha1_ocsp))
        if tbs_response_data['responseExtensions']:
            print('Response Extensions: %s',
                  tbs_response_data['responseExtensions'])
        for single_response in tbs_response_data['responses']:
            cert_status = single_response['certStatus']
            if cert_status['good'] is not None:
                print("This Update: {0}".format(
                    single_response['thisUpdate']))
                print("Next Update: {0}".format(
                    single_response['nextUpdate']))
                this_update = strptime(str(single_response['thisUpdate']),
                                       '%Y%m%d%H%M%SZ')
                next_update = strptime(str(single_response['nextUpdate']),
                                       '%Y%m%d%H%M%SZ')
                this_update = calendar.timegm(this_update)
                next_update = calendar.timegm(next_update)
                tolerable_validity = _calculate_tolerable_validity(this_update,
                                                                   next_update)
                print("Tolerable Update: {0}".format(
                    strftime('%Y%m%d%H%M%SZ', gmtime(
                        next_update + tolerable_validity))
                ))
                if _is_validaity_range(current_time, this_update, next_update):
                    print("OK")
                else:
                    print(_validity_error_message(
                        current_time, this_update, next_update))
            elif cert_status['revoked'] is not None:
                revocation_time = cert_status['revoked']['revocationTime']
                revocation_reason = cert_status['revoked']['revocationReason']
                print("Revoked Time: {0}".format(revocation_time))
                print("Revoked Reason: {0}".format(revocation_reason))
                print("Revoked")
            else:
                print("Unknown")
