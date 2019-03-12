#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

from datetime import datetime, timezone

from base64 import b64encode, b64decode
from logging import getLogger

from Cryptodome.Hash import SHA256, SHA384, SHA1, SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from asn1crypto.algos import DigestAlgorithm
from asn1crypto.core import OctetString, Integer
from asn1crypto.ocsp import CertId, OCSPRequest, TBSRequest, Requests, \
    Request, OCSPResponse, Version
from asn1crypto.x509 import Certificate

from snowflake.connector.errorcode import (
    ER_INVALID_OCSP_RESPONSE,
    ER_INVALID_OCSP_RESPONSE_CODE)
from snowflake.connector.errors import OperationalError
from snowflake.connector.ocsp_snowflake import SnowflakeOCSP
from collections import OrderedDict
from snowflake.connector.ssd_internal_keys import ret_wildcard_hkey

logger = getLogger(__name__)


class SnowflakeOCSPAsn1Crypto(SnowflakeOCSP):
    """
    OCSP checks by asn1crypto
    """

    # map signature algorithm name to digest class
    SIGNATURE_ALGORITHM_TO_DIGEST_CLASS = {
        'sha256': SHA256,
        'sha384': SHA384,
        'sha512': SHA512,
    }

    WILDCARD_CERTID = None

    def __init__(self, **kwargs):
        super(SnowflakeOCSPAsn1Crypto, self).__init__(**kwargs)
        self.WILDCARD_CERTID = self.encode_cert_id_key(ret_wildcard_hkey())

    def encode_cert_id_key(self, hkey):
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

    def decode_cert_id_key(self, cert_id):
        return (cert_id['issuer_name_hash'].dump(),
                cert_id['issuer_key_hash'].dump(),
                cert_id['serial_number'].dump())

    def decode_cert_id_base64(self, cert_id_base64):
        return CertId.load(b64decode(cert_id_base64))

    def encode_cert_id_base64(self, hkey):
        return b64encode(self.encode_cert_id_key(hkey).dump()).decode('ascii')

    def read_cert_bundle(self, ca_bundle_file, storage=None):
        """
        Reads a certificate file including certificates in PEM format
        """
        if storage is None:
            storage = SnowflakeOCSP.ROOT_CERTIFICATES_DICT
        logger.debug('reading certificate bundle: %s', ca_bundle_file)
        all_certs = open(ca_bundle_file, 'rb').read()

        # don't lock storage
        from asn1crypto import pem
        pem_certs = pem.unarmor(all_certs, multiple=True)
        for type_name, _, der_bytes in pem_certs:
            if type_name == 'CERTIFICATE':
                crt = Certificate.load(der_bytes)
                storage[crt.subject.sha256] = crt

    def create_ocsp_request(self, issuer, subject):
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
        ocsp_request = OCSPRequest({
            'tbs_request': TBSRequest({
                'version': Version(0),
                'request_list': Requests([
                    Request({
                        'req_cert': cert_id,
                    })]),
            }),
        })
        return cert_id, ocsp_request

    def extract_ocsp_url(self, cert):
        urls = cert.ocsp_urls
        ocsp_url = urls[0] if urls else None
        return ocsp_url

    def decode_ocsp_request(self, ocsp_request):
        return ocsp_request.dump()

    def decode_ocsp_request_b64(self, ocsp_request):
        data = self.decode_ocsp_request(ocsp_request)  # convert to DER
        b64data = b64encode(data).decode('ascii')
        return b64data

    def extract_good_status(self, single_response):
        """
        Extract GOOD status
        """
        this_update_native = single_response['this_update'].native
        next_update_native = single_response['next_update'].native

        return this_update_native, next_update_native

    def extract_revoked_status(self, single_response):
        """
        Extract REVOKED status
        """
        revoked_info = single_response['cert_status']
        revocation_time = revoked_info.native['revocation_time']
        revocation_reason = revoked_info.native['revocation_reason']
        return revocation_time, revocation_reason

    def is_valid_time(self, cert_id, ocsp_response):
        res = OCSPResponse.load(ocsp_response)

        if res['response_status'].native != 'successful':
            raise OperationalError(
                msg="Invalid Status: {0}".format(res['response_status'].native),
                errno=ER_INVALID_OCSP_RESPONSE)

        basic_ocsp_response = res.basic_ocsp_response
        tbs_response_data = basic_ocsp_response['tbs_response_data']

        single_response = tbs_response_data['responses'][0]
        cert_status = single_response['cert_status'].name

        try:
            if cert_status == 'good':
                self._process_good_status(single_response, cert_id, ocsp_response)
        except Exception as ex:
            logger.debug("Failed to validate ocsp response %s", ex)
            return False

        return True

    def process_ocsp_response(self, issuer, cert_id, ocsp_response):
        try:
            res = OCSPResponse.load(ocsp_response)
        except Exception:
            raise OperationalError(
                msg='Invalid OCSP Response',
                errno=ER_INVALID_OCSP_RESPONSE
            )
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
            logger.debug(
                "Valid Not After: %s",
                 ocsp_cert['tbs_certificate']['validity']['not_after'].native)

            cur_time = datetime.now(timezone.utc)

            if cur_time > ocsp_cert['tbs_certificate']['validity']['not_after'].native or \
                    cur_time < ocsp_cert['tbs_certificate']['validity']['not_before'].native:
                raise OperationalError(
                    msg="Certificate attached to OCSP response is invalid. OCSP response "
                    "current time - {0} "
                    "certificate not before time - {1} "
                    "certificate not after time - {2}".
                        format(cur_time,
                               ocsp_cert['tbs_certificate']['validity']['not_before'].native,
                               ocsp_cert['tbs_certificate']['validity']['not_after'].native),
                    errno=ER_INVALID_OCSP_RESPONSE_CODE
                )

            self.verify_signature(
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
        self.verify_signature(
            basic_ocsp_response['signature_algorithm'].hash_algo,
            basic_ocsp_response['signature'].native,
            ocsp_cert,
            tbs_response_data)

        single_response = tbs_response_data['responses'][0]
        cert_status = single_response['cert_status'].name
        if cert_status == 'good':
            self._process_good_status(single_response, cert_id, ocsp_response)
            SnowflakeOCSP.OCSP_CACHE.update_cache(self, cert_id, ocsp_response)
        elif cert_status == 'revoked':
            self._process_revoked_status(single_response, cert_id)
        elif cert_status == 'unknown':
            self._process_unknown_status(cert_id)
        else:
            raise OperationalError(
                msg="Unknown revocation status was returned. OCSP response "
                    "may be malformed: {0}".format(cert_status),
                errno=ER_INVALID_OCSP_RESPONSE_CODE
            )

    def verify_signature(self, signature_algorithm, signature, cert, data):
        pubkey = cert.public_key.unwrap().dump()
        rsakey = RSA.importKey(pubkey)
        signer = PKCS1_v1_5.new(rsakey)
        if signature_algorithm in SnowflakeOCSPAsn1Crypto.SIGNATURE_ALGORITHM_TO_DIGEST_CLASS:
            digest = \
                SnowflakeOCSPAsn1Crypto.SIGNATURE_ALGORITHM_TO_DIGEST_CLASS[
                    signature_algorithm].new()
        else:
            # the last resort. should not happen.
            digest = SHA1.new()
        digest.update(data.dump())
        if not signer.verify(digest, signature):
            raise OperationalError(
                msg="Failed to verify the signature",
                errno=ER_INVALID_OCSP_RESPONSE)

    def extract_certificate_chain(self, connection):
        """
        Gets certificate chain and extract the key info from OpenSSL connection
        """
        from OpenSSL.crypto import dump_certificate, FILETYPE_ASN1
        cert_map = OrderedDict()
        logger.debug(
            "# of certificates: %s",
            len(connection.get_peer_cert_chain()))

        for cert_openssl in connection.get_peer_cert_chain():
            cert_der = dump_certificate(FILETYPE_ASN1, cert_openssl)
            cert = Certificate.load(cert_der)
            logger.debug(
                u'subject: %s, issuer: %s',
                cert.subject.native, cert.issuer.native)
            cert_map[cert.subject.sha256] = cert

        return self.create_pair_issuer_subject(cert_map)

    def create_pair_issuer_subject(self, cert_map):
        """
        Creates pairs of issuer and subject certificates
        """
        issuer_subject = []
        for subject_der in cert_map:
            subject = cert_map[subject_der]
            if subject.ocsp_no_check_value or \
                    subject.ca and not subject.ocsp_urls:
                # Root certificate will not be validated
                # but it is used to validate the subject certificate
                continue
            issuer_hash = subject.issuer.sha256
            if issuer_hash not in cert_map:
                # IF NO ROOT certificate is attached in the certificate chain
                # read it from the local disk
                self._lazy_read_ca_bundle()
                logger.debug('not found issuer_der: %s', subject.issuer.native)
                if issuer_hash not in SnowflakeOCSP.ROOT_CERTIFICATES_DICT:
                    raise OperationalError(
                        msg="CA certificate is NOT found in the root "
                            "certificate list. Make sure you use the latest "
                            "Python Connector package and the URL is valid.")
                issuer = SnowflakeOCSP.ROOT_CERTIFICATES_DICT[issuer_hash]
            else:
                issuer = cert_map[issuer_hash]

            issuer_subject.append((issuer, subject))
        return issuer_subject

    def subject_name(self, subject):
        return subject.subject.native
