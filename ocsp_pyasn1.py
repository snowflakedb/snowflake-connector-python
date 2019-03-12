#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2019 Snowflake Computing Inc. All right reserved.
#

import hashlib
import pytz
from base64 import b64encode, b64decode
from collections import OrderedDict
from datetime import datetime
from logging import getLogger
from threading import Lock

import pyasn1
from Cryptodome.Hash import SHA256, SHA384, SHA1, SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from OpenSSL.crypto import (
    FILETYPE_PEM,
    FILETYPE_ASN1,
    load_certificate, dump_certificate)
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.codec.native.encoder import encode as nat_encoder
from pyasn1.type import (univ, tag)
from pyasn1_modules import (rfc2459, rfc2437, rfc2560)

from snowflake.connector.ocsp_snowflake import SnowflakeOCSP
from .compat import (PY2)
from .errorcode import (ER_INVALID_OCSP_RESPONSE, ER_INVALID_OCSP_RESPONSE_CODE)
from .errors import (OperationalError)
from .rfc6960 import (
    OCSPRequest,
    OCSPResponse,
    TBSRequest,
    CertID,
    Request,
    OCSPResponseStatus,
    BasicOCSPResponse,
    Version)

from snowflake.connector.ssd_internal_keys import ret_wildcard_hkey

logger = getLogger(__name__)


class SnowflakeOCSPPyasn1(SnowflakeOCSP):
    """
    OCSP checks by pyasn1
    """

    PYASN1_VERSION_LOCK = Lock()
    PYASN1_VERSION = None

    # Signature Hash Algorithm
    sha1WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.5')
    sha256WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.11')
    sha384WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.12')
    sha512WithRSAEncryption = univ.ObjectIdentifier('1.2.840.113549.1.1.13')

    SIGNATURE_HASH_ALGO_TO_DIGEST_CLASS = {
        sha1WithRSAEncryption: SHA1,
        sha256WithRSAEncryption: SHA256,
        sha384WithRSAEncryption: SHA384,
        sha512WithRSAEncryption: SHA512,
    }

    WILDCARD_CERTID = None

    @staticmethod
    def _get_pyasn1_version():
        with SnowflakeOCSPPyasn1.PYASN1_VERSION_LOCK:
            if SnowflakeOCSPPyasn1.PYASN1_VERSION is not None:
                return SnowflakeOCSPPyasn1.PYASN1_VERSION

            v = pyasn1.__version__
            vv = [int(x, 10) for x in v.split('.')]
            vv.reverse()
            SnowflakeOCSPPyasn1.PYASN1_VERSION = sum(
                x * (1000 ** i) for i, x in enumerate(vv))
            return SnowflakeOCSPPyasn1.PYASN1_VERSION

    def __init__(self, **kwargs):
        super(SnowflakeOCSPPyasn1, self).__init__(**kwargs)
        self.WILDCARD_CERTID = self.encode_cert_id_key(ret_wildcard_hkey())

    def encode_cert_id_key(self, hkey):
        issuer_name_hash, issuer_key_hash, serial_number = hkey
        issuer_name_hash, _ = der_decoder.decode(issuer_name_hash)
        issuer_key_hash, _ = der_decoder.decode(issuer_key_hash)
        serial_number, _ = der_decoder.decode(serial_number)
        cert_id = CertID()
        cert_id.setComponentByName(
            'hashAlgorithm',
            rfc2459.AlgorithmIdentifier().setComponentByName(
                'algorithm', rfc2437.id_sha1))
        cert_id.setComponentByName('issuerNameHash', issuer_name_hash)
        cert_id.setComponentByName('issuerKeyHash', issuer_key_hash)
        cert_id.setComponentByName('serialNumber', serial_number)
        return cert_id

    def decode_cert_id_key(self, cert_id):
        return (
            der_encoder.encode(cert_id.getComponentByName('issuerNameHash')),
            der_encoder.encode(cert_id.getComponentByName('issuerKeyHash')),
            der_encoder.encode(cert_id.getComponentByName('serialNumber')))

    def encode_cert_id_base64(self, hkey):
        return b64encode(der_encoder.encode(
            self.encode_cert_id_key(hkey))).decode('ascii')

    def decode_cert_id_base64(self, cert_id_base64):
        cert_id, _ = der_decoder.decode(b64decode(cert_id_base64), CertID())
        return cert_id

    def read_cert_bundle(self, ca_bundle_file, storage=None):
        """
        Reads a certificate file including certificates in PEM format
        """
        if storage is None:
            storage = SnowflakeOCSP.ROOT_CERTIFICATES_DICT
        logger.debug('reading certificate bundle: %s', ca_bundle_file)
        all_certs = open(ca_bundle_file, 'rb').read()

        state = 0
        contents = []
        for line in all_certs.split(b'\n'):
            if state == 0 and line.startswith(b'-----BEGIN CERTIFICATE-----'):
                state = 1
                contents.append(line)
            elif state == 1:
                contents.append(line)
                if line.startswith(b'-----END CERTIFICATE-----'):
                    cert_openssl = load_certificate(
                        FILETYPE_PEM,
                        b'\n'.join(contents))
                    cert = self._convert_openssl_to_pyasn1_certificate(
                        cert_openssl)
                    storage[self._get_subject_hash(cert)] = cert
                    state = 0
                    contents = []

    def _convert_openssl_to_pyasn1_certificate(self, cert_openssl):
        cert_der = dump_certificate(FILETYPE_ASN1, cert_openssl)
        cert = der_decoder.decode(
            cert_der, asn1Spec=rfc2459.Certificate())[0]
        return cert

    def _convert_pyasn1_to_openssl_certificate(self, cert):
        cert_der = der_encoder.encode(cert)
        cert_openssl = load_certificate(FILETYPE_ASN1, cert_der)
        return cert_openssl

    def _get_name_hash(self, cert):
        sha1_hash = hashlib.sha1()
        sha1_hash.update(der_encoder.encode(self._get_subject(cert)))
        return sha1_hash.hexdigest()

    def _get_key_hash(self, cert):
        sha1_hash = hashlib.sha1()
        h = SnowflakeOCSPPyasn1.bit_string_to_bytearray(
            cert.getComponentByName('tbsCertificate').getComponentByName(
                'subjectPublicKeyInfo').getComponentByName('subjectPublicKey'))
        sha1_hash.update(h)
        return sha1_hash.hexdigest()

    def create_ocsp_request(self, issuer, subject):
        """
        Create CertID and OCSPRequest
        """
        hashAlgorithm = rfc2459.AlgorithmIdentifier()
        hashAlgorithm.setComponentByName("algorithm", rfc2437.id_sha1)
        hashAlgorithm.setComponentByName(
            "parameters", univ.Any(hexValue='0500'))

        cert_id = CertID()
        cert_id.setComponentByName(
            'hashAlgorithm', hashAlgorithm)
        cert_id.setComponentByName(
            'issuerNameHash',
            univ.OctetString(hexValue=self._get_name_hash(issuer)))
        cert_id.setComponentByName(
            'issuerKeyHash',
            univ.OctetString(hexValue=self._get_key_hash(issuer)))
        cert_id.setComponentByName(
            'serialNumber',
            subject.getComponentByName(
                'tbsCertificate').getComponentByName('serialNumber'))

        request = Request()
        request.setComponentByName('reqCert', cert_id)

        request_list = univ.SequenceOf(componentType=Request())
        request_list.setComponentByPosition(0, request)

        tbs_request = TBSRequest()
        tbs_request.setComponentByName('requestList', request_list)
        tbs_request.setComponentByName('version', Version(0).subtype(
            explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0)))

        ocsp_request = OCSPRequest()
        ocsp_request.setComponentByName('tbsRequest', tbs_request)

        return cert_id, ocsp_request

    def extract_certificate_chain(self, connection):
        """
        Gets certificate chain and extract the key info from OpenSSL connection
        """
        cert_map = OrderedDict()
        logger.debug(
            "# of certificates: %s",
            len(connection.get_peer_cert_chain()))

        for cert_openssl in connection.get_peer_cert_chain():
            cert_der = dump_certificate(FILETYPE_ASN1, cert_openssl)
            cert = der_decoder.decode(
                cert_der, asn1Spec=rfc2459.Certificate())[0]
            subject_sha256 = self._get_subject_hash(cert)
            logger.debug(
                u'subject: %s, issuer: %s',
                nat_encoder(self._get_subject(cert)),
                nat_encoder(self._get_issuer(cert)))
            cert_map[subject_sha256] = cert

        return self.create_pair_issuer_subject(cert_map)

    def _get_subject(self, cert):
        return cert.getComponentByName(
            'tbsCertificate').getComponentByName('subject')

    def _get_issuer(self, cert):
        return cert.getComponentByName(
            'tbsCertificate').getComponentByName('issuer')

    def _get_subject_hash(self, cert):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(
            der_encoder.encode(self._get_subject(cert)))
        return sha256_hash.digest()

    def _get_issuer_hash(self, cert):
        sha256_hash = hashlib.sha256()
        sha256_hash.update(
            der_encoder.encode(self._get_issuer(cert)))
        return sha256_hash.digest()

    def create_pair_issuer_subject(self, cert_map):
        """
        Creates pairs of issuer and subject certificates
        """
        issuer_subject = []
        for subject_der in cert_map:
            cert = cert_map[subject_der]

            nocheck, is_ca, ocsp_urls = self._extract_extensions(cert)
            if nocheck or is_ca and not ocsp_urls:
                # Root certificate will not be validated
                # but it is used to validate the subject certificate
                continue
            issuer_hash = self._get_issuer_hash(cert)
            if issuer_hash not in cert_map:
                # IF NO ROOT certificate is attached in the certificate chain
                # read it from the local disk
                self._lazy_read_ca_bundle()
                logger.debug(
                    'not found issuer_der: %s', self._get_issuer_hash(cert))
                if issuer_hash not in SnowflakeOCSP.ROOT_CERTIFICATES_DICT:
                    raise OperationalError(
                        msg="CA certificate is NOT found in the root "
                            "certificate list. Make sure you use the latest "
                            "Python Connector package and the URL is valid.")
                issuer = SnowflakeOCSP.ROOT_CERTIFICATES_DICT[issuer_hash]
            else:
                issuer = cert_map[issuer_hash]

            issuer_subject.append((issuer, cert))
        return issuer_subject

    def _extract_extensions(self, cert):
        extensions = cert.getComponentByName(
            'tbsCertificate').getComponentByName('extensions')
        is_ca = False
        ocsp_urls = []
        nocheck = False
        for e in extensions:
            oid = e.getComponentByName('extnID')
            if oid == rfc2459.id_ce_basicConstraints:
                constraints = der_decoder.decode(
                    e.getComponentByName('extnValue'),
                    asn1Spec=rfc2459.BasicConstraints())[0]
                is_ca = constraints.getComponentByPosition(0)
            elif oid == rfc2459.id_pe_authorityInfoAccess:
                auth_info = der_decoder.decode(
                    e.getComponentByName('extnValue'),
                    asn1Spec=rfc2459.AuthorityInfoAccessSyntax())[0]
                for a in auth_info:
                    if a.getComponentByName('accessMethod') == \
                            rfc2560.id_pkix_ocsp:
                        url = nat_encoder(
                            a.getComponentByName(
                                'accessLocation').getComponentByName(
                                'uniformResourceIdentifier'))
                        ocsp_urls.append(url)
            elif oid == rfc2560.id_pkix_ocsp_nocheck:
                nocheck = True

        return nocheck, is_ca, ocsp_urls

    def subject_name(self, cert):
        return nat_encoder(self._get_subject(cert))

    def extract_ocsp_url(self, cert):
        _, _, ocsp_urls = self._extract_extensions(cert)
        return ocsp_urls[0] if ocsp_urls else None

    def decode_ocsp_request(self, ocsp_request):
        return der_encoder.encode(ocsp_request)

    def decode_ocsp_request_b64(self, ocsp_request):
        data = self.decode_ocsp_request(ocsp_request)
        b64data = b64encode(data).decode('ascii')
        return b64data

    def extract_good_status(self, single_response):
        """
        Extract GOOD status
        """
        this_update_native = \
            self._convert_generalized_time_to_datetime(
                single_response.getComponentByName('thisUpdate'))
        next_update_native = \
            self._convert_generalized_time_to_datetime(
                single_response.getComponentByName('nextUpdate'))
        return this_update_native, next_update_native

    def extract_revoked_status(self, single_response):
        """
        Extract REVOKED status
        """
        cert_status = single_response.getComponentByName('certStatus')
        revoked = cert_status.getComponentByName('revoked')
        revocation_time = \
            self._convert_generalized_time_to_datetime(
                revoked.getComponentByName('revocationTime'))
        revocation_reason = revoked.getComponentByName('revocationReason')
        try:
            revocation_reason_str = str(revocation_reason)
        except:
            revocation_reason_str = 'n/a'
        return revocation_time, revocation_reason_str

    def _convert_generalized_time_to_datetime(self, gentime):
        return datetime.strptime(str(gentime), '%Y%m%d%H%M%SZ')

    def is_valid_time(self, cert_id, ocsp_response):
        res = der_decoder.decode(ocsp_response, OCSPResponse())[0]

        if res.getComponentByName('responseStatus') != OCSPResponseStatus(
                'successful'):
            raise OperationalError(
                msg="Invalid Status: {0}".format(
                    res.getComponentByName('response_status')),
                errno=ER_INVALID_OCSP_RESPONSE)

        response_bytes = res.getComponentByName('responseBytes')
        basic_ocsp_response = der_decoder.decode(
            response_bytes.getComponentByName('response'),
            BasicOCSPResponse())[0]

        tbs_response_data = basic_ocsp_response.getComponentByName(
            'tbsResponseData')

        single_response = tbs_response_data.getComponentByName('responses')[0]
        cert_status = single_response.getComponentByName('certStatus')
        try:
            if cert_status.getName() == 'good':
                self._process_good_status(single_response, cert_id, ocsp_response)
        except Exception as ex:
            logger.debug("Failed to validate ocsp response %s", ex)
            return False

        return True

    def process_ocsp_response(self, issuer, cert_id, ocsp_response):
        try:
            res = der_decoder.decode(ocsp_response, OCSPResponse())[0]
        except Exception:
            raise OperationalError(
                msg='Invalid OCSP Response',
                errno=ER_INVALID_OCSP_RESPONSE
            )

        if res.getComponentByName('responseStatus') != OCSPResponseStatus(
                'successful'):
            raise OperationalError(
                msg="Invalid Status: {0}".format(
                    res.getComponentByName('response_status')),
                errno=ER_INVALID_OCSP_RESPONSE)

        response_bytes = res.getComponentByName('responseBytes')
        basic_ocsp_response = der_decoder.decode(
            response_bytes.getComponentByName('response'),
            BasicOCSPResponse())[0]

        attached_certs = basic_ocsp_response.getComponentByName('certs')
        if self._has_certs_in_ocsp_response(attached_certs):
            logger.debug("Certificate is attached in Basic OCSP Response")
            cert_der = der_encoder.encode(attached_certs[0])
            cert_openssl = load_certificate(FILETYPE_ASN1, cert_der)
            ocsp_cert = self._convert_openssl_to_pyasn1_certificate(
                cert_openssl)

            cur_time = datetime.utcnow().replace(tzinfo=pytz.utc)
            tbs_certificate = ocsp_cert.getComponentByName('tbsCertificate')
            cert_validity = tbs_certificate.getComponentByName('validity')
            cert_not_after = cert_validity.getComponentByName('notAfter')
            cert_not_after_utc = cert_not_after.getComponentByName('utcTime').asDateTime
            cert_not_before = cert_validity.getComponentByName('notBefore')
            cert_not_before_utc = cert_not_before.getComponentByName('utcTime').asDateTime

            if cur_time > cert_not_after_utc or cur_time < cert_not_before_utc:
                raise OperationalError(
                    msg="Certificate attached to OCSP Response is invalid. OCSP response "
                    "current time - {0} "
                    "certificate not before time - {1} "
                    "certificate not after time - {2}".format(cur_time, cert_not_before_utc, cert_not_after_utc),
                    errno=ER_INVALID_OCSP_RESPONSE_CODE
                )

            self.verify_signature(
                ocsp_cert.getComponentByName('signatureAlgorithm'),
                ocsp_cert.getComponentByName('signatureValue'),
                issuer,
                ocsp_cert.getComponentByName('tbsCertificate'))
        else:
            logger.debug("Certificate is NOT attached in Basic OCSP Response. "
                         "Using issuer's certificate")
            ocsp_cert = issuer

        tbs_response_data = basic_ocsp_response.getComponentByName(
            'tbsResponseData')

        logger.debug("Verifying the OCSP response is signed by the issuer.")
        self.verify_signature(
            basic_ocsp_response.getComponentByName('signatureAlgorithm'),
            basic_ocsp_response.getComponentByName('signature'),
            ocsp_cert,
            tbs_response_data
        )

        single_response = tbs_response_data.getComponentByName('responses')[0]
        cert_status = single_response.getComponentByName('certStatus')
        if cert_status.getName() == 'good':
            self._process_good_status(single_response, cert_id, ocsp_response)
            SnowflakeOCSP.OCSP_CACHE.update_cache(self, cert_id, ocsp_response)
        elif cert_status.getName() == 'revoked':
            self._process_revoked_status(single_response, cert_id)
        elif cert_status.getName() == 'unknown':
            self._process_unknown_status(cert_id)
        else:
            raise OperationalError(
                msg="Unknown revocation status was returned. OCSP response "
                    "may be malformed: {0}".format(cert_status),
                errno=ER_INVALID_OCSP_RESPONSE_CODE
            )

    def verify_signature(self, signature_algorithm, signature, cert, data):
        """
        Verifies the signature
        """
        sig = SnowflakeOCSPPyasn1.bit_string_to_bytearray(signature)
        if PY2:
            sig = str(sig)
        else:
            sig = sig.decode('latin-1').encode('latin-1')

        pubkey = SnowflakeOCSPPyasn1.bit_string_to_bytearray(
            cert.getComponentByName(
                'tbsCertificate').getComponentByName(
                'subjectPublicKeyInfo').getComponentByName('subjectPublicKey'))
        if PY2:
            pubkey = str(pubkey)
        else:
            pubkey = pubkey.decode('latin-1').encode('latin-1')

        rsakey = RSA.importKey(pubkey)
        signer = PKCS1_v1_5.new(rsakey)

        algorithm = signature_algorithm[0]
        if algorithm in SnowflakeOCSPPyasn1.SIGNATURE_HASH_ALGO_TO_DIGEST_CLASS:
            digest = SnowflakeOCSPPyasn1.SIGNATURE_HASH_ALGO_TO_DIGEST_CLASS[
                algorithm].new()
        else:
            digest = SHA1.new()

        data = der_encoder.encode(data)
        digest.update(data)
        if not signer.verify(digest, sig):
            raise OperationalError(
                msg="Failed to verify the signature",
                errno=ER_INVALID_OCSP_RESPONSE)

    def _has_certs_in_ocsp_response(self, certs):
        """
        Check if the certificate is attached to OCSP response
        """
        if SnowflakeOCSPPyasn1._get_pyasn1_version() <= 3000:
            return certs is not None
        else:
            # behavior changed.
            return certs is not None and certs.hasValue() and certs[
                0].hasValue()

    @staticmethod
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
