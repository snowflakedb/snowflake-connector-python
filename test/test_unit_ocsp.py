#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2017 Snowflake Computing Inc. All right reserved.
#
import codecs
import os
from logging import getLogger

import pytest
from OpenSSL.crypto import (load_certificate, FILETYPE_PEM)
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder
from pyasn1.error import (SubstrateUnderrunError)
from pyasn1.type import (univ)

logger = getLogger(__name__)
THIS_DIR = os.path.dirname(os.path.realpath(__file__))

from snowflake.connector.errors import OperationalError
from snowflake.connector.ocsp_pyopenssl import (
    SnowflakeOCSP,
    _extract_values_from_certificate, is_cert_id_in_cache, execute_ocsp_request,
    process_ocsp_response)
from snowflake.connector.rfc6960 import (OCSPResponse)

CERT_TESTS_DATA_DIR = os.path.join(THIS_DIR, 'data', 'cert_tests')


def _load_certificate(pem_file):
    with codecs.open(pem_file, 'r', encoding='utf-8') as f:
        c = f.read()
    return load_certificate(FILETYPE_PEM, c)


def _load_ocsp_uri(txt):
    with codecs.open(txt, 'r',
                     encoding='utf-8') as f:
        c = f.read()
    return c.rstrip()


def test_ocsp_validation():
    PROD_CERT_TESTS_DATA_DIR = os.path.join(
        CERT_TESTS_DATA_DIR, 'production')

    subject_cert = _load_certificate(
        os.path.join(PROD_CERT_TESTS_DATA_DIR, 'snowflakecomputing.crt')
    )
    issuer_cert = _load_certificate(
        os.path.join(PROD_CERT_TESTS_DATA_DIR, 'networksolutions.crt')
    )

    ocsp = SnowflakeOCSP()
    ocsp_issuer = _extract_values_from_certificate(issuer_cert)
    ocsp_subject = _extract_values_from_certificate(subject_cert)
    assert ocsp.validate_by_direct_connection(
        ocsp_issuer['ocsp_uri'], ocsp_issuer, ocsp_subject), \
        'Failed to validate the revocation status for snowflakecomputing'

    # second one should be cached
    assert ocsp.validate_by_direct_connection(
        ocsp_issuer['ocsp_uri'], ocsp_issuer, ocsp_subject), \
        'Failed to validate the revocation status for snowflakecomputing'

    serial_number = ocsp_subject['serial_number']
    ocsp_subject['serial_number'] = 123

    # bogus serial number
    with pytest.raises(OperationalError):
        ocsp.validate_by_direct_connection(
            ocsp_issuer['ocsp_uri'], ocsp_issuer, ocsp_subject)

    ocsp_subject['serial_number'] = serial_number


def test_negative_response():
    PROD_CERT_TESTS_DATA_DIR = os.path.join(
        CERT_TESTS_DATA_DIR, 'production')
    subject_cert = _load_certificate(
        os.path.join(PROD_CERT_TESTS_DATA_DIR, 'networksolutions.crt')
    )
    issuer_cert = _load_certificate(
        os.path.join(PROD_CERT_TESTS_DATA_DIR, 'usertrust.crt')
    )

    ocsp_issuer = _extract_values_from_certificate(issuer_cert)
    ocsp_subject = _extract_values_from_certificate(subject_cert)

    # get a valid OCSPResponse
    status, cert_id, ocsp_response = is_cert_id_in_cache(
        ocsp_issuer, ocsp_subject, use_cache=False)
    logger.debug(cert_id.prettyPrint())

    response = execute_ocsp_request(ocsp_issuer['ocsp_uri'], cert_id)

    # extract
    ocsp_response, _ = der_decoder.decode(response, OCSPResponse())

    response_bytes = ocsp_response['responseBytes']
    backup_response_type = response_bytes['responseType']
    response_bytes['responseType'] = \
        univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 48, 1, 1000))
    response = der_encoder.encode(ocsp_response)

    # bogus response type
    with pytest.raises(OperationalError):
        process_ocsp_response(response, ocsp_issuer)

    # bogus response
    response_bytes['responseType'] = backup_response_type
    backup_response_bytes_respose = response_bytes['response']
    response_bytes['response'] = univ.Null
    response = der_encoder.encode(ocsp_response)

    with pytest.raises(SubstrateUnderrunError):
        process_ocsp_response(response, ocsp_issuer)

    response_bytes['response'] = backup_response_bytes_respose
    response = der_encoder.encode(ocsp_response)

    # invalid issuer certificate
    with pytest.raises(OperationalError):
        process_ocsp_response(response, ocsp_subject)
