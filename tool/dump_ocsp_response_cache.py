#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
from os import path
import os
import calendar
import sys
import logging
import time
from time import strptime

from logging import getLogger

from pyasn1.codec.der import decoder as der_decoder

from snowflake.connector.rfc6960 import (
    OCSPResponse, CertID, BasicOCSPResponse)

from snowflake.connector.ocsp_pyopenssl import (
    read_ocsp_response_cache_file,
    _extract_values_from_certificate,
    _create_pair_issuer_subject,
    read_cert_bundle)

for logger_name in ['__main__', 'snowflake']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

logger = getLogger(__name__)


def main():
    """
    Internal Tool: Dump OCSP response cache file.
    """

    def help():
        print(
            "Dump OCSP Response cache. This tools extracts OCSP response "
            "cache file, i.e., ~/.cache/snowflake/ocsp_response_cache. "
            "Note the subject name shows up if the certificate exists in "
            "the certs directory.")
        print("""
Usage: {0}  <ocsp response cache file> <directory including certs>
""".format(path.basename(sys.argv[0])))
        sys.exit(2)

    if len(sys.argv) < 3:
        help()
        sys.exit(2)

    ocsp_response_cache_file = sys.argv[1]
    if not path.isfile(ocsp_response_cache_file):
        help()
        sys.exit(2)

    cert_dir = sys.argv[2]
    if not path.isdir(cert_dir):
        help()
        sys.exit(2)
    dump_ocsp_response_cache(ocsp_response_cache_file, cert_dir)


def dump_ocsp_response_cache(ocsp_response_cache_file, cert_dir):
    """
    Dump OCSP response cache contents. Show the subject name as well if
    the subject is included in the certificate files.
    """
    s_to_n = serial_to_name(cert_dir)

    ocsp_validation_cache = {}
    read_ocsp_response_cache_file(ocsp_response_cache_file,
                                  ocsp_validation_cache)

    def custom_key(k):
        k0, _ = der_decoder.decode(k, asn1Spec=CertID())
        return int(k0['serialNumber'])

    for cert_id in sorted(ocsp_validation_cache, key=custom_key):
        value = ocsp_validation_cache[cert_id]
        key_cert_id, _ = der_decoder.decode(cert_id, asn1Spec=CertID())
        serial_number = key_cert_id['serialNumber']
        if int(serial_number) in s_to_n:
            name = s_to_n[int(serial_number)]
        else:
            name = "Unknown"
        print(
            "serial #: {}, name: {}".format(serial_number, name),
        )
        cache = value[1]
        ocsp_response, _ = der_decoder.decode(cache, OCSPResponse())

        response_bytes = ocsp_response['responseBytes']

        basic_ocsp_response, _ = der_decoder.decode(
            response_bytes['response'],
            BasicOCSPResponse())

        tbs_response_data = basic_ocsp_response['tbsResponseData']

        if tbs_response_data['responseExtensions']:
            print('Response Extensions: {}'.format(
                tbs_response_data['responseExtensions']))

        for single_response in tbs_response_data['responses']:
            produced_at = strptime(str(tbs_response_data['producedAt']),
                                   '%Y%m%d%H%M%SZ')
            this_update = strptime(str(single_response['thisUpdate']),
                                   '%Y%m%d%H%M%SZ')
            next_update = strptime(str(single_response['nextUpdate']),
                                   '%Y%m%d%H%M%SZ')
            produced_at = calendar.timegm(produced_at)
            this_update = calendar.timegm(this_update)
            next_update = calendar.timegm(next_update)

            print("created on: {}, produced At: {}, this: {}, next: {}".format(
                time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(value[0])),
                time.strftime('%Y-%m-%d %H:%M:%S',
                              time.gmtime(produced_at)),
                time.strftime('%Y-%m-%d %H:%M:%S',
                              time.gmtime(this_update)),
                time.strftime('%Y-%m-%d %H:%M:%S',
                              time.gmtime(next_update))))


def serial_to_name(cert_dir):
    """
    Create a map table from serial number to name
    """
    map_serial_to_name = {}
    for cert_file in os.listdir(cert_dir):
        cert_file = path.join(cert_dir, cert_file)
        certificates_in_files = {}
        read_cert_bundle(cert_file, certificates_in_files)

        cert_data = {}
        for cert_id, cert in certificates_in_files.items():
            data = _extract_values_from_certificate(cert)
            cert_data[cert.get_subject().der()] = data

        issuer_and_subject = _create_pair_issuer_subject(cert_data)
        for c in issuer_and_subject:
            subject = c['subject']
            map_serial_to_name[subject['serial_number']] = subject['name']

    return map_serial_to_name


if __name__ == '__main__':
    main()
