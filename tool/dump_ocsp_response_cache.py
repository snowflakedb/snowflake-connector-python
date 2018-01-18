#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import os
import sys
from logging import getLogger
from os import path
from time import gmtime, strftime

from asn1crypto import core, ocsp

from snowflake.connector.ocsp_asn1crypto import (
    OUTPUT_TIMESTAMP_FORMAT,
    read_ocsp_response_cache_file,
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
    s_to_n = _serial_to_name(cert_dir)

    ocsp_validation_cache = {}
    read_ocsp_response_cache_file(ocsp_response_cache_file,
                                  ocsp_validation_cache)

    def custom_key(k):
        serial_number = core.Integer.load(k[2])
        return int(serial_number.native)

    for hkey in sorted(ocsp_validation_cache, key=custom_key):
        serial_number = core.Integer.load(hkey[2]).native
        if int(serial_number) in s_to_n:
            name = s_to_n[int(serial_number)]
        else:
            name = "Unknown"
        print(
            "serial #: {}, name: {}".format(serial_number, name),
        )
        value = ocsp_validation_cache[hkey]
        cache = value[1]
        ocsp_response = ocsp.OCSPResponse.load(cache)
        basic_ocsp_response = ocsp_response.basic_ocsp_response

        tbs_response_data = basic_ocsp_response['tbs_response_data']

        for single_response in tbs_response_data['responses']:
            print("created on: {}, produced At: {}, this: {}, next: {}".format(
                strftime(OUTPUT_TIMESTAMP_FORMAT, gmtime(int(value[0]))),
                tbs_response_data['produced_at'].native,
                single_response['this_update'].native,
                single_response['next_update'].native))


def _serial_to_name(cert_dir):
    """
    Create a map table from serial number to name
    """
    map_serial_to_name = {}
    for cert_file in os.listdir(cert_dir):
        cert_file = path.join(cert_dir, cert_file)
        cert_map = {}
        read_cert_bundle(cert_file, cert_map)
        cert_data = _create_pair_issuer_subject(cert_map)

        for issuer, subject in cert_data:
            map_serial_to_name[subject.serial_number] = subject.subject.native

    return map_serial_to_name


if __name__ == '__main__':
    main()
