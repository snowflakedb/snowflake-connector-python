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

if __name__ != 'snowflake.connector.ocsp_dump_certs':
    # for debugging on PyCharm
    from snowflake.connector.ocsp_pyopenssl import (
        _extract_values_from_certificate,
        read_cert_bundle,
        _create_pair_issuer_subject)
else:
    from ..ocsp_pyopenssl import (
        _extract_values_from_certificate,
        read_cert_bundle,
        _create_pair_issuer_subject)

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
    Internal Tool: Extract certificate files in PEM
    """

    def help():
        print(
            "Extract certificate file. The target file can be a single file "
            "or a directory including multiple certificates. The certificate "
            "file format should be PEM.")
        print("""
Usage: {0}  <input file/dir>
""".format(path.basename(sys.argv[0])))
        sys.exit(2)

    if len(sys.argv) < 2:
        help()
        sys.exit(2)

    input_filename = sys.argv[1]
    if path.isdir(input_filename):
        files = [path.join(input_filename, f) for f in
                 os.listdir(input_filename)]
    else:
        files = [input_filename]

    for f in files:
        open(f)
        extract_certificate_file(f)


def extract_certificate_file(input_filename):
    certificates_in_files = {}

    read_cert_bundle(input_filename, certificates_in_files)

    cert_data = {}
    for cert_id, cert in certificates_in_files.items():
        data = _extract_values_from_certificate(cert)
        cert_data[cert.get_subject().der()] = data

    issuer_and_subject = _create_pair_issuer_subject(cert_data)

    for c in issuer_and_subject:
        subject = c['subject']
        print("serial #: {}, name: {}".format(
            subject['serial_number'],
            subject['name']))


if __name__ == '__main__':
    main()
