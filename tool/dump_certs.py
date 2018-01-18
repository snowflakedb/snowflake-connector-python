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

from snowflake.connector.ocsp_asn1crypto import (
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
    cert_map = {}
    read_cert_bundle(input_filename, cert_map)
    cert_data = _create_pair_issuer_subject(cert_map)

    for issuer, subject in cert_data:
        print("serial #: {}, name: {}".format(
            subject.serial_number,
            subject.subject.native))


if __name__ == '__main__':
    main()
