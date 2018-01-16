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
    Internal Tool: POC asn1crypto
    """

    def help():
        print("")
        print("""
Usage: {0}  <input file/dir> <output dir>
""".format(path.basename(sys.argv[0])))
        sys.exit(2)

    if len(sys.argv) < 3:
        help()
        sys.exit(2)

    input_filename = sys.argv[1]
    output_dir = sys.argv[2]

    if path.isdir(input_filename):
        files = [path.join(input_filename, f) for f in
                 os.listdir(input_filename)]
    else:
        files = [input_filename]

    if not path.isdir(output_dir):
        help()
        sys.exit(1)

    for f in files:
        open(f)
        load_cert(f)


def _read_cert_bundle(ca_bundle_file):
    """
    Reads a certificate file including certificates in PEM format
    """
    from asn1crypto.x509 import Certificate
    from asn1crypto import pem
    certs = []

    logger = getLogger(__name__)
    logger.debug('reading certificate bundle: %s', ca_bundle_file)
    all_certs = open(ca_bundle_file, 'rb').read()

    pem_certs = pem.unarmor(all_certs, multiple=True)
    for type_name, _, der_bytes in pem_certs:
        if type_name == 'CERTIFICATE':
            crt = Certificate.load(der_bytes)
            logger.debug("Found part of the chain..")
            certs.append(crt)

    return certs


def load_cert(cert_file):
    for cert in _read_cert_bundle(cert_file):
        print(cert.ocsp_urls)


if __name__ == '__main__':
    main()
