#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import sys
from logging import getLogger
from os import path

from snowflake.connector.compat import (urlsplit)

for logger_name in ['__main__', 'snowflake']:
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(message)s'))
    logger.addHandler(ch)

logger = getLogger(__name__)

from snowflake.connector.ocsp_asn1crypto import (_openssl_connect)


def main():
    from OpenSSL.crypto import dump_certificate, FILETYPE_PEM

    def help():
        print("Export certificate on the URL")
        print("""
    Usage: {0}  <url>
    """.format(path.basename(sys.argv[0])))
        sys.exit(2)

    if len(sys.argv) < 2:
        help()

    input_url = sys.argv[1]
    parsed_url = urlsplit(input_url)
    connection = _openssl_connect(parsed_url.hostname, parsed_url.port or 443)
    for cert_openssl in connection.get_peer_cert_chain():
        cert_pem = dump_certificate(FILETYPE_PEM, cert_openssl)
        print(cert_pem.decode('utf-8'))


if __name__ == '__main__':
    main()
