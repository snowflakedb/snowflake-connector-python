#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import logging
import time
from logging import getLogger
from os import path
from time import gmtime, strftime

from asn1crypto import ocsp

from snowflake.connector.compat import (urlsplit)
from snowflake.connector.ocsp_asn1crypto import (
    ZERO_EPOCH,
    OUTPUT_TIMESTAMP_FORMAT,
    validate_by_direct_connection,
    _create_ocsp_request,
    _extract_certificate_chain,
    _is_validaity_range,
    _validity_error_message,
    _calculate_tolerable_validity,
    write_ocsp_response_cache_file,
    OCSP_VALIDATION_CACHE)
from snowflake.connector.ssl_wrap_socket import _openssl_connect

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
    Internal Tool: OCSP response dumper
    """

    def help():
        print(
            "Dump OCSP Response for the URL. "
            "Warning: The output is not stable, don't rely on the output for "
            "automation.")
        print("""
Usage: {0} <url> [<url> ...]
""".format(path.basename(sys.argv[0])))
        sys.exit(2)

    import sys
    if len(sys.argv) < 2:
        help()

    urls = sys.argv[1:]
    dump_ocsp_response(urls, output_filename=None)


def dump_ocsp_response(urls, output_filename):
    for url in urls:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        connection = _openssl_connect(hostname, port)
        cert_data = _extract_certificate_chain(connection)
        current_time = int(time.time())
        print("Target URL: {0}".format(url))
        print("Current Time: {0}".format(
            strftime('%Y%m%d%H%M%SZ', gmtime(current_time))))
        for issuer, subject in cert_data:
            cert_id, _ = _create_ocsp_request(issuer, subject)
            _, cert_id, ocsp_response_der = validate_by_direct_connection(
                issuer, subject)
            ocsp_response = ocsp.OCSPResponse.load(ocsp_response_der)
            print(
                "------------------------------------------------------------")
            print("Issuer Name: {0}".format(issuer.subject.native))
            print("Subject Name: {0}".format(subject.subject.native))
            print("OCSP URI: {0}".format(subject.ocsp_urls))
            print("CRL URI: {0}".format(
                subject.crl_distribution_points[0].native))
            print("Issuer Name Hash: {0}".format(subject.issuer.sha1))
            print("Issuer Key Hash: {0}".format(issuer.public_key.sha1))
            print("Serial Number: {0}".format(subject.serial_number))
            print("Response Status: {0}".format(
                ocsp_response['response_status'].native))
            basic_ocsp_response = ocsp_response.basic_ocsp_response
            tbs_response_data = basic_ocsp_response['tbs_response_data']
            print("Responder ID: {0}".format(
                tbs_response_data['responder_id'].name))
            current_time = int(time.time())
            for single_response in tbs_response_data['responses']:
                cert_status = single_response['cert_status'].name
                if cert_status == 'good':
                    print("This Update: {0}".format(
                        single_response['this_update'].native))
                    print("Next Update: {0}".format(
                        single_response['next_update'].native))
                    this_update = (
                            single_response['this_update'].native.replace(
                                tzinfo=None) - ZERO_EPOCH).total_seconds()
                    next_update = (
                            single_response['next_update'].native.replace(
                                tzinfo=None) - ZERO_EPOCH).total_seconds()

                    tolerable_validity = _calculate_tolerable_validity(
                        this_update,
                        next_update)
                    print("Tolerable Update: {0}".format(
                        strftime('%Y%m%d%H%M%SZ', gmtime(
                            next_update + tolerable_validity))
                    ))
                    if _is_validaity_range(current_time, this_update,
                                           next_update):
                        print("OK")
                    else:
                        print(_validity_error_message(
                            current_time, this_update, next_update))
                elif cert_status == 'revoked':
                    revoked_info = single_response['cert_status']
                    revocation_time = revoked_info.native['revocation_time']
                    revocation_reason = revoked_info.native['revocation_reason']
                    print("Revoked Time: {0}".format(
                        revocation_time.strftime(OUTPUT_TIMESTAMP_FORMAT)))
                    print("Revoked Reason: {0}".format(revocation_reason))
                    print("Revoked")
                else:
                    print("Unknown")
            print('')

        if output_filename:
            write_ocsp_response_cache_file(
                output_filename, OCSP_VALIDATION_CACHE)
    return OCSP_VALIDATION_CACHE


if __name__ == '__main__':
    main()
