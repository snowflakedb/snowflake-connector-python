#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2018 Snowflake Computing Inc. All right reserved.
#
import calendar
import logging
import socket
import time
from os import path
from time import gmtime, strftime, strptime

from snowflake.connector.ocsp_pyopenssl import (
    SnowflakeOCSP,
    _is_validaity_range,
    octet_string_to_bytearray,
    _validity_error_message,
    _calculate_tolerable_validity,
    write_ocsp_response_cache_file,
    OCSP_VALIDATION_CACHE)

from logging import getLogger

from pyasn1.codec.der import decoder as der_decoder

from snowflake.connector.rfc6960 import (
    OCSPResponseStatus,
    OCSPResponse, CertID, BasicOCSPResponse)

from snowflake.connector.compat import (urlsplit)

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


def dump_ocsp_response(urls, output_filename, previous_output_uri=None):
    from OpenSSL.SSL import SSLv23_METHOD, Context, Connection

    def _openssl_connect(hostname, port=443):
        client = socket.socket()
        client.connect((hostname, port))
        client_ssl = Connection(Context(SSLv23_METHOD), client)
        client_ssl.set_connect_state()
        client_ssl.set_tlsext_host_name(hostname.encode('utf-8'))
        client_ssl.do_handshake()
        return client_ssl

    for url in urls:
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        ocsp = SnowflakeOCSP(
            ocsp_response_cache_url=previous_output_uri)
        connection = _openssl_connect(hostname, port)
        results = ocsp.generate_cert_id_response(
            hostname, connection)
        current_Time = int(time.time())
        print("Target URL: {0}".format(url))
        print("Current Time: {0}".format(
            strftime('%Y%m%d%H%M%SZ', gmtime(current_Time))))
        for cert_id, (current_time, issuer, subject, ocsp_response) in \
                results.items():
            cert_id, _ = der_decoder.decode(cert_id, CertID())
            ocsp_response, _ = der_decoder.decode(ocsp_response, OCSPResponse())
            print(
                "------------------------------------------------------------")
            print("Issuer Name: {0}".format(issuer['cert'].get_subject()))
            print("Subject Name: {0}".format(subject['cert'].get_subject()))
            print("OCSP URI: {0}".format(subject['ocsp_uri']))
            print("CRL URI: {0}".format(subject['crl']))
            print("Issuer Name Hash: {0}".format(
                octet_string_to_bytearray(cert_id['issuerNameHash']).decode(
                    'latin-1').encode('latin-1')))
            print("Issuer Key Hash: {0}".format(
                octet_string_to_bytearray(cert_id['issuerKeyHash']).decode(
                    'latin-1').encode('latin-1')))
            print("Serial Number: {0}".format(cert_id['serialNumber']))
            if ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'successful'):
                status = "successful"
            elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'malformedRequest'):
                status = "malformedRequest"
            elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'internalError'):
                status = "internalError"
            elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'tryLater'):
                status = "tryLater"
            elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'sigRequired'):
                status = "sigRequired"
            elif ocsp_response['responseStatus'] == OCSPResponseStatus(
                    'unauthorized'):
                status = "unauthorized"
            else:
                status = "Unknown"
            print("Response Status: {0}".format(status))
            response_bytes = ocsp_response['responseBytes']
            basic_ocsp_response, _ = der_decoder.decode(
                response_bytes['response'],
                BasicOCSPResponse())
            tbs_response_data = basic_ocsp_response['tbsResponseData']
            if tbs_response_data['responderID']['byName']:
                print("Responder Name: {0}".format(
                    tbs_response_data['responderID']['byName']))
            elif tbs_response_data['responderID']['byKey']:
                sha1_ocsp = tbs_response_data['responderID']['byKey']
                sha1_ocsp = octet_string_to_bytearray(sha1_ocsp).decode(
                    'latin-1').encode('latin-1')
                print("Responder Key: {0}".format(sha1_ocsp))
            if tbs_response_data['responseExtensions']:
                print('Response Extensions: %s',
                      tbs_response_data['responseExtensions'])
            for single_response in tbs_response_data['responses']:
                cert_status = single_response['certStatus']
                if cert_status['good'] is not None:
                    print("This Update: {0}".format(
                        single_response['thisUpdate']))
                    print("Next Update: {0}".format(
                        single_response['nextUpdate']))
                    this_update = strptime(str(single_response['thisUpdate']),
                                           '%Y%m%d%H%M%SZ')
                    next_update = strptime(str(single_response['nextUpdate']),
                                           '%Y%m%d%H%M%SZ')
                    this_update = calendar.timegm(this_update)
                    next_update = calendar.timegm(next_update)
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
                elif cert_status['revoked'] is not None:
                    revocation_time = cert_status['revoked']['revocationTime']
                    revocation_reason = cert_status['revoked'][
                        'revocationReason']
                    print("Revoked Time: {0}".format(revocation_time))
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
