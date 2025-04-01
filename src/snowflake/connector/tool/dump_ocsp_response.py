#!/usr/bin/env python
from __future__ import annotations

import logging
import sys
import time
from argparse import ArgumentParser, Namespace
from time import gmtime, strftime

from asn1crypto import ocsp as asn1crypto_ocsp

from snowflake.connector.compat import urlsplit
from snowflake.connector.ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto as SFOCSP
from snowflake.connector.ocsp_snowflake import OCSPTelemetryData
from snowflake.connector.ssl_wrap_socket import _openssl_connect


def _parse_args() -> Namespace:
    parser = ArgumentParser(
        prog="dump_ocsp_response",
        description="Dump OCSP Response for the URLs (an internal tool).",
    )
    parser.add_argument(
        "-o",
        "--output-file",
        required=False,
        help="Dump output file",
        type=str,
        default=None,
    )
    parser.add_argument(
        "--log-level",
        required=False,
        help="Log level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("--log-file", required=False, help="Log file", default=None)
    parser.add_argument("urls", nargs="+", help="URLs to dump OCSP Response for")
    return parser.parse_args()


def main() -> None:
    """Internal Tool: OCSP response dumper."""
    args = _parse_args()
    if args.log_level:
        if args.log_file:
            logging.basicConfig(
                filename=args.log_file, level=getattr(logging, args.log_level.upper())
            )
        else:
            logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
    dump_ocsp_response(args.urls, output_filename=args.output_file)


def dump_good_status(current_time, single_response) -> None:
    print("This Update: {}".format(single_response["this_update"].native))
    print("Next Update: {}".format(single_response["next_update"].native))
    this_update = (
        single_response["this_update"].native.replace(tzinfo=None) - SFOCSP.ZERO_EPOCH
    ).total_seconds()
    next_update = (
        single_response["next_update"].native.replace(tzinfo=None) - SFOCSP.ZERO_EPOCH
    ).total_seconds()

    tolerable_validity = SFOCSP._calculate_tolerable_validity(this_update, next_update)
    print(
        "Tolerable Update: {}".format(
            strftime("%Y%m%d%H%M%SZ", gmtime(next_update + tolerable_validity))
        )
    )
    if SFOCSP._is_validaity_range(current_time, this_update, next_update):
        print("OK")
    else:
        print(SFOCSP._validity_error_message(current_time, this_update, next_update))


def dump_revoked_status(single_response) -> None:
    revoked_info = single_response["cert_status"]
    revocation_time = revoked_info.native["revocation_time"]
    revocation_reason = revoked_info.native["revocation_reason"]
    print(
        "Revoked Time: {}".format(
            revocation_time.strftime(SFOCSP.OUTPUT_TIMESTAMP_FORMAT)
        )
    )
    print(f"Revoked Reason: {revocation_reason}")


def dump_ocsp_response(urls, output_filename):
    ocsp = SFOCSP()
    for url in urls:
        if not url.startswith("http"):
            url = "https://" + url
        parsed_url = urlsplit(url)
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        connection = _openssl_connect(hostname, port)
        cert_data = ocsp.extract_certificate_chain(connection)
        current_time = int(time.time())
        print(f"Target URL: {url}")
        print(
            "Current Time: {}".format(strftime("%Y%m%d%H%M%SZ", gmtime(current_time)))
        )
        for issuer, subject in cert_data:
            _, _ = ocsp.create_ocsp_request(issuer, subject)
            _, _, _, cert_id, ocsp_response_der = ocsp.validate_by_direct_connection(
                issuer, subject, OCSPTelemetryData()
            )
            ocsp_response = asn1crypto_ocsp.OCSPResponse.load(ocsp_response_der)
            print("------------------------------------------------------------")
            print(f"Subject Name: {subject.subject.native}")
            print(f"Issuer Name: {issuer.subject.native}")
            print(f"OCSP URI: {subject.ocsp_urls}")
            print(f"CRL URI: {subject.crl_distribution_points[0].native}")
            print(f"Issuer Name Hash: {subject.issuer.sha1}")
            print(f"Issuer Key Hash: {issuer.public_key.sha1}")
            print(f"Serial Number: {subject.serial_number}")
            print("Response Status: {}".format(ocsp_response["response_status"].native))
            basic_ocsp_response = ocsp_response.basic_ocsp_response
            tbs_response_data = basic_ocsp_response["tbs_response_data"]
            print("Responder ID: {}".format(tbs_response_data["responder_id"].name))
            current_time = int(time.time())
            for single_response in tbs_response_data["responses"]:
                cert_status = single_response["cert_status"].name
                if cert_status == "good":
                    dump_good_status(current_time, single_response)
                elif cert_status == "revoked":
                    dump_revoked_status(single_response)
                else:
                    print("Unknown")
            print("")

        if output_filename:
            SFOCSP.OCSP_CACHE.write_ocsp_response_cache_file(ocsp, output_filename)
    return SFOCSP.OCSP_CACHE


if __name__ == "__main__":
    main()
