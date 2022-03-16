import ipaddress
import json
import os
import re
import requests
import socket
import socks
import ssl
import tempfile
import OpenSSL

from datetime import datetime
from logging import getLogger
from pathlib import Path
from urllib.request import getproxies
from .compat import IS_WINDOWS, urlparse

logger = getLogger(__name__)


class ConnectionDiagnostic(object):
    """Implementation of a connection test utility for Snowflake connector

    Use new ConnectionTest() to get the object.


    """

    def __init__(self, **kwargs):
        path_failed = False
        self.report_file = "SnowflakeConnectionTestReport.txt"
        self.report_destination = Path(str(kwargs.get('connection_diag_log_path')))
        if not self.report_destination.is_absolute():
            path_failed = True
            logger.warning(f"Path({self.report_destination} for connection test is not absolute and is not valid.")
        elif not self.report_destination.exists():
            path_failed = True
            logger.warning(f"Path({self.report_destination} for connection test does not exist.")

        if path_failed:
            if IS_WINDOWS:
                new_report_destination = Path(tempfile.gettempdir())
            else:
                new_report_destination = Path("/tmp/")
            logger.warning(f"Since the provided path({self.report_destination}) was invalid, using"
                           f" {new_report_destination}")
            self.report_destination = new_report_destination

        self.report_file = Path(f"{str(self.report_destination)}/{self.report_file}")
        logger.info(f"Reporting to file {self.report_file}")

        self.whitelist_json = Path(str(kwargs.get('connection_diag_whitelist_path')))
        if not self.whitelist_json.is_absolute():
            logger.warning(f"Path '{self.whitelist_json}' for connection test whitelist is not absolute and is not "
                           f"valid.")
            logger.warning(f"Will connect to Snowflake for whitelist json instead.  If you did not provide a valid "
                           f"password, please make sure to update and run again.")
            self.whitelist_json = None
        elif not self.whitelist_json.exists():
            logger.warning(f"File '{self.report_destination}' for connection test whitelist does not exist.")
            logger.warning(f"Will connect to Snowflake for whitelist json instead.  If you did not provide a valid "
                           f"password, please make sure to update and run again.")
            self.whitelist_json = None

        self.initial_host = kwargs.get("host")
        self.host = self.initial_host
        self.account = kwargs.get("account")
        self.proxy_host = kwargs.get("proxy_host")
        self.proxy_port = kwargs.get("proxy_port")
        self.proxy_user = kwargs.get("proxy_user")
        self.proxy_password = kwargs.get("proxy_password")
        self.test_results = {'INITIAL': [], 'PROXY': [], 'SNOWFLAKE_URL': [], 'STAGE': [], 'OCSP_RESPONDER': [],
                             'OUT_OF_BAND_TELEMETRY': []}
        self.ocsp_urls = []
        if self.__is_privatelink():
            self.ocsp_urls.append(f"ocsp.{self.host}")
            self.whitelist_sql = "select system$whitelist_privatelink();"
        else:
            self.ocsp_urls.append(f"ocsp.snowflakecomputing.com")
            self.whitelist_sql = "select system$whitelist();"
        self.whitelist_retrieval_success = False
        self.crl_urls = []
        self.cursor = None

    def set_cursor(self, cursor):
        self.cursor = cursor

    def __get_certificate(self, host, port=443, timeout=10, host_type="SNOWFLAKE_URL"):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            conn = socket.create_connection((host, port))
            sock = context.wrap_socket(conn, server_hostname=host)
            sock.settimeout(timeout)
            der_cert = sock.getpeercert(True)
        except Exception as e:
            self.test_results[host_type].append(f"{host_type}: {host}:{port}: URL Check: Failed: {e}")
        finally:
            sock.close()
        return ssl.DER_cert_to_PEM_cert(der_cert)

    def __socket_test(self, host, port, host_type="OCSP_RESPONDER"):
        proxy_url = None
        proxy_host = self.proxy_host
        proxy_port = self.proxy_port
        proxy_user = self.proxy_user
        proxy_password = self.proxy_password
        if self.proxy_host is None:
            if "HTTPS_PROXY" in os.environ.keys():
                proxy_url = os.environ["HTTPS_PROXY"]

        if proxy_url is not None:
            parsed = urlparse(proxy_url)
            proxy_host = parsed.hostname
            proxy_port = parsed.port
            proxy_user = parsed.username
            proxy_password = parsed.password

        try:
            self.__list_ips(host, host_type=host_type)
            s = socks.socksocket()
            s.settimeout(5)
            if proxy_host is not None:
                s.set_proxy(socks.HTTP, proxy_host, proxy_port, proxy_user, proxy_password)
            s.connect((host, int(port)))
            self.test_results[host_type].append(f"{host_type}: {host}:{port}: URL Check: Connected Successfully")
        except Exception as e:
            self.test_results[host_type].append(f"{host_type}: {host}:{port}: URL Check: Failed: {e}")
            pass
        finally:
            s.close()

    def run_post_test(self):
        if self.whitelist_json is None:
            try:
                results = self.cursor().execute(self.whitelist_sql).fetchall()[0][0]
                results = json.loads(str(results))
            except Exception as e:
                logger.warning(f"Unable to do whitelist checks: exception: {e}")
                pass
        else:
            results_file = open(self.whitelist_json)
            results = json.load(results_file)

        self.whitelist_retrieval_success = True
        for result in results:
            host_type = result['type']
            host = result['host']
            host_port = result['port']
            if host_type in ["OUT_OF_BAND_TELEMETRY", "OCSP_RESPONDER"]:
                if host not in self.ocsp_urls:
                    self.__socket_test(host, host_port, host_type=host_type)
            elif host_type in ["STAGE"]:
                self.__https_host_report(host, port=host_port, host_type="STAGE")

    def __is_privatelink(self):
        if "privatelink" in self.host:
            return True
        return False

    def __list_ips(self, host, host_type="SNOWFLAKE_URL"):
        try:
            ips = socket.gethostbyname_ex(host)[2]
            base_message = f"{host_type}: {host}: nslookup results"

            self.test_results[host_type].append(f"{base_message}: {ips}")
            if host_type in ["SNOWFLAKE_URL"]:
                for ip in ips:
                    if ipaddress.ip_address(ip).is_private:
                        if self.__is_privatelink():
                            self.test_results[host_type].append(
                                f"{base_message}: private ip: {ip}: we expect this for privatelink.")
                        else:
                            self.test_results[host_type].append(
                                f"{base_message}: private ip: {ip}: WARNING: this is not "
                                f"typical for a non-privatelink account")
                    else:
                        self.test_results[host_type].append(f"{base_message}: public ip: {ip}")
        except Exception as e:
            logger.warning(f"Connectivity Test Exception in list_ips: {e}")
            pass

    def __https_host_report(self, host, port=443, host_type="SNOWFLAKE_URL"):
        try:
            self.__list_ips(host, host_type=host_type)

            certificate = self.__get_certificate(host, host_type=host_type)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)

            result = {
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components()),
                'serialNumber': x509.get_serial_number(),
                'version': x509.get_version(),
                'notBefore': datetime.strptime(str(x509.get_notBefore().decode("utf-8")), '%Y%m%d%H%M%SZ'),
                'notAfter': datetime.strptime(str(x509.get_notAfter().decode("utf-8")), '%Y%m%d%H%M%SZ'),
            }

            self.test_results[host_type].append(f"{host_type}: {host}:{port}: URL Check: Connected Successfully")
            self.test_results[host_type].append(f"{host_type}: {host}: Cert info:")
            self.test_results[host_type].append(f"{host_type}: {host}: subject: {result['subject']}")
            self.test_results[host_type].append(f"{host_type}: {host}: issuer: {result['issuer']}")
            self.test_results[host_type].append(f"{host_type}: {host}: serialNumber: {result['serialNumber']}")
            self.test_results[host_type].append(f"{host_type}: {host}: version: {result['version']}")
            self.test_results[host_type].append(f"{host_type}: {host}: notBefore: {result['notBefore']}")
            self.test_results[host_type].append(f"{host_type}: {host}: notAfter: {result['notAfter']}")

            extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
            extension_data = {}
            for e in extensions:
                extension_data[e.get_short_name().decode("utf-8")] = str(e)

            extra_result = {
                'subjectAltName': extension_data['subjectAltName'],
                'crlDistributionPoints': extension_data['crlDistributionPoints'],
                'authorityInfoAccess': extension_data['authorityInfoAccess']
            }
            result.update(extra_result)
            ocsp_urls_orig = re.findall(r'(https?://\S+)', extra_result['authorityInfoAccess'])

            for url in ocsp_urls_orig:
                self.ocsp_urls.append(url.split('/')[2])

            crl_urls_orig = re.findall(r'(https?://\S+)', extra_result['crlDistributionPoints'])

            for url in crl_urls_orig:
                self.crl_urls.append(url.split('/')[2])

            self.test_results[host_type].append(f"{host_type}: {host}: subjectAltName: {result['subjectAltName']}")
            self.test_results[host_type].append(f"{host_type}: {host}: crlUrls: {self.crl_urls}")
            self.test_results[host_type].append(f"{host_type}: {host}: ocspURLs: {self.ocsp_urls}")
        except Exception as e:
            logger.warning(f"Connectivity Test Exception in https_host_report: {e}")
            pass

    def __check_for_proxies(self):
        # To do
        # See if we need to do anything for noproxy
        # If we need more proxy checks, this site might work
        # curl -k -v https://amibehindaproxy.com 2>&1 | tee | grep alert
        env_proxy_backup = {}
        proxy_keys = ["HTTP_PROXY", "HTTPS_PROXY"]
        restore_keys = []

        for proxy_key in proxy_keys:
            if proxy_key in os.environ.keys():
                env_proxy_backup[proxy_key] = os.environ.get(proxy_key)
                del os.environ[proxy_key]
                restore_keys.append(proxy_key)

        self.test_results['PROXY'].append(f"PROXY: Proxies with Env vars removed(SYSTEM PROXIES): {getproxies()}")

        for restore_key in restore_keys:
            os.environ[restore_key] = env_proxy_backup[restore_key]

        self.test_results['PROXY'].append(f"PROXY: Proxies with Env vars restored(ENV PROXIES): {getproxies()}")

        try:
            # Using a URL that does not exist is a check for a transparent proxy
            session = requests.Session()
            # Important because this request has to be unverified to check for proxy
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
            r = session.get("https://ireallyshouldnotexistatallanywhere.com", verify=False)
            # squid does not throw exception.  Check HTML
            if "does not exist" in str(r.content.decode("utf-8")):
                self.test_results['PROXY'].append(f"PROXY: It is likely there is a proxy based on HTTP response.")
        except Exception as e:
            if "NewConnectionError" in str(e):
                self.test_results['PROXY'].append(f"PROXY: No proxy detected: Exception: {e}")
            elif "ProxyError" in str(e):
                self.test_results['PROXY'].append(f"PROXY: It is likely there is a proxy based on Exception: {e}")
            else:
                self.test_results['PROXY'].append(
                    f"PROXY: Could not determine if a proxy does or does not exist based on Exeption: {e}")
            pass

    def run_test(self):
        self.test_results['INITIAL'].append(f"Specified snowflake account: {self.account}")
        self.test_results['INITIAL'].append(f"Host based on specified account: {self.initial_host}")
        if '.com.snowflakecomputing.com' in self.initial_host:
            self.host = self.initial_host.split('.com.snow')[0] + ".com"
            logger.warning(f"Account should not have snowflakecomputing.com in it. You provided {self.initial_host}.  "
                           f"Continuing with fixed host.")
            self.test_results['INITIAL'].append(
                f"We removed extra .snowflakecomputing.com and will continue with host: "
                f"{self.host}")

        self.__check_for_proxies()
        self.__https_host_report(self.host)
        self.ocsp_urls = list(set(self.ocsp_urls))
        for url in self.ocsp_urls:
            self.__socket_test(url, 80)

    def generate_report(self):
        message = "=========Connectivity diagnostic report================================"
        initial_joined_results = '\n'.join(self.test_results['INITIAL'])
        message = (
            f"{message}\n"
            f"{initial_joined_results}\n"
        )

        proxy_joined_results = '\n'.join(self.test_results['PROXY'])
        message = (
            f"{message}\n"
            "=========Proxy information - These are best guesses, not guarantees====\n"
            f"{proxy_joined_results}\n"
        )

        snowflake_url_joined_results = '\n'.join(self.test_results['SNOWFLAKE_URL'])
        message = (
            f"{message}\n"
            "=========Snowflake URL information=====================================\n"
            f"{snowflake_url_joined_results}\n"
        )

        if self.whitelist_retrieval_success:
            snowflake_stage_joined_results = '\n'.join(self.test_results['STAGE'])
            message = (
                f"{message}\n"
                "=========Snowflake Stage information===================================\n"
                "We retrieved stage info from the whitelist\n"
                f"{snowflake_stage_joined_results}\n"
            )
        else:
            message = (
                f"{message}\n"
                "=========Snowflake Stage information - Unavailable=====================\n"
                "We could not connect to Snowflake to get whitelist, so we do not have stage\n"
                f"diagnostic info\n"
            )

        message = (
            f"{message}\n"
            "=========Snowflake OCSP information===================================="
        )
        snowflake_ocsp_joined_results = '\n'.join(self.test_results['OCSP_RESPONDER'])
        if self.whitelist_retrieval_success:
            message = (
                f"{message}\n"
                "We were able to retrieve system whitelist.\n"
                "These OCSP hosts came from the certificate and the whitelist."
            )
        else:
            message = (
                f"{message}\n"
                "We were unable to retrieve system whitelist.\n"
                "These OCSP hosts only came from the certificate."
            )
        message = (
            f"{message}\n"
            f"{snowflake_ocsp_joined_results}\n"
        )

        if self.whitelist_retrieval_success:
            snowflake_telemetry_joined_results = '\n'.join(self.test_results['OUT_OF_BAND_TELEMETRY'])
            message = (
                f"{message}\n"
                "=========Snowflake Out of bound telemetry check========================\n"
                f"{snowflake_telemetry_joined_results}\n"
            )

        logger.debug(message)
        with open(self.report_file, "w") as report_file_handle:
            report_file_handle.write(message)
