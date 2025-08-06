import json
import logging
import pathlib
import socket
import subprocess
from contextlib import contextmanager
from time import sleep
from typing import Iterable, List, Optional, Union

try:
    from snowflake.connector.vendored import requests
except ImportError:
    import requests

WIREMOCK_START_MAX_RETRY_COUNT = 12
logger = logging.getLogger(__name__)


def _get_mapping_str(mapping: Union[str, dict, pathlib.Path]) -> str:
    if isinstance(mapping, str):
        return mapping
    if isinstance(mapping, dict):
        return json.dumps(mapping)
    if isinstance(mapping, pathlib.Path):
        if mapping.is_file():
            with open(mapping) as f:
                return f.read()
        else:
            raise RuntimeError(f"File with mapping: {mapping} does not exist")

    raise RuntimeError(f"Mapping {mapping} is of an invalid type")


class WiremockClient:
    HTTP_HOST_PLACEHOLDER: str = "{{WIREMOCK_HTTP_HOST_WITH_PORT}}"

    def __init__(
        self,
        forbidden_ports: Optional[List[int]] = None,
        additional_wiremock_process_args: Optional[Iterable[str]] = None,
    ) -> None:
        self.wiremock_filename = "wiremock-standalone.jar"
        self.wiremock_host = "localhost"
        self.wiremock_http_port = None
        self.wiremock_https_port = None
        self.forbidden_ports = forbidden_ports if forbidden_ports is not None else []

        self.wiremock_dir = (
            pathlib.Path(__file__).parent.parent.parent.parent / ".wiremock"
        )
        assert self.wiremock_dir.exists(), f"{self.wiremock_dir} does not exist"

        self.wiremock_jar_path = self.wiremock_dir / self.wiremock_filename
        assert (
            self.wiremock_jar_path.exists()
        ), f"{self.wiremock_jar_path} does not exist"
        self._additional_wiremock_process_args = (
            additional_wiremock_process_args or list()
        )

    @property
    def http_host_with_port(self) -> str:
        return f"http://{self.wiremock_host}:{self.wiremock_http_port}"

    def get_http_placeholders(self) -> dict[str, str]:
        """Placeholder that substitutes the target Wiremock's host:port in JSON."""
        return {self.HTTP_HOST_PLACEHOLDER: self.http_host_with_port}

    def add_expected_headers_to_mapping(
        self,
        mapping_str: str,
        expected_headers: dict,
    ) -> str:
        """Add expected headers to all request matchers in mapping string."""
        mapping_dict = json.loads(mapping_str)

        def add_headers_to_request(request_dict: dict) -> None:
            if "headers" not in request_dict:
                request_dict["headers"] = {}
            request_dict["headers"].update(expected_headers)

        if "request" in mapping_dict:
            add_headers_to_request(mapping_dict["request"])

        if "mappings" in mapping_dict:
            for single_mapping in mapping_dict["mappings"]:
                if "request" in single_mapping:
                    add_headers_to_request(single_mapping["request"])

        return json.dumps(mapping_dict)

    def get_default_placeholders(self) -> dict[str, str]:
        return self.get_http_placeholders()

    def _start_wiremock(self):
        self.wiremock_http_port = self._find_free_port(
            forbidden_ports=self.forbidden_ports,
        )
        self.wiremock_https_port = self._find_free_port(
            forbidden_ports=self.forbidden_ports + [self.wiremock_http_port]
        )
        self.wiremock_process = subprocess.Popen(
            [
                "java",
                "-jar",
                self.wiremock_jar_path,
                "--root-dir",
                self.wiremock_dir,
                "--enable-browser-proxying",  # work as forward proxy
                "--proxy-pass-through",
                "false",  # pass through only matched requests
                "--port",
                str(self.wiremock_http_port),
                "--https-port",
                str(self.wiremock_https_port),
                "--https-keystore",
                self.wiremock_dir / "ca-cert.jks",
                "--ca-keystore",
                self.wiremock_dir / "ca-cert.jks",
            ]
            + self._additional_wiremock_process_args
        )
        self._wait_for_wiremock()

    def _stop_wiremock(self):
        if self.wiremock_process.poll() is not None:
            logger.warning("Wiremock process already exited, skipping shutdown")
            return

        try:
            response = self._wiremock_post(
                f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/shutdown"
            )
            if response.status_code != 200:
                logger.info("Wiremock shutdown failed, the process will be killed")
                self.wiremock_process.kill()
            else:
                logger.debug("Wiremock shutdown gracefully")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Shutdown request failed: {e}. Killing process directly.")
            self.wiremock_process.kill()

    def _wait_for_wiremock(self):
        retry_count = 0
        while retry_count < WIREMOCK_START_MAX_RETRY_COUNT:
            if self._health_check():
                return
            retry_count += 1
            sleep(1)

        raise TimeoutError(
            f"WiremockClient did not respond within {WIREMOCK_START_MAX_RETRY_COUNT} seconds"
        )

    def _health_check(self):
        mappings_endpoint = (
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/health"
        )
        try:
            response = requests.get(mappings_endpoint)
        except requests.exceptions.RequestException as e:
            logger.warning(f"Wiremock healthcheck failed with exception: {e}")
            return False

        if (
            response.status_code == requests.codes.ok
            and response.json()["status"] != "healthy"
        ):
            logger.warning(f"Wiremock healthcheck failed with response: {response}")
            return False
        elif response.status_code != requests.codes.ok:
            logger.warning(
                f"Wiremock healthcheck failed with status code: {response.status_code}"
            )
            return False

        return True

    def _reset_wiremock(self):
        clean_journal_endpoint = (
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/requests"
        )
        requests.delete(clean_journal_endpoint)
        reset_endpoint = (
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/reset"
        )
        response = self._wiremock_post(reset_endpoint)
        if response.status_code != requests.codes.ok:
            raise RuntimeError("Failed to reset WiremockClient")

    def _wiremock_post(
        self, endpoint: str, body: Optional[str] = None
    ) -> requests.Response:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        return requests.post(endpoint, data=body, headers=headers)

    def _replace_placeholders_in_mapping(
        self, mapping_str: str, placeholders: Optional[dict[str, object]]
    ) -> str:
        if placeholders:
            for key, value in placeholders.items():
                mapping_str = mapping_str.replace(str(key), str(value))
        return mapping_str

    def import_mapping(
        self,
        mapping: Union[str, dict, pathlib.Path],
        placeholders: Optional[dict[str, object]] = None,
        expected_headers: Optional[dict] = None,
    ):
        self._reset_wiremock()
        import_mapping_endpoint = f"{self.http_host_with_port}/__admin/mappings/import"

        mapping_str = _get_mapping_str(mapping)
        if expected_headers is not None:
            mapping_str = self.add_expected_headers_to_mapping(
                mapping_str, expected_headers
            )

        mapping_str = self._replace_placeholders_in_mapping(mapping_str, placeholders)
        response = self._wiremock_post(import_mapping_endpoint, mapping_str)
        if response.status_code != requests.codes.ok:
            raise RuntimeError("Failed to import mapping")

    def import_mapping_with_default_placeholders(
        self,
        mapping: Union[str, dict, pathlib.Path],
        expected_headers: Optional[dict] = None,
    ):
        placeholders = self.get_default_placeholders()
        return self.import_mapping(mapping, placeholders, expected_headers)

    def add_mapping_with_default_placeholders(
        self,
        mapping: Union[str, dict, pathlib.Path],
        expected_headers: Optional[dict] = None,
    ):
        placeholders = self.get_default_placeholders()
        return self.add_mapping(mapping, placeholders, expected_headers)

    def add_mapping(
        self,
        mapping: Union[str, dict, pathlib.Path],
        placeholders: Optional[dict[str, object]] = None,
        expected_headers: Optional[dict] = None,
    ):
        add_mapping_endpoint = f"{self.http_host_with_port}/__admin/mappings"

        mapping_str = _get_mapping_str(mapping)
        if expected_headers is not None:
            mapping_str = self.add_expected_headers_to_mapping(
                mapping_str, expected_headers
            )

        mapping_str = self._replace_placeholders_in_mapping(mapping_str, placeholders)
        response = self._wiremock_post(add_mapping_endpoint, mapping_str)
        if response.status_code != requests.codes.created:
            raise RuntimeError("Failed to add mapping")

    def _find_free_port(self, forbidden_ports: Union[List[int], None] = None) -> int:
        max_retries = 1 if forbidden_ports is None else 3
        if forbidden_ports is None:
            forbidden_ports = []

        retry_count = 0
        while retry_count < max_retries:
            retry_count += 1
            with socket.socket() as sock:
                sock.bind((self.wiremock_host, 0))
                port = sock.getsockname()[1]
                if port not in forbidden_ports:
                    return port

        raise RuntimeError(
            f"Unable to find a free port for wiremock in {max_retries} attempts"
        )

    def __enter__(self):
        self._start_wiremock()
        logger.debug(
            f"Starting wiremock process, listening on {self.wiremock_host}:{self.wiremock_http_port}"
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        logger.debug("Stopping wiremock process")
        self._stop_wiremock()


@contextmanager
def get_clients_for_proxy_and_target(
    proxy_mapping_template: Union[str, dict, pathlib.Path, None] = None,
    additional_proxy_placeholders: Optional[dict[str, object]] = None,
    additional_proxy_args: Optional[Iterable[str]] = None,
):
    """Context manager that starts two Wiremock instances – *target* and *proxy* – and
    configures the proxy to forward **all** traffic to the target.

    It yields a tuple ``(target_wm, proxy_wm)`` where both items are fully initialised
    ``WiremockClient`` objects ready for use in tests.  When the context exits both
    Wiremock processes are shut down automatically.

    Parameters
    ----------
    proxy_mapping_template
        Mapping JSON (str / dict / pathlib.Path) to be used for configuring the proxy
        Wiremock.  If *None*, the default template at
        ``test/data/wiremock/mappings/proxy/forward_all.json`` is used.
    additional_proxy_placeholders
        Optional placeholders to be replaced in the proxy mapping *in addition* to the
        automatically provided ``{{TARGET_HTTP_HOST_WITH_PORT}}``.
    additional_proxy_args
        Extra command-line arguments passed to the proxy Wiremock instance when it is
        launched.  Useful for tweaking Wiremock behaviour in specific tests.
    """

    # Resolve default mapping template if none provided
    if proxy_mapping_template is None:
        proxy_mapping_template = (
            pathlib.Path(__file__).parent.parent.parent.parent
            / "test"
            / "data"
            / "wiremock"
            / "mappings"
            / "generic"
            / "proxy_forward_all.json"
        )

    # Start the *target* Wiremock first – this will emulate Snowflake / IdP backend
    with WiremockClient() as target_wm:
        # Then start the *proxy* Wiremock and ensure it doesn't try to bind the same port
        with WiremockClient(
            forbidden_ports=[target_wm.wiremock_http_port],
            additional_wiremock_process_args=additional_proxy_args,
        ) as proxy_wm:
            # Prepare placeholders so that proxy forwards to the *target*
            placeholders: dict[str, object] = {
                "{{TARGET_HTTP_HOST_WITH_PORT}}": target_wm.http_host_with_port
            }
            if additional_proxy_placeholders:
                placeholders.update(additional_proxy_placeholders)

            # Configure proxy Wiremock to forward everything to target
            proxy_wm.add_mapping(proxy_mapping_template, placeholders=placeholders)

            # Yield control back to the caller with both Wiremocks ready
            yield target_wm, proxy_wm
