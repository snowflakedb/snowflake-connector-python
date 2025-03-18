#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import json
import logging
import pathlib
import socket
import subprocess
from time import sleep
from typing import List, Optional, Union

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
    def __init__(self, forbidden_ports: Optional[List[int]] = None) -> None:
        self.wiremock_filename = "wiremock-standalone.jar"
        self.wiremock_host = "localhost"
        self.wiremock_http_port = None
        self.wiremock_https_port = None
        self.forbidden_ports = forbidden_ports if forbidden_ports is not None else []

        self.wiremock_dir = pathlib.Path(__file__).parent.parent.parent / ".wiremock"
        assert self.wiremock_dir.exists(), f"{self.wiremock_dir} does not exist"

        self.wiremock_jar_path = self.wiremock_dir / self.wiremock_filename
        assert (
            self.wiremock_jar_path.exists()
        ), f"{self.wiremock_jar_path} does not exist"

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
        )
        self._wait_for_wiremock()

    def _stop_wiremock(self):
        response = self._wiremock_post(
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/shutdown"
        )
        if response.status_code != 200:
            logger.info("Wiremock shutdown failed, the process will be killed")
            self.wiremock_process.kill()
        else:
            logger.debug("Wiremock shutdown gracefully")

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

    def import_mapping(self, mapping: Union[str, dict, pathlib.Path]):
        self._reset_wiremock()
        import_mapping_endpoint = f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/mappings/import"
        mapping_str = _get_mapping_str(mapping)
        response = self._wiremock_post(import_mapping_endpoint, mapping_str)
        if response.status_code != requests.codes.ok:
            raise RuntimeError("Failed to import mapping")

    def add_mapping(self, mapping: Union[str, dict, pathlib.Path]):
        add_mapping_endpoint = (
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/mappings"
        )
        mapping_str = _get_mapping_str(mapping)
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
