#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import json
import logging
import os.path
import pathlib
import socket
import subprocess
from time import sleep
from typing import Optional

try:
    from snowflake.connector.vendored import requests
except ImportError:
    import requests

WIREMOCK_START_MAX_RETRY_COUNT = 12
LOGGER = logging.getLogger(__name__)


def _get_mapping_str(mapping):
    if isinstance(mapping, str):
        return mapping
    if isinstance(mapping, dict):
        return json.dumps(mapping)
    if os.path.isfile(str(mapping)):
        with open(mapping) as f:
            return f.read()

    raise RuntimeError(f"Mapping {mapping} is of an invalid type")


class WiremockClient:
    def __init__(self):
        self.wiremock_filename = "wiremock-standalone.jar"
        self.wiremock_host = "localhost"
        self.wiremock_http_port = None
        self.wiremock_https_port = None

        self.wiremock_dir = pathlib.Path(__file__).parent.parent.parent / ".wiremock"
        assert self.wiremock_dir.exists(), f"{self.wiremock_dir} does not exist"

        self.wiremock_jar_path = self.wiremock_dir / self.wiremock_filename
        assert (
            self.wiremock_jar_path.exists()
        ), f"{self.wiremock_jar_path} does not exist"

    def _start_wiremock(self):
        self.wiremock_http_port = self._find_free_port()
        self.wiremock_https_port = self._find_free_port()
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
            LOGGER.warning(f"Wiremock healthcheck failed with exception: {e}")
            return False
        if (
            response.status_code == requests.codes.ok
            and response.json()["status"] == "healthy"
        ):
            LOGGER.debug(f"Wiremock healthcheck failed with response: {response}")
        else:
            LOGGER.warning(
                f"Wiremock healthcheck failed with status code: {response.status_code}"
            )
            return False
        return True

    def _reset_wiremock(self):
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

    def import_mapping(self, mapping):
        self._reset_wiremock()
        import_mapping_endpoint = f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/mappings/import"
        mapping_str = _get_mapping_str(mapping)
        response = self._wiremock_post(import_mapping_endpoint, mapping_str)
        if response.status_code != requests.codes.ok:
            raise RuntimeError("Failed to import mapping")

    def add_mapping(self, mapping):
        add_mapping_endpoint = (
            f"http://{self.wiremock_host}:{self.wiremock_http_port}/__admin/mappings"
        )
        mapping_str = _get_mapping_str(mapping)
        response = self._wiremock_post(add_mapping_endpoint, mapping_str)
        if response.status_code != requests.codes.created:
            raise RuntimeError("Failed to add mapping")

    def _find_free_port(self) -> int:
        with socket.socket() as sock:
            sock.bind((self.wiremock_host, 0))
            return sock.getsockname()[1]

    def __enter__(self):
        self._start_wiremock()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_wiremock()
