import logging.config
import os
import subprocess
import threading
import webbrowser
from enum import Enum

import requests

import snowflake.connector

try:
    from src.snowflake.connector.vendored.requests.auth import HTTPBasicAuth
except ImportError:
    pass

logger = logging.getLogger(__name__)

logger.setLevel(logging.INFO)


class Scenario(Enum):
    SUCCESS = "success"
    FAIL = "fail"
    TIMEOUT = "timeout"
    EXTERNAL_OAUTH_OKTA_SUCCESS = "externalOauthOktaSuccess"
    INTERNAL_OAUTH_SNOWFLAKE_SUCCESS = "internalOauthSnowflakeSuccess"


def get_access_token_oauth(cfg):
    auth_url = cfg["auth_url"]

    data = {
        "username": cfg["okta_user"],
        "password": cfg["okta_pass"],
        "grant_type": "password",
        "scope": f"session:role:{cfg['role']}",
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}

    auth_credentials = HTTPBasicAuth(cfg["oauth_client_id"], cfg["oauth_client_secret"])
    try:
        response = requests.post(
            url=auth_url, data=data, headers=headers, auth=auth_credentials
        )
        response.raise_for_status()
        return response.json()["access_token"]

    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
        raise


def clean_browser_processes():
    if os.getenv("RUN_AUTH_TESTS_MANUALLY") != "true":
        try:
            clean_browser_processes_path = "/externalbrowser/cleanBrowserProcesses.js"
            process = subprocess.run(["node", clean_browser_processes_path], timeout=15)
            logger.debug(f"OUTPUT:  {process.stdout}, ERRORS: {process.stderr}")
        except Exception as e:
            raise RuntimeError(e)


class AuthorizationTestHelper:
    def __init__(self, configuration: dict):
        self.run_auth_test_manually = os.getenv("RUN_AUTH_TESTS_MANUALLY")
        self.configuration = configuration
        self.error_msg = ""

    def update_config(self, configuration):
        self.configuration = configuration

    def connect_and_provide_credentials(
        self, scenario: Scenario, login: str, password: str
    ):
        try:
            connect = threading.Thread(target=self.connect_and_execute_simple_query)
            connect.start()

            if self.run_auth_test_manually != "true":
                browser = threading.Thread(
                    target=self._provide_credentials, args=(scenario, login, password)
                )
                browser.start()
                browser.join()

            connect.join()

        except Exception as e:
            self.error_msg = e
            logger.error(e)

    def get_error_msg(self) -> str:
        return str(self.error_msg)

    def connect_and_execute_simple_query(self):
        try:
            logger.info("Trying to connect to Snowflake")
            with snowflake.connector.connect(**self.configuration) as con:
                result = con.cursor().execute("select 1;")
                logger.debug(result.fetchall())
                logger.info("Successfully connected to Snowflake")
                return True
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False

    def _provide_credentials(self, scenario: Scenario, login: str, password: str):
        try:
            webbrowser.register("xdg-open", None, webbrowser.GenericBrowser("xdg-open"))
            provide_browser_credentials_path = (
                "/externalbrowser/provideBrowserCredentials.js"
            )
            process = subprocess.run(
                [
                    "node",
                    provide_browser_credentials_path,
                    scenario.value,
                    login,
                    password,
                ],
                timeout=15,
            )
            logger.debug(f"OUTPUT:  {process.stdout}, ERRORS: {process.stderr}")
        except Exception as e:
            self.error_msg = e
            raise RuntimeError(e)
