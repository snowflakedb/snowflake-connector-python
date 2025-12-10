import logging.config
import os
import subprocess
import threading
import webbrowser
from enum import Enum
from typing import Union

import requests

import snowflake.connector.aio

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
    if os.getenv("AUTHENTICATION_TESTS_ENV") == "docker":
        try:
            clean_browser_processes_path = "/externalbrowser/cleanBrowserProcesses.js"
            process = subprocess.run(["node", clean_browser_processes_path], timeout=30)
            logger.debug(f"OUTPUT:  {process.stdout}, ERRORS: {process.stderr}")
        except Exception as e:
            raise RuntimeError(e)


class AuthorizationTestHelper:
    def __init__(self, configuration: dict):
        self.auth_test_env = os.getenv("AUTHENTICATION_TESTS_ENV")
        self.configuration = configuration
        self.error_msg = ""

    def update_config(self, configuration):
        self.configuration = configuration

    async def connect_and_provide_credentials(
        self, scenario: Scenario, login: str, password: str
    ):
        import asyncio

        try:
            # Run connection in a separate thread with its own event loop
            # This prevents blocking I/O operations in the OAuth flow from blocking the main event loop
            def _run_connection_in_thread():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    return loop.run_until_complete(
                        self.connect_and_execute_simple_query()
                    )
                finally:
                    loop.close()

            loop = asyncio.get_running_loop()
            connect_future = loop.run_in_executor(None, _run_connection_in_thread)

            if self.auth_test_env == "docker":
                # Give the connection thread a chance to start and open the browser
                await asyncio.sleep(2)

                # Start browser automation in a separate thread
                browser = threading.Thread(
                    target=self._provide_credentials, args=(scenario, login, password)
                )
                browser.start()
                # Wait for browser thread to complete
                await loop.run_in_executor(None, browser.join)

            # Wait for connection to complete
            await connect_future

        except Exception as e:
            self.error_msg = e
            logger.error(e)

    def get_error_msg(self) -> str:
        return str(self.error_msg)

    async def connect_and_execute_simple_query(self):
        try:
            logger.info("Trying to connect to Snowflake")
            async with snowflake.connector.aio.SnowflakeConnection(
                **self.configuration
            ) as con:
                result = await con.cursor().execute("select 1;")
                logger.debug(await result.fetchall())
                logger.info("Successfully connected to Snowflake")
                return True
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False

    async def connect_and_execute_set_session_state(self, key: str, value: str):
        try:
            logger.info("Trying to connect to Snowflake")
            async with snowflake.connector.aio.SnowflakeConnection(
                **self.configuration
            ) as con:
                result = await con.cursor().execute(f"SET {key} = '{value}'")
                logger.debug(await result.fetchall())
                logger.info("Successfully SET session variable")
                return True
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False

    async def connect_and_execute_check_session_state(self, key: str):
        try:
            logger.info("Trying to connect to Snowflake")
            async with snowflake.connector.aio.SnowflakeConnection(
                **self.configuration
            ) as con:
                result = await con.cursor().execute(f"SELECT 1, ${key}")
                value = (await result.fetchone())[1]
                logger.debug(value)
                logger.info("Successfully READ session variable")
                return value
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
                timeout=30,
            )
            logger.debug(f"OUTPUT:  {process.stdout}, ERRORS: {process.stderr}")
        except Exception as e:
            self.error_msg = e
            raise RuntimeError(e)

    def get_totp(self, seed: str = "") -> []:
        if self.auth_test_env == "docker":
            try:
                provide_totp_generator_path = "/externalbrowser/totpGenerator.js"
                process = subprocess.run(
                    ["node", provide_totp_generator_path, seed],
                    timeout=40,
                    capture_output=True,
                    text=True,
                )
                logger.debug(f"OUTPUT:  {process.stdout}, ERRORS: {process.stderr}")
                return process.stdout.strip().split()
            except Exception as e:
                self.error_msg = e
                raise RuntimeError(e)
        else:
            logger.info("TOTP generation is not supported in this environment")
            return ""

    async def connect_using_okta_connection_and_execute_custom_command(
        self, command: str, return_token: bool = False
    ) -> Union[bool, str]:
        try:
            logger.info("Setup PAT")
            async with snowflake.connector.aio.SnowflakeConnection(
                **self.configuration
            ) as con:
                result = await con.cursor().execute(command)
                token = (await result.fetchall())[0][1]
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False
        if return_token:
            return token
        return False

    async def connect_and_execute_simple_query_with_mfa_token(self, totp_codes):
        # Try each TOTP code until one works
        for i, totp_code in enumerate(totp_codes):
            logging.info(f"Trying TOTP code {i + 1}/{len(totp_codes)}")

            self.configuration["passcode"] = totp_code
            self.error_msg = ""

            connection_success = await self.connect_and_execute_simple_query()

            if connection_success:
                logging.info(f"Successfully connected with TOTP code {i + 1}")
                return True
            else:
                last_error = str(self.error_msg)
                logging.warning(f"TOTP code {i + 1} failed: {last_error}")
                if "TOTP Invalid" in last_error:
                    logging.info("TOTP/MFA error detected.")
                    continue
                else:
                    logging.error(f"Non-TOTP error detected: {last_error}")
                    break
        return False
