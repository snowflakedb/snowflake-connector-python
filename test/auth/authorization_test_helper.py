from __future__ import annotations

import logging.config
import os
import subprocess
import threading
import webbrowser
from collections.abc import Sequence
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


_EXTERNAL_BROWSER_DIR = "/externalbrowser"
_NODE_SCRIPT_TIMEOUT = 15


def _redact(text: str | bytes | None, secrets: Sequence[str]) -> str:
    """Replaces every non-empty secret in ``text`` with a placeholder.

    Accepts bytes as well as str: ``subprocess.TimeoutExpired`` carries the
    partial output as raw bytes even when the call passed ``text=True``, because
    the exception is raised before the streams are decoded.
    """
    if not text:
        return ""
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    for secret in secrets:
        if secret:
            text = text.replace(secret, "****")
    return text


def _log_node_output(
    label: str,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    secrets: Sequence[str],
    level: int,
) -> None:
    for stream_name, content in (("stdout", stdout), ("stderr", stderr)):
        redacted = _redact(content, secrets).strip()
        if redacted:
            logger.log(level, "%s %s:\n%s", label, stream_name, redacted)


def _run_node_script(
    script_name: str,
    args: Sequence[str] | None = None,
    *,
    timeout: int = _NODE_SCRIPT_TIMEOUT,
    context: str = "",
    secrets: Sequence[str] = (),
) -> subprocess.CompletedProcess:
    """Runs one of the browser-automation scripts shipped inside the test image.

    Captures and logs the script's own output on failure. Without this, a broken
    browser automation is invisible: the node process is killed at ``timeout``,
    its error is discarded, and the only thing that reaches the log is the
    connector's generic "Unable to receive the OAuth message within a given
    timeout" ~120s later, which points at the redirect URI rather than at the
    browser.

    The argv is deliberately kept out of both the log and any raised exception:
    these scripts take the IdP login and password as positional arguments, and
    ``subprocess.TimeoutExpired``/``CalledProcessError`` echo the whole argv in
    ``str(exc)``. Re-raising those verbatim has published live browser
    credentials into CI logs.

    Raises only on timeout, matching what the individual call sites did before
    they were funnelled through here: ``subprocess.run`` was never called with
    ``check=True``, so a non-zero exit was tolerated. A non-zero exit is logged
    at ERROR rather than raised, to keep this change from turning a previously
    silent ``cleanBrowserProcesses.js`` failure into an error in the autouse
    setup/teardown fixture.
    """
    script_path = f"{_EXTERNAL_BROWSER_DIR}/{script_name}"
    label = f"{script_name}({context})" if context else script_name
    try:
        process = subprocess.run(
            ["node", script_path, *(args or ())],
            timeout=timeout,
            capture_output=True,
            text=True,
        )
    except subprocess.TimeoutExpired as e:
        # Whatever the script managed to print before being killed usually names
        # the real failure (a missing selector, a navigation timeout, ...).
        _log_node_output(label, e.stdout, e.stderr, secrets, logging.ERROR)
        raise RuntimeError(
            f"{label} did not complete within {timeout}s: browser automation "
            f"failed. See the captured node output above for the cause."
        ) from None

    if process.returncode != 0:
        logger.error("%s exited with code %s", label, process.returncode)
        _log_node_output(label, process.stdout, process.stderr, secrets, logging.ERROR)
    else:
        _log_node_output(label, process.stdout, process.stderr, secrets, logging.DEBUG)
    return process


def clean_browser_processes():
    if os.getenv("AUTHENTICATION_TESTS_ENV") == "docker":
        _run_node_script("cleanBrowserProcesses.js")


class AuthorizationTestHelper:
    def __init__(self, configuration: dict):
        self.auth_test_env = os.getenv("AUTHENTICATION_TESTS_ENV")
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
            if self.auth_test_env == "docker":
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

    def connect_and_execute_set_session_state(self, key: str, value: str):
        try:
            logger.info("Trying to connect to Snowflake")
            with snowflake.connector.connect(**self.configuration) as con:
                result = con.cursor().execute(f"SET {key} = '{value}'")
                logger.debug(result.fetchall())
                logger.info("Successfully SET session variable")
                return True
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False

    def connect_and_execute_check_session_state(self, key: str):
        try:
            logger.info("Trying to connect to Snowflake")
            with snowflake.connector.connect(**self.configuration) as con:
                result = con.cursor().execute(f"SELECT 1, ${key}")
                value = result.fetchone()[1]
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
            _run_node_script(
                "provideBrowserCredentials.js",
                [scenario.value, login, password],
                context=scenario.value,
                secrets=(login, password),
            )
        except Exception as e:
            self.error_msg = e
            raise

    def get_totp(self, seed: str = "") -> []:
        if self.auth_test_env == "docker":
            try:
                process = _run_node_script(
                    "totpGenerator.js", [seed], timeout=40, secrets=(seed,)
                )
                return process.stdout.strip().split()
            except Exception as e:
                self.error_msg = e
                raise
        else:
            logger.info("TOTP generation is not supported in this environment")
            return ""

    def connect_using_okta_connection_and_execute_custom_command(
        self, command: str, return_token: bool = False
    ) -> bool | str:
        try:
            logger.info("Setup PAT")
            with snowflake.connector.connect(**self.configuration) as con:
                result = con.cursor().execute(command)
                token = result.fetchall()[0][1]
        except Exception as e:
            self.error_msg = e
            logger.error(e)
            return False
        if return_token:
            return token
        return False

    def connect_and_execute_simple_query_with_mfa_token(self, totp_codes):
        # Try each TOTP code until one works
        for i, totp_code in enumerate(totp_codes):
            logging.info(f"Trying TOTP code {i + 1}/{len(totp_codes)}")

            self.configuration["passcode"] = totp_code
            self.error_msg = ""

            connection_success = self.connect_and_execute_simple_query()

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
