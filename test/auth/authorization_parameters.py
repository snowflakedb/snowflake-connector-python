import os
import sys
from typing import Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.abspath(os.path.dirname(__file__)))


def get_oauth_token_parameters() -> dict[str, str]:
    return {
        "auth_url": _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_URL"),
        "oauth_client_id": _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_CLIENT_ID"),
        "oauth_client_secret": _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_OAUTH_CLIENT_SECRET"
        ),
        "okta_user": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_USER"),
        "okta_pass": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS"),
        "role": (_get_env_variable("SNOWFLAKE_AUTH_TEST_ROLE")).lower(),
    }


def _get_env_variable(name: str, required: bool = True) -> str:
    value = os.getenv(name)
    if required and value is None:
        raise OSError(f"Environment variable {name} is not set")
    return value


def get_okta_login_credentials() -> dict[str, str]:
    return {
        "login": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_USER"),
        "password": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS"),
    }


def get_soteria_okta_login_credentials() -> dict[str, str]:
    return {
        "login": _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"),
        "password": _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_USER_PASSWORD"
        ),
    }


def get_rsa_private_key_for_key_pair(
    key_path: str,
) -> serialization.load_pem_private_key:
    with open(_get_env_variable(key_path), "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
        return private_key


def get_pat_setup_command_variables() -> dict[str, Union[str, bool, int]]:
    return {
        "snowflake_user": _get_env_variable("SNOWFLAKE_AUTH_TEST_SNOWFLAKE_USER"),
        "role": _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE"),
    }


class AuthConnectionParameters:
    def __init__(self):
        self.basic_config = {
            "host": _get_env_variable("SNOWFLAKE_AUTH_TEST_HOST"),
            "port": _get_env_variable("SNOWFLAKE_AUTH_TEST_PORT"),
            "role": _get_env_variable("SNOWFLAKE_AUTH_TEST_ROLE"),
            "account": _get_env_variable("SNOWFLAKE_AUTH_TEST_ACCOUNT"),
            "db": _get_env_variable("SNOWFLAKE_AUTH_TEST_DATABASE"),
            "schema": _get_env_variable("SNOWFLAKE_AUTH_TEST_SCHEMA"),
            "warehouse": _get_env_variable("SNOWFLAKE_AUTH_TEST_WAREHOUSE"),
            "CLIENT_STORE_TEMPORARY_CREDENTIAL": False,
        }

    def get_base_connection_parameters(self) -> dict[str, Union[str, bool, int]]:
        return self.basic_config

    def get_key_pair_connection_parameters(self):
        config = self.basic_config.copy()
        config["authenticator"] = "KEY_PAIR_AUTHENTICATOR"
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")

        return config

    def get_external_browser_connection_parameters(self) -> dict[str, str]:
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "externalbrowser"

        return config

    def get_store_id_token_connection_parameters(self) -> dict[str, str]:
        config = self.get_external_browser_connection_parameters()

        config["CLIENT_STORE_TEMPORARY_CREDENTIAL"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_STORE_ID_TOKEN_USER"
        )

        return config

    def get_okta_connection_parameters(self) -> dict[str, str]:
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["password"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS")
        config["authenticator"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_URL")

        return config

    def get_oauth_connection_parameters(self, token: str) -> dict[str, str]:
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "OAUTH"
        config["token"] = token
        return config

    def get_oauth_external_authorization_code_connection_parameters(
        self,
    ) -> dict[str, Union[str, bool, int]]:
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauth_client_id"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"
        )
        config["oauth_client_secret"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET"
        )
        config["oauth_redirect_uri"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_REDIRECT_URI"
        )
        config["oauth_authorization_url"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_AUTH_URL"
        )
        config["oauth_token_request_url"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN"
        )
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")

        return config

    def get_snowflake_authorization_code_connection_parameters(
        self,
    ) -> dict[str, Union[str, bool, int]]:
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauth_client_id"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_ID"
        )
        config["oauth_client_secret"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_SECRET"
        )
        config["oauth_redirect_uri"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_REDIRECT_URI"
        )
        config["role"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE"
        )
        config["user"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"
        )

        return config

    def get_snowflake_wildcard_external_authorization_code_connection_parameters(
        self,
    ) -> dict[str, Union[str, bool, int]]:
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauth_client_id"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_ID"
        )
        config["oauth_client_secret"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_SECRET"
        )
        config["role"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE"
        )
        config["user"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"
        )

        return config

    def get_oauth_external_client_credential_connection_parameters(
        self,
    ) -> dict[str, str]:
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_CLIENT_CREDENTIALS"
        config["oauth_client_id"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"
        )
        config["oauth_client_secret"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET"
        )
        config["oauth_token_request_url"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN"
        )
        config["user"] = _get_env_variable(
            "SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID"
        )

        return config

    def get_pat_connection_parameters(self) -> dict[str, str]:
        config = self.basic_config.copy()

        config["authenticator"] = "PROGRAMMATIC_ACCESS_TOKEN"
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")

        return config

    def get_snowflake_authorization_code_local_application_connection_parameters(self):
        config = self.get_snowflake_authorization_code_connection_parameters()
        config["oauth_client_id"] = ""
        config["oauth_client_secret"] = ""
        return config
