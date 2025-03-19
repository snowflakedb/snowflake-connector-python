import os
import sys

sys.path.append(os.path.abspath(os.path.dirname(__file__)))

def get_oauth_token_parameters():
    return {"auth_url": _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_URL"),
                    "oauth_client_id": _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_CLIENT_ID"),
                    "oauth_client_secret": _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_CLIENT_SECRET"),
                    "okta_user": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_USER"),
                    "okta_pass": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS"),
                    "role": (_get_env_variable("SNOWFLAKE_AUTH_TEST_ROLE")).lower()
                    }

def _get_env_variable(name: str, required: bool = True) -> str:
    value = os.getenv(name)
    if required and value is None:
        raise EnvironmentError(f"Environment variable {name} is not set")
    return value

def get_okta_login_credentials():
    return {"login": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_USER"),
            "password": _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS")}


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
            "CLIENT_STORE_TEMPORARY_CREDENTIAL": False
        }

    def get_base_connection_parameters(self):
        return self.basic_config

    def get_external_browser_connection_parameters(self):
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "externalbrowser"

        return config

    def get_store_id_token_connection_parameters(self):
        config = self.get_external_browser_connection_parameters()

        config["CLIENT_STORE_TEMPORARY_CREDENTIAL"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_STORE_ID_TOKEN_USER")

        return config

    def get_okta_connection_parameters(self):
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["password"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASS")
        config["authenticator"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_URL")

        return config

    def get_oauth_connection_parameters(self, token: str):
        config = self.basic_config.copy()

        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "OAUTH"
        config["token"] = token
        return config

    def get_oauth_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")
        config["oauthClientSecret"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET")
        config["oauthRedirectURI"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_REDIRECT_URI")
        config["oauthAuthorizationUrl"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_AUTH_URL")
        config["oauthTokenRequestUrl"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN")
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")

        return config

    def get_snowflake_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_ID")
        config["oauthClientSecret"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_SECRET")
        config["oauthRedirectURI"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_REDIRECT_URI")
        config["role"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE")
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config


    def get_snowflake_wildcard_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_ID")
        config["oauthClientSecret"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_SECRET")
        config["role"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE")
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config

    def get_oauth_snowflake_client_credential_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_CLIENT_CREDENTIALS"
        config["oauthClientId"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")
        config["oauthClientSecret"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET")
        config["oauthTokenRequestUrl"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN")
        config["user"] = _get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config

