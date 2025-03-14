import os


class AuthConnectionParameters:
    def __init__(self, o):
        self.basic_config = {
            "host": self._get_env_variable("SNOWFLAKE_AUTH_TEST_HOST"),
            "port": self._get_env_variable("SNOWFLAKE_AUTH_TEST_PORT"),
            "role": self._get_env_variable("SNOWFLAKE_AUTH_TEST_ROLE"),
            "account": self._get_env_variable("SNOWFLAKE_AUTH_TEST_ACCOUNT"),
            "db": self._get_env_variable("SNOWFLAKE_AUTH_TEST_DATABASE"),
            "schema": self._get_env_variable("SNOWFLAKE_AUTH_TEST_SCHEMA"),
            "warehouse": self._get_env_variable("SNOWFLAKE_AUTH_TEST_WAREHOUSE"),
            "CLIENT_STORE_TEMPORARY_CREDENTIAL": False
        }

    def get_base_connection_parameters(self):
        return self.basic_config

    def get_external_browser_connection_parameters(self):
        config = self.basic_config.copy()

        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "externalbrowser"

        return config

    def get_store_id_token_connection_parameters(self):
        config = self.get_external_browser_connection_parameters()

        config["CLIENT_STORE_TEMPORARY_CREDENTIAL"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_STORE_ID_TOKEN_USER")

        return config

    def get_okta_connection_parameters(self):
        config = self.basic_config.copy()

        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["password"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_OKTA_PASSWORD")
        config["authenticator"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_OAUTH_URL")

        return config

    def get_oauth_connection_parameters(self, token: str):
        config = self.basic_config.copy()

        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")
        config["authenticator"] = "OAUTH"
        config["token"] = token

        return config

    def get_oauth_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")
        config["oauthClientSecret"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET")
        config["oauthRedirectURI"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_REDIRECT_URI")
        config["oauthAuthorizationUrl"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_AUTH_URL")
        config["oauthTokenRequestUrl"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN")
        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_BROWSER_USER")

        return config

    def get_snowflake_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_ID")
        config["oauthClientSecret"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_CLIENT_SECRET")
        config["oauthRedirectURI"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_REDIRECT_URI")
        config["role"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE")
        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config


    def get_snowflake_wildcard_external_authorization_code_connection_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_AUTHORIZATION_CODE"
        config["oauthClientId"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_ID")
        config["oauthClientSecret"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_WILDCARDS_CLIENT_SECRET")
        config["role"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_INTERNAL_OAUTH_SNOWFLAKE_ROLE")
        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config

    def get_oauth_snowflake_client_credential_parameters(self):
        config = self.basic_config.copy()

        config["authenticator"] = "OAUTH_CLIENT_CREDENTIALS"
        config["oauthClientId"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")
        config["oauthClientSecret"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_SECRET")
        config["oauthTokenRequestUrl"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_TOKEN")
        config["user"] = self._get_env_variable("SNOWFLAKE_AUTH_TEST_EXTERNAL_OAUTH_OKTA_CLIENT_ID")

        return config

    def _get_env_variable(self, name: str, required: bool = True) -> str:
        value = os.getenv(name)
        if required and value is None:
            raise EnvironmentError(f"Environment variable {name} is not set")
        return value

