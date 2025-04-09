import logging
from test.auth.authorization_parameters import (
    AuthConnectionParameters,
    get_soteria_okta_login_credentials,
)

import pytest
from authorization_test_helper import (
    AuthorizationTestHelper,
    Scenario,
    clean_browser_processes,
)


@pytest.fixture(autouse=True)
def setup_and_teardown():
    logging.info("Cleanup before test")
    clean_browser_processes()

    yield

    logging.info("Teardown: Performing specific actions after the test")
    clean_browser_processes()


@pytest.mark.auth
def test_snowflake_authorization_code_successful():
    connection_parameters = (
        AuthConnectionParameters().get_snowflake_authorization_code_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)
    browser_login, browser_password = get_soteria_okta_login_credentials().values()

    test_helper.connect_and_provide_credentials(
        Scenario.INTERNAL_OAUTH_SNOWFLAKE_SUCCESS, browser_login, browser_password
    )

    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth
def test_snowflake_authorization_code_mismatched_user():
    connection_parameters = (
        AuthConnectionParameters().get_snowflake_authorization_code_connection_parameters()
    )
    connection_parameters["user"] = "differentUsername"
    browser_login, browser_password = get_soteria_okta_login_credentials().values()
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_provide_credentials(
        Scenario.INTERNAL_OAUTH_SNOWFLAKE_SUCCESS, browser_login, browser_password
    )

    assert (
        "The user you were trying to authenticate as differs from the user"
        in test_helper.get_error_msg()
    )


@pytest.mark.auth
def test_snowflake_authorization_code_timeout():
    connection_parameters = (
        AuthConnectionParameters().get_snowflake_authorization_code_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)
    connection_parameters["external_browser_timeout"] = 1

    assert (
        test_helper.connect_and_execute_simple_query() is False
    ), "Connection should not be established"
    assert (
        "Unable to receive the OAuth message within a given timeout"
        in test_helper.get_error_msg()
    )


@pytest.mark.auth
def test_snowflake_authorization_code_with_token_cache():
    connection_parameters = (
        AuthConnectionParameters().get_snowflake_authorization_code_connection_parameters()
    )
    connection_parameters["external_browser_timeout"] = 15
    connection_parameters["client_store_temporary_credential"] = True
    test_helper = AuthorizationTestHelper(connection_parameters)
    browser_login, browser_password = get_soteria_okta_login_credentials().values()

    test_helper.connect_and_provide_credentials(
        Scenario.INTERNAL_OAUTH_SNOWFLAKE_SUCCESS, browser_login, browser_password
    )

    clean_browser_processes()

    assert (
        test_helper.connect_and_execute_simple_query() is True
    ), "Connection should be established"
    assert test_helper.get_error_msg() == "", "Error message should be empty"


@pytest.mark.auth  # @pytest.mark.skip(reason="SNOW-1852279 implement error handling for invalid URL")
def test_snowflake_authorization_code_without_token_cache():
    connection_parameters = (
        AuthConnectionParameters().get_snowflake_authorization_code_connection_parameters()
    )
    connection_parameters["client_store_temporary_credential"] = False
    connection_parameters["external_browser_timeout"] = 15
    test_helper = AuthorizationTestHelper(connection_parameters)
    browser_login, browser_password = get_soteria_okta_login_credentials().values()

    test_helper.connect_and_provide_credentials(
        Scenario.INTERNAL_OAUTH_SNOWFLAKE_SUCCESS, browser_login, browser_password
    )

    clean_browser_processes()

    assert (
        test_helper.connect_and_execute_simple_query() is False
    ), "Connection should be established"

    assert (
        "Unable to receive the OAuth message within a given timeout"
        in test_helper.get_error_msg()
    ), "Error message should contain timeout"
