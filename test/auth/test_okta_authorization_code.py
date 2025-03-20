#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging

import pytest
from authorization_test_helper import (
    AuthorizationTestHelper,
    Scenario,
    clean_browser_processes,
)
from test.auth.authorization_parameters import AuthConnectionParameters, get_okta_login_credentials


@pytest.fixture(autouse=True)
def setup_and_teardown():
    logging.info("Cleanup before test")
    clean_browser_processes()

    yield

    logging.info("Teardown: Performing specific actions after the test")
    clean_browser_processes()


@pytest.mark.auth
def test_okta_authorization_code_successful():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_authorization_code_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)
    browser_login, browser_password = get_okta_login_credentials().values()
    test_helper.connect_and_provide_credentials(
        Scenario.SUCCESS, browser_login, browser_password
    )

    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth
def test_okta_authorization_code_mismatched_user():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_authorization_code_connection_parameters()
    )
    connection_parameters["user"] = "differentUsername"
    browser_login, browser_password = get_okta_login_credentials().values()

    test_helper = AuthorizationTestHelper(connection_parameters)
    test_helper.connect_and_provide_credentials(
        Scenario.SUCCESS, browser_login, browser_password
    )

    assert (
        "The user you were trying to authenticate as differs from the user"
        in test_helper.get_error_msg()
    )


@pytest.mark.auth
def test_okta_authorization_code_timeout():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_authorization_code_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)
    connection_parameters["timeout"] = 1

    assert (
        test_helper.connect_and_execute_simple_query() == False
    ), "Connection should not be established"
    assert (
        "TIMEOUT INFO" in test_helper.get_error_msg()
    )  # TODO: Adjust error message here


@pytest.mark.auth
def test_okta_authorization_code_token_cache():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_authorization_code_connection_parameters()
    )
    connection_parameters["token_cache"] = True  # TODO: Adjust field name here
    test_helper = AuthorizationTestHelper(connection_parameters)
    browser_login, browser_password = get_okta_login_credentials().values()

    test_helper.connect_and_provide_credentials(
        Scenario.FAIL, browser_login, browser_password
    )

    assert (
        test_helper.connect_and_execute_simple_query() == True
    ), "Connection should be established"
    assert test_helper.error_msg == "", "Error message should be empty"
