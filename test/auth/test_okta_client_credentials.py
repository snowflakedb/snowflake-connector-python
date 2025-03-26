#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import logging
from test.auth.authorization_parameters import AuthConnectionParameters

import pytest
from authorization_test_helper import AuthorizationTestHelper, clean_browser_processes


@pytest.fixture(autouse=True)
def setup_and_teardown():
    logging.info("Cleanup before test")
    clean_browser_processes()

    yield

    logging.info("Teardown: Performing specific actions after the test")
    clean_browser_processes()


@pytest.mark.auth
def test_okta_client_credentials_successful():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_client_credential_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_execute_simple_query()

    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth
def test_okta_client_credentials_mismatched_user():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_client_credential_connection_parameters()
    )
    connection_parameters["user"] = "differentUsername"
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_execute_simple_query()

    assert (
        "The user you were trying to authenticate as differs from the user"
        in test_helper.get_error_msg()
    )


@pytest.mark.auth
def test_external_browser_unauthorized():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_client_credential_connection_parameters()
    )
    connection_parameters["oauth_client_id"] = "invalidClientID"
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_execute_simple_query()

    assert "Invalid HTTP request from web browser" in test_helper.get_error_msg()
