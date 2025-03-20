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

from .authorization_parameters import (
    AuthConnectionParameters,
    get_okta_login_credentials,
)


@pytest.fixture(autouse=True)
def setup_and_teardown():
    logging.info("Cleanup before test")
    clean_browser_processes()

    yield

    logging.info("Teardown: Performing specific actions after the test")
    clean_browser_processes()


@pytest.mark.auth_test
def test_okta_client_credentials_successful():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_client_credential_connection_parameters()
    )
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_execute_simple_query()

    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth_test
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


@pytest.mark.auth_test
def test_external_browser_unauthorized():
    connection_parameters = (
        AuthConnectionParameters().get_oauth_external_client_credential_connection_parameters()
    )
    connection_parameters["oauthClientId"] = "invalidClientID"
    test_helper = AuthorizationTestHelper(connection_parameters)

    test_helper.connect_and_execute_simple_query()

    assert "Invalid OAuth access token" in test_helper.get_error_msg()
