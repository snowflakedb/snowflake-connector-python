#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from test.auth.authorization_parameters import AuthConnectionParameters
from test.auth.authorization_test_helper import AuthorizationTestHelper

import pytest


@pytest.mark.auth
def test_okta_successful():
    connection_parameters = AuthConnectionParameters().get_okta_connection_parameters()
    test_helper = AuthorizationTestHelper(connection_parameters)

    assert (
        test_helper.connect_and_execute_simple_query()
    ), "Failed to connect with Snowflake"
    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth
def test_okta_with_wrong_okta_username():
    connection_parameters = AuthConnectionParameters().get_okta_connection_parameters()
    connection_parameters["user"] = "differentUsername"

    test_helper = AuthorizationTestHelper(connection_parameters)
    assert (
        not test_helper.connect_and_execute_simple_query()
    ), "Connection to Snowflake should not be established"
    assert "Failed to get authentication by OKTA" in test_helper.get_error_msg()


@pytest.mark.auth
def test_okta_wrong_url():
    connection_parameters = AuthConnectionParameters().get_okta_connection_parameters()

    connection_parameters["authenticator"] = "https://invalid.okta.com/"
    test_helper = AuthorizationTestHelper(connection_parameters)
    assert (
        not test_helper.connect_and_execute_simple_query()
    ), "Connection to Snowflake should not be established"
    assert (
        "The specified authenticator is not accepted by your Snowflake account configuration"
        in test_helper.get_error_msg()
    )


@pytest.mark.auth
@pytest.mark.skip(reason="SNOW-1852279 implement error handling for invalid URL")
def test_okta_wrong_url_2():
    connection_parameters = AuthConnectionParameters().get_okta_connection_parameters()

    connection_parameters["authenticator"] = "https://invalid.abc.com/"
    test_helper = AuthorizationTestHelper(connection_parameters)
    assert (
        not test_helper.connect_and_execute_simple_query()
    ), "Connection to Snowflake should not be established"
    assert "The specified authenticator is not accepted by your Snowflake account configuration" in test_helper.get_error_msg()
