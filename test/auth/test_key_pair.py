from test.auth.authorization_parameters import (
    AuthConnectionParameters,
    get_rsa_private_key_for_key_pair,
)
from test.auth.authorization_test_helper import AuthorizationTestHelper

import pytest


@pytest.mark.auth
def test_key_pair_successful():
    connection_parameters = (
        AuthConnectionParameters().get_key_pair_connection_parameters()
    )
    connection_parameters["private_key"] = get_rsa_private_key_for_key_pair(
        "SNOWFLAKE_AUTH_TEST_PRIVATE_KEY_PATH"
    )

    test_helper = AuthorizationTestHelper(connection_parameters)
    assert (
        test_helper.connect_and_execute_simple_query()
    ), "Failed to connect with Snowflake"
    assert test_helper.error_msg == "", "Error message should be empty"


@pytest.mark.auth
def test_key_pair_invalid_key():
    connection_parameters = (
        AuthConnectionParameters().get_key_pair_connection_parameters()
    )
    connection_parameters["private_key"] = get_rsa_private_key_for_key_pair(
        "SNOWFLAKE_AUTH_TEST_INVALID_PRIVATE_KEY_PATH"
    )

    test_helper = AuthorizationTestHelper(connection_parameters)
    assert (
        not test_helper.connect_and_execute_simple_query()
    ), "Connection to Snowflake should not be established"
    assert "JWT token is invalid" in test_helper.get_error_msg()
