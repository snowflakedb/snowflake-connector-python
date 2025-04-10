from datetime import datetime
from test.auth.authorization_parameters import (
    AuthConnectionParameters,
    get_pat_setup_command_variables,
)
from typing import Union

import pytest
from authorization_test_helper import AuthorizationTestHelper


@pytest.mark.auth
def test_authenticate_with_pat_successful():
    pat_command_variables = get_pat_setup_command_variables()
    connection_parameters = AuthConnectionParameters().get_pat_connection_parameters()
    test_helper = AuthorizationTestHelper(connection_parameters)
    try:
        pat_command_variables["snowflake_user"], connection_parameters["token"] = (
            get_pat_token(pat_command_variables).popitem()
        )
        test_helper.connect_and_execute_simple_query()
    finally:
        remove_pat_token(pat_command_variables)
    assert test_helper.get_error_msg() == "", "Error message should be empty"


@pytest.mark.auth
def test_authenticate_with_pat_mismatched_user():
    pat_command_variables = get_pat_setup_command_variables()
    connection_parameters = AuthConnectionParameters().get_pat_connection_parameters()
    connection_parameters["user"] = "differentUsername"
    test_helper = AuthorizationTestHelper(connection_parameters)
    try:

        pat_command_variables["snowflake_user"], connection_parameters["token"] = (
            get_pat_token(pat_command_variables).popitem()
        )
        test_helper.connect_and_execute_simple_query()
    finally:
        remove_pat_token(pat_command_variables)

    assert "Programmatic access token is invalid" in test_helper.get_error_msg()


@pytest.mark.auth
def test_authenticate_with_pat_invalid_token():
    connection_parameters = AuthConnectionParameters().get_pat_connection_parameters()
    connection_parameters["token"] = "invalidToken"
    test_helper = AuthorizationTestHelper(connection_parameters)
    test_helper.connect_and_execute_simple_query()
    assert "Programmatic access token is invalid" in test_helper.get_error_msg()


def get_pat_token(pat_command_variables) -> dict[str, Union[str, bool]]:
    okta_connection_parameters = (
        AuthConnectionParameters().get_okta_connection_parameters()
    )

    pat_name = "PAT_PYTHON_" + generate_random_suffix()
    pat_command_variables["pat_name"] = pat_name
    command = (
        f"alter user {pat_command_variables['snowflake_user']} add programmatic access token {pat_name} "
        f"ROLE_RESTRICTION = '{pat_command_variables['role']}' DAYS_TO_EXPIRY=1;"
    )
    test_helper = AuthorizationTestHelper(okta_connection_parameters)
    token = test_helper.connect_using_okta_connection_and_execute_custom_command(
        command, True
    )
    return {pat_name: token}


def remove_pat_token(pat_command_variables: dict[str, Union[str, bool]]) -> None:
    okta_connection_parameters = (
        AuthConnectionParameters().get_okta_connection_parameters()
    )

    command = f"alter user {pat_command_variables['snowflake_user']} remove programmatic access token {pat_command_variables['pat_name']};"
    test_helper = AuthorizationTestHelper(okta_connection_parameters)
    test_helper.connect_using_okta_connection_and_execute_custom_command(command)


def generate_random_suffix():
    return datetime.now().strftime("%Y%m%d%H%M%S%f")
