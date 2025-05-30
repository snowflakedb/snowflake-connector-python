import uuid
from test.auth.authorization_parameters import (
    AuthConnectionParameters,
    get_pat_setup_command_variables,
)

import pytest
from authorization_test_helper import AuthorizationTestHelper
from test_pat import get_pat_token, remove_pat_token

EXTERNAL_SESSION_ID = str(uuid.uuid4())
SESSION_VAR_KEY = "PAT_WITH_EXTERNAL_SESSION_TEST_KEY"
SESSION_VAR_VALUE = "PAT_WITH_EXTERNAL_SESSION_TEST_VALUE"


@pytest.mark.auth
def test_pat_with_external_session_authN_success() -> None:
    pat_command_variables = get_pat_setup_command_variables()
    connection_parameters = AuthConnectionParameters().get_pat_connection_parameters()
    try:
        pat_command_variables = get_pat_token(pat_command_variables)
        connection_parameters["token"] = pat_command_variables["token"]
        connection_parameters["external_session_id"] = EXTERNAL_SESSION_ID
        connection_parameters["authenticator"] = "PAT_WITH_EXTERNAL_SESSION"
        test_helper = AuthorizationTestHelper(connection_parameters)
        test_helper.connect_and_execute_set_session_state(
            SESSION_VAR_KEY, SESSION_VAR_VALUE
        )
        ret = test_helper.connect_and_execute_check_session_state(SESSION_VAR_KEY)
        assert ret == SESSION_VAR_VALUE
    finally:
        remove_pat_token(pat_command_variables)
    assert test_helper.get_error_msg() == "", "Error message should be empty"


@pytest.mark.auth
def test_pat_with_external_session_authN_fail() -> None:
    pat_command_variables = get_pat_setup_command_variables()
    try:
        pat_command_variables = get_pat_token(pat_command_variables)
        connection_parameters = (
            AuthConnectionParameters().get_pat_connection_parameters()
        )
        connection_parameters["token"] = pat_command_variables["token"]
        connection_parameters["external_session_id"] = EXTERNAL_SESSION_ID
        connection_parameters["authenticator"] = "PAT_WITH_EXTERNAL_SESSION"
        test_helper = AuthorizationTestHelper(connection_parameters)
        test_helper.connect_and_execute_set_session_state(
            SESSION_VAR_KEY, SESSION_VAR_VALUE
        )
        connection_parameters["external_session_id"] = str(
            uuid.uuid4()
        )  # User different external session
        test_helper = AuthorizationTestHelper(connection_parameters)
        ret = test_helper.connect_and_execute_check_session_state(SESSION_VAR_KEY)
        assert ret != SESSION_VAR_VALUE
    finally:
        remove_pat_token(pat_command_variables)
    print(test_helper.get_error_msg())
    assert (
        f"Session variable '${SESSION_VAR_KEY}' does not exist"
        in test_helper.get_error_msg()
    )
