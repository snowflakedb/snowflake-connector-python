import uuid
from test.auth.authorization_parameters import (
    AuthConnectionParameters,
    get_pat_setup_command_variables,
)

import pytest
from authorization_test_helper import AuthorizationTestHelper
from test_pat import get_pat_token, remove_pat_token

EXTERNAL_SESSION_ID = str(uuid.uuid4())


@pytest.mark.auth
def test_authenticate_pat_with_external_session_successful() -> None:
    pat_command_variables = get_pat_setup_command_variables()
    connection_parameters = AuthConnectionParameters().get_pat_connection_parameters()
    try:
        pat_command_variables = get_pat_token(pat_command_variables)
        print(f"PAT token = {pat_command_variables['token']}")
        del connection_parameters["password"]
        connection_parameters["token"] = pat_command_variables["token"]
        connection_parameters["external_session_id"] = EXTERNAL_SESSION_ID
        connection_parameters["authenticator"] = "PAT_WITH_EXTERNAL_SESSION"
        test_helper = AuthorizationTestHelper(connection_parameters)
        session_key = "my_pat_with_external_session_key"
        session_value = "my_pat_with_external_session_value"
        test_helper.connect_and_execute_set_session_state(session_key, session_value)
        ret = test_helper.connect_and_execute_check_session_state(session_key)
        assert ret == session_value
    finally:
        remove_pat_token(pat_command_variables)
    assert test_helper.get_error_msg() == "", "Error message should be empty"
