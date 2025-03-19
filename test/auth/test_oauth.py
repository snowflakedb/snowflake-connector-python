from .authorization_parameters import AuthConnectionParameters
from authorization_parameters import get_oauth_token_parameters
from authorization_test_helper import get_oauth_access_token, AuthorizationTestHelper


def test_oauth_successful():
    token = get_oauth_token()
    connection_parameters = AuthConnectionParameters().get_oauth_connection_parameters(token)
    test_helper = AuthorizationTestHelper(connection_parameters)
    assert test_helper.connect_and_execute_simple_query(), "Failed to connect with OAuth token"
    assert test_helper.error_msg == "", "Error message should be empty"


def test_oauth_mismatched_user():
    token = get_oauth_token()
    connection_parameters = AuthConnectionParameters().get_oauth_connection_parameters(token)
    connection_parameters["user"] = "differentUsername"
    test_helper = AuthorizationTestHelper(connection_parameters)
    assert test_helper.connect_and_execute_simple_query() == False, "Connection should not be established"
    assert "The user you were trying to authenticate as differs from the user" in test_helper.get_error_msg()


def test_oauth_invalid_token():
    token = "invalidToken"
    connection_parameters = AuthConnectionParameters().get_oauth_connection_parameters(token)
    test_helper = AuthorizationTestHelper(connection_parameters)
    assert test_helper.connect_and_execute_simple_query() == False, "Connection should not be established"
    assert "Invalid OAuth access token" in test_helper.get_error_msg()


def get_oauth_token():
    oauth_config = get_oauth_token_parameters()
    return get_oauth_access_token(oauth_config)
