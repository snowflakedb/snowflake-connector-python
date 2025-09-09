import logging
from test.auth.authorization_parameters import AuthConnectionParameters
from test.auth.authorization_test_helper import AuthorizationTestHelper

import pytest


@pytest.mark.auth
def test_mfa_successful():
    connection_parameters = AuthConnectionParameters().get_mfa_connection_parameters()
    connection_parameters["client_request_mfa_token"] = True
    test_helper = AuthorizationTestHelper(connection_parameters)
    totp_codes = test_helper.get_totp()
    logging.info(f"Got {len(totp_codes)} TOTP codes to try")

    connection_success = test_helper.connect_and_execute_simple_query_with_mfa_token(
        totp_codes
    )

    assert (
        connection_success
    ), f"Failed to connect with any of the {len(totp_codes)} TOTP codes. Last error: {test_helper.error_msg}"
    assert (
        test_helper.error_msg == ""
    ), f"Final error message should be empty but got: {test_helper.error_msg}"

    logging.info("Testing MFA token caching with second connection...")

    connection_parameters["passcode"] = None
    cache_test_helper = AuthorizationTestHelper(connection_parameters)
    cache_connection_success = cache_test_helper.connect_and_execute_simple_query()

    assert (
        cache_connection_success
    ), f"Failed to connect with cached MFA token. Error: {cache_test_helper.error_msg}"
    assert (
        cache_test_helper.error_msg == ""
    ), f"Cache test error message should be empty but got: {cache_test_helper.error_msg}"
