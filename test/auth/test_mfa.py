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

    connection_success = False
    last_error = ""

    # Try each TOTP code until one works
    for i, totp_code in enumerate(totp_codes):
        logging.info(f"Trying TOTP code {i+1}/{len(totp_codes)}")

        # Update the passcode in connection parameters
        connection_parameters["passcode"] = totp_code
        test_helper.update_config(connection_parameters)

        # Clear any previous error
        test_helper.error_msg = ""

        # Try to connect
        connection_success = test_helper.connect_and_execute_simple_query()

        if connection_success:
            logging.info(f"Successfully connected with TOTP code {i+1}")
            break
        else:
            last_error = str(test_helper.error_msg)
            logging.warning(f"TOTP code {i+1} failed: {last_error}")

            # Check if it's a TOTP-related error before continuing
            if "TOTP Invalid" in last_error:
                logging.info("TOTP/MFA error detected, trying next code...")
                continue
            else:
                # If it's not a TOTP error, no point trying other codes
                logging.error(f"Non-TOTP error detected: {last_error}")
                break

    assert (
        connection_success
    ), f"Failed to connect with any of the {len(totp_codes)} TOTP codes. Last error: {last_error}"
    assert (
        test_helper.error_msg == ""
    ), f"Final error message should be empty but got: {test_helper.error_msg}"

    logging.info("Testing MFA token caching with second connection...")

    # Create fresh connection parameters for cache test - but use same exact config
    cache_test_parameters = connection_parameters.copy()

    # Remove the passcode that was set in the loop - should use cached MFA token instead
    if "passcode" in cache_test_parameters:
        del cache_test_parameters["passcode"]

    # Create new helper for cache test
    cache_test_helper = AuthorizationTestHelper(cache_test_parameters)
    cache_test_helper.error_msg = ""
    cache_connection_success = cache_test_helper.connect_and_execute_simple_query()

    assert (
        cache_connection_success
    ), f"Failed to connect with cached MFA token. Error: {cache_test_helper.error_msg}"
    assert (
        cache_test_helper.error_msg == ""
    ), f"Cache test error message should be empty but got: {cache_test_helper.error_msg}"
