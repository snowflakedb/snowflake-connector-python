import logging.config
import os
import subprocess

import pytest

import snowflake.connector

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


"""
Running tests locally:

1. Push branch to repository
2. Set environment variables PARAMETERS_SECRET and BRANCH
3. Run ci/test_wif.sh
"""


ACCOUNT = os.getenv("SNOWFLAKE_TEST_WIF_ACCOUNT")
HOST = os.getenv("SNOWFLAKE_TEST_WIF_HOST")
PROVIDER = os.getenv("SNOWFLAKE_TEST_WIF_PROVIDER")


@pytest.mark.wif
def test_wif_provider_autodetection():
    connection_params = {
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "host": HOST,
    }
    assert connect_and_execute_simple_query(
        connection_params
    ), "Failed to connect with using WIF - automatic provider detection"


@pytest.mark.wif
def test_wif_defined_provider():
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": PROVIDER,
    }
    assert connect_and_execute_simple_query(
        connection_params
    ), "Failed to connect with using WIF - automatic provider detection"


@pytest.mark.wif
def test_should_authenticate_using_oidc():
    if not is_provider_gcp():
        pytest.skip("Skipping test - not running on GCP")

    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "OIDC",
        "token": get_gcp_access_token(),
    }

    assert connect_and_execute_simple_query(
        connection_params
    ), "Failed to connect using WIF with OIDC provider"


def is_provider_gcp() -> bool:
    return PROVIDER == "GCP"


def connect_and_execute_simple_query(connection_params) -> bool:
    try:
        logger.info("Trying to connect to Snowflake")
        with snowflake.connector.connect(**connection_params) as con:
            result = con.cursor().execute("select 1;")
            logger.debug(result.fetchall())
            logger.info("Successfully connected to Snowflake")
            return True
    except Exception as e:
        logger.error(e)
        return False


def get_gcp_access_token() -> str:
    try:
        command = (
            'curl -H "Metadata-Flavor: Google" '
            '"http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=snowflakecomputing.com"'
        )

        result = subprocess.run(
            ["bash", "-c", command], capture_output=True, text=True, check=False
        )

        if result.returncode == 0 and result.stdout and result.stdout.strip():
            return result.stdout.strip()
        else:
            raise RuntimeError(
                f"Failed to retrieve GCP access token, exit code: {result.returncode}"
            )

    except Exception as e:
        raise RuntimeError(f"Error executing GCP metadata request: {e}")
