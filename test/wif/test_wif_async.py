import logging
import os
from test.wif.test_wif import get_gcp_access_token, is_provider_gcp

import pytest

import snowflake.connector.aio

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
@pytest.mark.aio
async def test_wif_defined_provider_async():
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": PROVIDER,
    }
    assert connection_params == {}
    assert await connect_and_execute_simple_query_async(
        connection_params
    ), "Failed to connect with using WIF - automatic provider detection"


@pytest.mark.wif
@pytest.mark.aio
async def test_should_authenticate_using_oidc_async():
    if not is_provider_gcp():
        pytest.skip("Skipping test - not running on GCP")

    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "OIDC",
        "token": get_gcp_access_token(),
    }

    assert await connect_and_execute_simple_query_async(
        connection_params
    ), "Failed to connect using WIF with OIDC provider"


async def connect_and_execute_simple_query_async(connection_params) -> bool:
    try:
        logger.info("Trying to connect to Snowflake")
        async with snowflake.connector.aio.connect(**connection_params) as con:
            result = await con.cursor().execute("select 1;")
            logger.debug(await result.fetchall())
            logger.info("Successfully connected to Snowflake")
            return True
    except Exception as e:
        logger.error(e)
        return False
