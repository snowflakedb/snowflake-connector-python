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
EXPECTED_USERNAME = os.getenv("SNOWFLAKE_TEST_WIF_USERNAME")
IMPERSONATION_PATH = os.getenv("SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH")
EXPECTED_USERNAME_IMPERSONATION = os.getenv("SNOWFLAKE_TEST_WIF_USERNAME_IMPERSONATION")
IS_AKS = bool(
    os.environ.get("AZURE_CLIENT_ID")
    and os.environ.get("AZURE_TENANT_ID")
    and os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
)


@pytest.mark.wif
@pytest.mark.asyncio
async def test_wif_defined_provider_async():
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": PROVIDER,
    }
    assert await connect_and_execute_simple_query_async(
        connection_params, EXPECTED_USERNAME
    ), f"Failed to connect with using WIF using provider {PROVIDER}"


@pytest.mark.wif
@pytest.mark.asyncio
async def test_aks_mi_native_auth_async():
    """Case 1 & 4: AKS native MI authentication via WorkloadIdentityCredential."""
    if not IS_AKS or PROVIDER != "AZURE":
        pytest.skip("Requires AKS environment with AZURE provider")
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "AZURE",
    }
    assert await connect_and_execute_simple_query_async(
        connection_params, EXPECTED_USERNAME
    ), "AKS MI native authentication failed"


@pytest.mark.wif
@pytest.mark.asyncio
async def test_aks_sp_direct_auth_async():
    """Case 2: AKS SP direct authentication via service account annotation."""
    if not IS_AKS or PROVIDER != "AZURE":
        pytest.skip("Requires AKS environment with AZURE provider")
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "AZURE",
    }
    assert await connect_and_execute_simple_query_async(
        connection_params, EXPECTED_USERNAME
    ), "AKS SP direct authentication failed"


@pytest.mark.wif
@pytest.mark.asyncio
async def test_aks_oidc_backward_compat_async():
    """Case 3: OIDC backward-compatible path using K8s SA projected token."""
    if not IS_AKS:
        pytest.skip("Requires AKS environment")
    token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE")
    if not token_file:
        pytest.skip("AZURE_FEDERATED_TOKEN_FILE not set")
    with open(token_file) as f:
        token = f.read().strip()
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "OIDC",
        "token": token,
    }
    assert await connect_and_execute_simple_query_async(
        connection_params, EXPECTED_USERNAME
    ), "AKS OIDC backward-compatible authentication failed"


@pytest.mark.wif
@pytest.mark.asyncio
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
        connection_params, expected_user=None
    ), "Failed to connect using WIF with OIDC provider"


@pytest.mark.wif
@pytest.mark.asyncio
async def test_should_authenticate_with_impersonation_async():
    if not isinstance(IMPERSONATION_PATH, str) or not IMPERSONATION_PATH:
        pytest.skip("Skipping test - IMPERSONATION_PATH is not set")

    logger.debug(f"Using impersonation path: {IMPERSONATION_PATH}")
    impersonation_path_list = IMPERSONATION_PATH.split(",")

    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": PROVIDER,
        "workload_identity_impersonation_path": impersonation_path_list,
    }

    assert await connect_and_execute_simple_query_async(
        connection_params, EXPECTED_USERNAME_IMPERSONATION
    ), f"Failed to connect using WIF with provider {PROVIDER}"


async def connect_and_execute_simple_query_async(
    connection_params, expected_user=None
) -> bool:
    try:
        logger.info("Trying to connect to Snowflake")
        async with snowflake.connector.aio.SnowflakeConnection(
            **connection_params
        ) as con:
            result = await con.cursor().execute("select current_user();")
            (user,) = await result.fetchone()
            logger.debug(user)
            if expected_user:
                assert (
                    expected_user == user
                ), f"Expected user '{expected_user}', got user '{user}'"
            logger.info(f"Successfully connected to Snowflake as {user}")
            return True
    except Exception as e:
        logger.error(e)
        return False
