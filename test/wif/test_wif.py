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
EXPECTED_USERNAME = os.getenv("SNOWFLAKE_TEST_WIF_USERNAME")
IMPERSONATION_PATH = os.getenv("SNOWFLAKE_TEST_WIF_IMPERSONATION_PATH")
EXPECTED_USERNAME_IMPERSONATION = os.getenv("SNOWFLAKE_TEST_WIF_USERNAME_IMPERSONATION")
_federated_token_file = os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "")
IS_AKS = bool(
    os.environ.get("AZURE_CLIENT_ID")
    and os.environ.get("AZURE_TENANT_ID")
    and _federated_token_file
    and os.path.exists(_federated_token_file)
)


@pytest.mark.wif
def test_wif_defined_provider():
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": PROVIDER,
    }
    assert connect_and_execute_simple_query(
        connection_params, EXPECTED_USERNAME
    ), f"Failed to connect with using WIF using provider {PROVIDER}"


@pytest.mark.wif
def test_aks_workload_identity_auth():
    """AKS workload identity authentication via WorkloadIdentityCredential.

    Covers MI and SP scenarios via different service accounts configured in CI:
    - Case 1: MI service account on cluster 1
    - Case 2: SP service account on cluster 1
    - Case 4: MI service account on cluster 2
    """
    if not IS_AKS or PROVIDER != "AZURE":
        pytest.skip("Requires AKS environment with AZURE provider")
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "AZURE",
    }
    assert connect_and_execute_simple_query(
        connection_params, EXPECTED_USERNAME
    ), "AKS workload identity authentication failed"


@pytest.mark.wif
def test_aks_oidc_backward_compat():
    """Case 3: OIDC backward-compatible path using K8s SA projected token."""
    if not IS_AKS:
        pytest.skip("Requires AKS environment")
    token_file = "/var/run/secrets/snowflake/token"
    if not os.path.exists(token_file):
        pytest.skip(f"Projected token file not found: {token_file}")
    with open(token_file) as f:
        token = f.read().strip()
    connection_params = {
        "host": HOST,
        "account": ACCOUNT,
        "authenticator": "WORKLOAD_IDENTITY",
        "workload_identity_provider": "OIDC",
        "token": token,
    }
    assert connect_and_execute_simple_query(
        connection_params, EXPECTED_USERNAME
    ), "AKS OIDC backward-compatible authentication failed"


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
        connection_params, expected_user=None
    ), "Failed to connect using WIF with OIDC provider"


@pytest.mark.wif
def test_should_authenticate_with_impersonation():
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

    assert connect_and_execute_simple_query(
        connection_params, EXPECTED_USERNAME_IMPERSONATION
    ), f"Failed to connect using WIF with provider {PROVIDER}"


@pytest.mark.wif
@pytest.mark.parametrize("outbound_token_enabled", ["true", "false"], ids=["outbound_token", "caller_identity"])
def test_should_authenticate_using_aws_with_issuer(outbound_token_enabled):
    if PROVIDER != "AWS":
        pytest.skip("Skipping test - not running on AWS")

    os.environ["SNOWFLAKE_ENABLE_AWS_WIF_OUTBOUND_TOKEN"] = outbound_token_enabled
    try:
        connection_params = {
            "host": HOST,
            "account": ACCOUNT,
            "authenticator": "WORKLOAD_IDENTITY",
            "workload_identity_provider": "AWS",
            "workload_identity_impersonation_path": ["arn:aws:iam::376129840140:role/drivers-wif-automated-tests-with-issuer"],
        }
        assert connect_and_execute_simple_query(
            connection_params, "TEST_WIF_E2E_AWS_WITH_ISSUER"
        ), f"Failed to connect using WIF with AWS outbound token enabled={outbound_token_enabled}"
    finally:
        os.environ.pop("SNOWFLAKE_ENABLE_AWS_WIF_OUTBOUND_TOKEN", None)


def is_provider_gcp() -> bool:
    return PROVIDER == "GCP"


def connect_and_execute_simple_query(connection_params, expected_user=None) -> bool:
    try:
        logger.info("Trying to connect to Snowflake")
        with snowflake.connector.connect(**connection_params) as con:
            result = con.cursor().execute("select current_user();")
            (user,) = result.fetchone()
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


def get_gcp_access_token() -> str:
    try:
        command = (
            'curl -H "Metadata-Flavor: Google" '
            '"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=snowflakecomputing.com"'
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
