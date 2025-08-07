import pathlib

import pytest

try:
    import snowflake.connector
    from src.snowflake.connector.network import PROGRAMMATIC_ACCESS_TOKEN
except ImportError:
    pass

from ..test_utils.wiremock.wiremock_utils import WiremockClient


@pytest.mark.skipolddriver
def test_valid_pat(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )

    wiremock_generic_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "generic"
    )

    wiremock_client.import_mapping(wiremock_data_dir / "successful_flow.json")
    wiremock_client.add_mapping(
        wiremock_generic_data_dir / "snowflake_disconnect_successful.json"
    )

    cnx = snowflake.connector.connect(
        authenticator=PROGRAMMATIC_ACCESS_TOKEN,
        token="some PAT",
        account="testAccount",
        protocol="http",
        host=wiremock_client.wiremock_host,
        port=wiremock_client.wiremock_http_port,
    )

    assert cnx, "invalid cnx"
    cnx.close()


@pytest.mark.skipolddriver
def test_invalid_pat(wiremock_client: WiremockClient) -> None:
    wiremock_data_dir = (
        pathlib.Path(__file__).parent.parent
        / "data"
        / "wiremock"
        / "mappings"
        / "auth"
        / "pat"
    )
    wiremock_client.import_mapping(wiremock_data_dir / "invalid_token.json")

    with pytest.raises(snowflake.connector.errors.DatabaseError) as execinfo:
        snowflake.connector.connect(
            authenticator=PROGRAMMATIC_ACCESS_TOKEN,
            token="some PAT",
            account="testAccount",
            protocol="http",
            host=wiremock_client.wiremock_host,
            port=wiremock_client.wiremock_http_port,
        )

    assert str(execinfo.value).endswith("Programmatic access token is invalid.")
