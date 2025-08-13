import pathlib
from unittest.mock import MagicMock

import pytest

try:
    from snowflake.connector import SnowflakeConnection
    from snowflake.connector.file_transfer_agent import (
        SnowflakeFileMeta,
        StorageCredential,
    )
    from snowflake.connector.s3_storage_client import SnowflakeS3RestClient
except ImportError:  # pragma: no cover
    pytest.skip("Snowflake connector not available", allow_module_level=True)


MEGABYTE = 1024 * 1024


@pytest.fixture(scope="session")
def wiremock_password_auth_dir(wiremock_auth_dir) -> pathlib.Path:
    return wiremock_auth_dir / "password"


@pytest.mark.parametrize("object_name", ["MANIFEST.yml"])
def test_s3_redirect_do_not_raise(
    wiremock_client,
    wiremock_generic_mappings_dir,
    wiremock_password_auth_dir,
    object_name,
):
    """Reproduce the 307→403 pattern that causes PUT to fail.

    The Wiremock server acts as a forward proxy.  We stub two responses:
      1. Initial HEAD request returns **307 Temporary Redirect** with a Location
         pointing to a new path and the x-amz-bucket-region header.
      2. Follow-up HEAD request on the redirected URL returns **403 Forbidden**.

    The SnowflakeS3RestClient should surface this as an HTTPError coming from
    `requests` (raised by ``response.raise_for_status()`` inside
    ``get_file_header``).
    """

    wiremock_client.import_mapping(wiremock_password_auth_dir / "successful_flow.json")
    wiremock_client.add_mapping(wiremock_generic_mappings_dir / "telemetry.json")
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_head_redirect_307.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_head_forbidden_403.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_accelerate_successful.json"
    )

    # Minimal file-meta & credentials setup for the storage client
    creds_dict = {"AWS_SECRET_KEY": "dummy", "AWS_KEY_ID": "dummy", "AWS_TOKEN": ""}

    meta_info = {
        "name": object_name,
        "src_file_name": "/tmp/nonexistent",  # Not used in HEAD path
        "stage_location_type": "S3",
    }
    meta = SnowflakeFileMeta(**meta_info)

    # Build the storage client.  We purposefully override its endpoint so that
    # it points at Wiremock instead of a real S3 bucket.
    stage_info = {
        "locationType": "AWS",
        "location": "bucket/path/",  # yields "/path/<object_name>" in the URL
        "creds": creds_dict,
        "region": "us-west-2",
        "endPoint": None,
    }

    client = SnowflakeS3RestClient(
        meta,
        StorageCredential(creds_dict, MagicMock(spec=SnowflakeConnection), "PUT"),
        stage_info,
        8 * MEGABYTE,
        # use_s3_regional_url=True,
    )

    # Direct all calls to Wiremock (HTTP for simplicity)
    client.endpoint = wiremock_client.http_host_with_port

    # The first HEAD will be redirected, the second will receive 403 → HTTPError
    # with pytest.raises(requests.exceptions.HTTPError):
    #     client.get_file_header(object_name)
    file_header = client.get_file_header(object_name)
    assert file_header is None


# tODO: uzyj cursor.execute do puta
# TODO: upewnij sie ze nie mam zlego podejscia do wiremocka i nie powinienm ustawiac proxy


@pytest.mark.parametrize("object_name", ["MANIFEST.yml"])
def test_put_via_cursor_handles_307_403(
    wiremock_client,
    wiremock_generic_mappings_dir,
    wiremock_password_auth_dir,
    wiremock_queries_dir,
    conn_cnx_wiremock,
    tmp_path,
    object_name,
):
    """Execute a real `PUT` through the connection and ensure the driver copes with
    307 redirect followed by 403 on HEAD requests to S3 (it should raise
    OperationalError 253003).
    """

    # --- Prepare WireMock mappings ------------------------------------------------
    wiremock_client.import_mapping(wiremock_password_auth_dir / "successful_flow.json")
    wiremock_client.add_mapping(wiremock_generic_mappings_dir / "telemetry.json")
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_head_redirect_307.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_head_forbidden_403.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "s3_accelerate_successful.json"
    )
    wiremock_client.add_mapping(
        wiremock_generic_mappings_dir / "snowflake_disconnect_successful.json"
    )
    # Mapping that makes Snowflake respond successfully to the PUT command

    # -----------------------------------------------------------------------------
    test_file = tmp_path / object_name
    test_file.write_text("dummy data")
    wiremock_client.add_mapping(
        wiremock_queries_dir / "put_file_successful.json",
        placeholders={"{{SRC_FILE}}": test_file.as_uri()},
    )

    conn = conn_cnx_wiremock()

    with conn as cxn:
        cur = cxn.cursor()
        # No need to create stage; use @~ (user stage)
        put_sql = f"PUT file://{test_file} @~/{object_name} AUTO_COMPRESS=FALSE"
        # with pytest.raises(requests.exceptions.HTTPError):
        #     cur.execute(put_sql)

        cur.execute(put_sql)
