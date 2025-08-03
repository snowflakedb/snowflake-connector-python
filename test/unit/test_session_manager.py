#!/usr/bin/env python
from __future__ import annotations

from unittest import mock

from snowflake.connector.session_manager import ProxySupportAdapter, SessionManager

HOST_SFC_TEST_0 = "sfctest0.snowflakecomputing.com"
URL_SFC_TEST_0 = f"https://{HOST_SFC_TEST_0}:443/session/v1/login-request"

HOST_SFC_S3_STAGE = "sfc-ds2-customer-stage.s3.amazonaws.com"
URL_SFC_S3_STAGE_1 = f"https://{HOST_SFC_S3_STAGE}/rgm1-s-sfctest0/stages/"
URL_SFC_S3_STAGE_2 = f"https://{HOST_SFC_S3_STAGE}/rgm1-s-sfctst0/stages/another-url"


def create_session(
    manager: SessionManager, num_sessions: int = 1, url: str | None = None
) -> None:
    """Recursively create `num_sessions` sessions for `url`.

    Recursion ensures that multiple sessions are simultaneously active so that
    the SessionPool cannot immediately reuse an idle session.
    """
    if num_sessions == 0:
        return
    with manager.use_requests_session(url):
        create_session(manager, num_sessions - 1, url)


def close_and_assert(manager: SessionManager, expected_pool_count: int) -> None:
    """Close the manager and assert that close() was invoked on all expected pools."""
    with mock.patch(
        "snowflake.connector.session_manager.SessionPool.close"
    ) as close_mock:
        manager.close()
        assert close_mock.call_count == expected_pool_count


ORIGINAL_MAKE_SESSION = SessionManager.make_session


@mock.patch(
    "snowflake.connector.session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_pooling_disabled(make_session_mock):
    """When pooling is disabled every request creates and closes a new Session."""
    manager = SessionManager(use_pooling=False)

    create_session(manager, url=URL_SFC_TEST_0)
    create_session(manager, url=URL_SFC_TEST_0)

    # Two independent sessions were created
    assert make_session_mock.call_count == 2
    # Pooling disabled => no session pools maintained
    assert manager.sessions_map == {}

    close_and_assert(manager, expected_pool_count=0)


@mock.patch(
    "snowflake.connector.session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_single_hostname_pooling(make_session_mock):
    """A single hostname should result in exactly one underlying Session."""
    manager = SessionManager()  # pooling enabled by default

    # Create 5 sequential sessions for the same hostname
    for _ in range(5):
        create_session(manager, url=URL_SFC_TEST_0)

    # Only one underlying Session should have been created
    assert make_session_mock.call_count == 1

    assert list(manager.sessions_map.keys()) == [HOST_SFC_TEST_0]
    pool = manager.sessions_map[HOST_SFC_TEST_0]
    assert len(pool._idle_sessions) == 1
    assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=1)


@mock.patch(
    "snowflake.connector.session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_multiple_hostnames_separate_pools(make_session_mock):
    """Different hostnames (and None) should create separate pools."""
    manager = SessionManager()

    for url in [URL_SFC_TEST_0, URL_SFC_S3_STAGE_1, None]:
        create_session(manager, num_sessions=2, url=url)

    # Two sessions created for each of the three keys (HOST_SFC_TEST_0, HOST_SFC_S3_STAGE, None)
    assert make_session_mock.call_count == 6

    for expected_host in [HOST_SFC_TEST_0, HOST_SFC_S3_STAGE, None]:
        assert expected_host in manager.sessions_map

    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 2
        assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=3)


@mock.patch(
    "snowflake.connector.session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_reuse_sessions_within_pool(make_session_mock):
    """After many sequential sessions only one Session per hostname should exist."""
    manager = SessionManager()

    for url in [URL_SFC_TEST_0, URL_SFC_S3_STAGE_1, URL_SFC_S3_STAGE_2, None]:
        for _ in range(10):
            create_session(manager, url=url)

    # One Session per unique hostname (URL_SFC_S3_STAGE_2 shares HOST_SFC_S3_STAGE)
    assert make_session_mock.call_count == 3

    assert set(manager.sessions_map.keys()) == {
        HOST_SFC_TEST_0,
        HOST_SFC_S3_STAGE,
        None,
    }
    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 1
        assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=3)


def test_clone_independence():
    """`clone` should return an independent manager sharing only the adapter_factory."""
    manager = SessionManager()
    with manager.use_requests_session(URL_SFC_TEST_0):
        pass
    assert HOST_SFC_TEST_0 in manager.sessions_map

    clone = manager.shallow_clone()

    assert clone is not manager
    assert clone.adapter_factory is manager.adapter_factory
    assert clone.sessions_map == {}

    with clone.use_requests_session(URL_SFC_S3_STAGE_1):
        pass

    assert HOST_SFC_S3_STAGE in clone.sessions_map
    assert HOST_SFC_S3_STAGE not in manager.sessions_map


def test_mount_adapters_and_pool_manager():
    """Verify that default adapter factory mounts ProxySupportAdapter correctly."""
    manager = SessionManager()

    session = manager.make_session()
    adapter = session.get_adapter("https://example.com")
    assert isinstance(adapter, ProxySupportAdapter)

    pool_manager = manager.get_session_pool_manager(session, "https://example.com")
    assert pool_manager is not None
