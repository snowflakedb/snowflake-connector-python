#!/usr/bin/env python
from __future__ import annotations

from unittest import mock

import pytest

from snowflake.connector.session_manager import (
    HttpConfig,
    ProxySupportAdapter,
    ProxySupportAdapterFactory,
    SessionManager,
)
from snowflake.connector.vendored.urllib3 import Retry

# Module and class path constants for easier refactoring
SESSION_MANAGER_MODULE = "snowflake.connector.session_manager"
SESSION_MANAGER = f"{SESSION_MANAGER_MODULE}.SessionManager"

TEST_HOST_1 = "testaccount.example.com"
TEST_URL_1 = f"https://{TEST_HOST_1}:443/session/v1/login-request"

TEST_STORAGE_HOST = "test-customer-stage.s3.example.com"
TEST_STORAGE_URL_1 = f"https://{TEST_STORAGE_HOST}/test-stage/stages/"
TEST_STORAGE_URL_2 = f"https://{TEST_STORAGE_HOST}/test-stage/stages/another-url"


def create_session(
    manager: SessionManager, num_sessions: int = 1, url: str | None = None
) -> None:
    """Recursively create `num_sessions` sessions for `url`.

    Recursion ensures that multiple sessions are simultaneously active so that
    the SessionPool cannot immediately reuse an idle session.
    """
    if num_sessions == 0:
        return
    with manager.use_session(url):
        create_session(manager, num_sessions - 1, url)


def close_and_assert(manager: SessionManager, expected_pool_count: int) -> None:
    """Close the manager and assert that close() was invoked on all expected pools."""
    with mock.patch(f"{SESSION_MANAGER_MODULE}.SessionPool.close") as close_mock:
        manager.close()
        assert close_mock.call_count == expected_pool_count


ORIGINAL_MAKE_SESSION = SessionManager.make_session


@mock.patch(
    f"{SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_pooling_disabled(make_session_mock):
    """When pooling is disabled every request creates and closes a new Session."""
    manager = SessionManager(use_pooling=False)

    create_session(manager, url=TEST_URL_1)
    create_session(manager, url=TEST_URL_1)

    # Two independent sessions were created
    assert make_session_mock.call_count == 2
    # Pooling disabled => no session pools maintained
    assert manager.sessions_map == {}

    close_and_assert(manager, expected_pool_count=0)


@mock.patch(
    f"{SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_single_hostname_pooling(make_session_mock):
    """A single hostname should result in exactly one underlying Session."""
    manager = SessionManager()  # pooling enabled by default

    # Create 5 sequential sessions for the same hostname
    for _ in range(5):
        create_session(manager, url=TEST_URL_1)

    # Only one underlying Session should have been created
    assert make_session_mock.call_count == 1

    assert list(manager.sessions_map.keys()) == [TEST_HOST_1]
    pool = manager.sessions_map[TEST_HOST_1]
    assert len(pool._idle_sessions) == 1
    assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=1)


@mock.patch(
    f"{SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_multiple_hostnames_separate_pools(make_session_mock):
    """Different hostnames (and None) should create separate pools."""
    manager = SessionManager()

    for url in [TEST_URL_1, TEST_STORAGE_URL_1, None]:
        create_session(manager, num_sessions=2, url=url)

    # Two sessions created for each of the three keys (TEST_HOST_1, TEST_STORAGE_HOST, None)
    assert make_session_mock.call_count == 6

    for expected_host in [TEST_HOST_1, TEST_STORAGE_HOST, None]:
        assert expected_host in manager.sessions_map

    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 2
        assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=3)


@mock.patch(
    f"{SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
def test_reuse_sessions_within_pool(make_session_mock):
    """After many sequential sessions only one Session per hostname should exist."""
    manager = SessionManager()

    for url in [TEST_URL_1, TEST_STORAGE_URL_1, TEST_STORAGE_URL_2, None]:
        for _ in range(10):
            create_session(manager, url=url)

    # One Session per unique hostname (TEST_STORAGE_URL_2 shares TEST_STORAGE_HOST)
    assert make_session_mock.call_count == 3

    assert set(manager.sessions_map.keys()) == {
        TEST_HOST_1,
        TEST_STORAGE_HOST,
        None,
    }
    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 1
        assert len(pool._active_sessions) == 0

    close_and_assert(manager, expected_pool_count=3)


def test_clone_independence():
    """`clone` should return an independent manager sharing only the adapter_factory."""
    manager = SessionManager()
    with manager.use_session(TEST_URL_1):
        pass
    assert TEST_HOST_1 in manager.sessions_map

    clone = manager.clone()

    assert clone is not manager
    assert clone.adapter_factory is manager.adapter_factory
    assert clone.sessions_map == {}

    with clone.use_session(TEST_STORAGE_URL_1):
        pass

    assert TEST_STORAGE_HOST in clone.sessions_map
    assert TEST_STORAGE_HOST not in manager.sessions_map


def test_mount_adapters_and_pool_manager():
    """Verify that default adapter factory mounts ProxySupportAdapter correctly."""
    manager = SessionManager()

    session = manager.make_session()
    adapter = session.get_adapter("https://example.com")
    assert isinstance(adapter, ProxySupportAdapter)

    pool_manager = manager.get_session_pool_manager(session, "https://example.com")
    assert pool_manager is not None


def test_clone_independent_pools():
    """A clone must *not* share its SessionPool objects with the original."""
    from snowflake.connector.session_manager import (
        HttpConfig,
        ProxySupportAdapterFactory,
        SessionManager,
    )

    base = SessionManager(
        HttpConfig(adapter_factory=ProxySupportAdapterFactory(), use_pooling=True)
    )

    # Use the base manager – this should register a pool for the hostname
    with base.use_session("https://example.com"):
        pass
    assert "example.com" in base.sessions_map

    clone = base.clone()
    # No pools yet in the clone
    assert clone.sessions_map == {}

    # After use the clone should have its own pool, distinct from the base’s pool
    with clone.use_session("https://example.com"):
        pass
    assert "example.com" in clone.sessions_map
    assert clone.sessions_map["example.com"] is not base.sessions_map["example.com"]


def test_context_var_weakref_does_not_leak():
    """Setting the current SessionManager should not create a strong ref that keeps it alive."""
    import gc

    from snowflake.connector.session_manager import (
        HttpConfig,
        ProxySupportAdapterFactory,
        SessionManager,
    )
    from snowflake.connector.ssl_wrap_socket import (
        get_current_session_manager,
        reset_current_session_manager,
        set_current_session_manager,
    )

    passed_max_retries = 12345
    passed_config = HttpConfig(
        adapter_factory=ProxySupportAdapterFactory(),
        use_pooling=False,
        max_retries=passed_max_retries,
    )
    sm = SessionManager(passed_config)
    token = set_current_session_manager(sm)

    # The context var should return the same object while it's alive
    assert (
        get_current_session_manager(create_default_if_missing=False).config
        == passed_config
    )

    # Delete all strong refs and force GC – the weakref in the ContextVar should be cleared
    del sm
    gc.collect()

    reset_current_session_manager(token)
    assert get_current_session_manager(create_default_if_missing=False) is None


@pytest.fixture
def mock_adapter_with_factory():
    """Fixture providing a mock adapter factory and adapter."""
    mock_adapter_factory = mock.MagicMock()
    mock_adapter = mock.MagicMock()
    mock_adapter_factory.return_value = mock_adapter
    return mock_adapter, mock_adapter_factory


@pytest.mark.parametrize(
    "max_retries,extra_kwargs,expected_kwargs",
    [
        # Test with integer max_retries
        (
            5,
            {"timeout": 30, "pool_connections": 10},
            {"timeout": 30, "pool_connections": 10, "max_retries": 5},
        ),
        # Test with None max_retries
        (None, {}, {"max_retries": None}),
        # Test with no extra kwargs
        (7, {}, {"max_retries": 7}),
        # Test override by extra kwargs
        (0.2, {"max_retries": 0.7}, {"max_retries": 0.7}),
    ],
)
def test_http_config_get_adapter_parametrized(
    mock_adapter_with_factory, max_retries, extra_kwargs, expected_kwargs
):
    """Test that HttpConfig.get_adapter properly passes kwargs and max_retries to adapter factory."""
    mock_adapter, mock_adapter_factory = mock_adapter_with_factory

    config = HttpConfig(adapter_factory=mock_adapter_factory, max_retries=max_retries)
    result = config.get_adapter(**extra_kwargs)

    # Verify the adapter factory was called with correct arguments
    mock_adapter_factory.assert_called_once_with(**expected_kwargs)
    assert result is mock_adapter


def test_http_config_get_adapter_with_retry_object(mock_adapter_with_factory):
    """Test get_adapter with Retry object as max_retries."""
    mock_adapter, mock_adapter_factory = mock_adapter_with_factory

    retry_config = Retry(total=3, backoff_factor=0.3)
    config = HttpConfig(adapter_factory=mock_adapter_factory, max_retries=retry_config)

    result = config.get_adapter(pool_maxsize=20)

    # Verify the call was made with the Retry object
    mock_adapter_factory.assert_called_once()
    call_args = mock_adapter_factory.call_args
    assert call_args.kwargs["pool_maxsize"] == 20
    assert call_args.kwargs["max_retries"] is retry_config  # Same object reference
    assert result is mock_adapter


def test_http_config_get_adapter_kwargs_override(mock_adapter_with_factory):
    """Test that get_adapter config's max_retries takes precedence over kwargs max_retries."""
    mock_adapter, mock_adapter_factory = mock_adapter_with_factory

    config = HttpConfig(adapter_factory=mock_adapter_factory, max_retries=5)

    # The config's max_retries should override any passed in kwargs
    result = config.get_adapter(max_retries=10, timeout=30)

    # Verify that config's max_retries (5) takes precedence over kwargs max_retries (10)
    mock_adapter_factory.assert_called_once_with(max_retries=10, timeout=30)
    assert result is mock_adapter


def test_http_config_get_adapter_with_real_factory():
    """Test get_adapter with the actual ProxySupportAdapterFactory."""
    config = HttpConfig(adapter_factory=ProxySupportAdapterFactory(), max_retries=3)

    adapter = config.get_adapter()

    # Verify we get a real ProxySupportAdapter instance
    assert isinstance(adapter, ProxySupportAdapter)
    # Verify max_retries was set correctly
    assert adapter.max_retries.total == 3
