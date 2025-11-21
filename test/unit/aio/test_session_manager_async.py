#!/usr/bin/env python
from __future__ import annotations

from unittest import mock

import aiohttp
import pytest

from snowflake.connector.aio._session_manager import (
    AioHttpConfig,
    SessionManager,
    SnowflakeSSLConnector,
    SnowflakeSSLConnectorFactory,
)
from snowflake.connector.constants import OCSPMode

# Module and class path constants for easier refactoring
ASYNC_SESSION_MANAGER_MODULE = "snowflake.connector.aio._session_manager"
ASYNC_SESSION_MANAGER = f"{ASYNC_SESSION_MANAGER_MODULE}.SessionManager"

TEST_HOST_1 = "testaccount.example.com"
TEST_URL_1 = f"https://{TEST_HOST_1}:443/session/v1/login-request"

TEST_STORAGE_HOST = "test-customer-stage.s3.example.com"
TEST_STORAGE_URL_1 = f"https://{TEST_STORAGE_HOST}/test-stage/stages/"
TEST_STORAGE_URL_2 = f"https://{TEST_STORAGE_HOST}/test-stage/stages/another-url"


async def create_session(
    manager: SessionManager, num_sessions: int = 1, url: str | None = None
) -> None:
    """Recursively create `num_sessions` sessions for `url`.

    Recursion ensures that multiple sessions are simultaneously active so that
    the SessionPool cannot immediately reuse an idle session.
    """
    if num_sessions == 0:
        return
    async with manager.use_session(url):
        await create_session(manager, num_sessions - 1, url)


async def close_and_assert(manager: SessionManager, expected_pool_count: int) -> None:
    """Close the manager and assert that close() was invoked on all expected pools."""
    with mock.patch(
        "snowflake.connector.aio._session_manager.SessionPool.close"
    ) as close_mock:
        await manager.close()
        assert close_mock.call_count == expected_pool_count


ORIGINAL_MAKE_SESSION = SessionManager.make_session


@mock.patch(
    f"{ASYNC_SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_pooling_disabled(make_session_mock):
    """When pooling is disabled every request creates and closes a new Session."""
    manager = SessionManager(use_pooling=False)

    await create_session(manager, url=TEST_URL_1)
    await create_session(manager, url=TEST_URL_1)

    # Two independent sessions were created
    assert make_session_mock.call_count == 2
    # Pooling disabled => no session pools maintained
    assert manager.sessions_map == {}

    await close_and_assert(manager, expected_pool_count=0)


@mock.patch(
    f"{ASYNC_SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_single_hostname_pooling(make_session_mock):
    """A single hostname should result in exactly one underlying Session."""
    manager = SessionManager()  # pooling enabled by default

    # Create 5 sequential sessions for the same hostname
    for _ in range(5):
        await create_session(manager, url=TEST_URL_1)

    # Only one underlying Session should have been created
    assert make_session_mock.call_count == 1

    assert list(manager.sessions_map.keys()) == [TEST_HOST_1]
    pool = manager.sessions_map[TEST_HOST_1]
    assert len(pool._idle_sessions) == 1
    assert len(pool._active_sessions) == 0

    await close_and_assert(manager, expected_pool_count=1)


@mock.patch(
    f"{ASYNC_SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_multiple_hostnames_separate_pools(make_session_mock):
    """Different hostnames (and None) should create separate pools."""
    manager = SessionManager()

    for url in [TEST_URL_1, TEST_STORAGE_URL_1, None]:
        await create_session(manager, num_sessions=2, url=url)

    # Two sessions created for each of the three keys (TEST_HOST_1, TEST_STORAGE_HOST, None)
    assert make_session_mock.call_count == 6

    for expected_host in [TEST_HOST_1, TEST_STORAGE_HOST, None]:
        assert expected_host in manager.sessions_map

    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 2
        assert len(pool._active_sessions) == 0

    await close_and_assert(manager, expected_pool_count=3)


@mock.patch(
    f"{ASYNC_SESSION_MANAGER}.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_reuse_sessions_within_pool(make_session_mock):
    """After many sequential sessions only one Session per hostname should exist."""
    manager = SessionManager()

    for url in [TEST_URL_1, TEST_STORAGE_URL_1, TEST_STORAGE_URL_2, None]:
        for _ in range(10):
            await create_session(manager, url=url)

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

    await close_and_assert(manager, expected_pool_count=3)


async def test_clone_independence():
    """`clone` should return an independent manager sharing only the connector_factory."""
    manager = SessionManager()
    async with manager.use_session(TEST_URL_1):
        pass
    assert TEST_HOST_1 in manager.sessions_map

    clone = manager.clone()

    assert clone is not manager
    assert clone.connector_factory is manager.connector_factory
    assert clone.sessions_map == {}

    async with clone.use_session(TEST_STORAGE_URL_1):
        pass

    assert TEST_STORAGE_HOST in clone.sessions_map
    assert TEST_STORAGE_HOST not in manager.sessions_map

    await manager.close()
    await clone.close()


async def test_connector_factory_creates_sessions():
    """Verify that connector factory creates aiohttp sessions with proper connector."""
    manager = SessionManager()

    session = manager.make_session()
    assert session is not None
    # Verify it's an aiohttp.ClientSession
    assert hasattr(session, "connector")
    assert session.connector is not None

    await session.close()


async def test_clone_independent_pools():
    """A clone must *not* share its SessionPool objects with the original."""
    base = SessionManager(
        AioHttpConfig(
            connector_factory=SnowflakeSSLConnectorFactory(),
            use_pooling=True,
        )
    )

    # Use the base manager – this should register a pool for the hostname
    async with base.use_session("https://example.com"):
        pass
    assert "example.com" in base.sessions_map

    clone = base.clone()
    # No pools yet in the clone
    assert clone.sessions_map == {}

    # After use the clone should have its own pool, distinct from the base's pool
    async with clone.use_session("https://example.com"):
        pass
    assert "example.com" in clone.sessions_map
    assert clone.sessions_map["example.com"] is not base.sessions_map["example.com"]

    await base.close()
    await clone.close()


async def test_config_propagation():
    """Verify that config values are properly propagated to sessions."""
    config = AioHttpConfig(
        connector_factory=SnowflakeSSLConnectorFactory(),
        use_pooling=True,
        trust_env=False,
        snowflake_ocsp_mode=OCSPMode.FAIL_CLOSED,
    )
    manager = SessionManager(config)

    assert manager.config is config
    assert manager.config.trust_env is False
    assert manager.config.snowflake_ocsp_mode == OCSPMode.FAIL_CLOSED

    # Verify session is created with the config
    session = manager.make_session()
    assert session is not None
    assert session._trust_env is False  # trust_env passed to ClientSession

    await session.close()


async def test_config_copy_with():
    """Test that copy_with creates a new config with overrides."""
    original_config = AioHttpConfig(
        use_pooling=True,
        trust_env=True,
        snowflake_ocsp_mode=OCSPMode.FAIL_OPEN,
    )

    new_config = original_config.copy_with(
        use_pooling=False,
        snowflake_ocsp_mode=OCSPMode.FAIL_CLOSED,
    )

    # Original unchanged
    assert original_config.use_pooling is True
    assert original_config.trust_env is True
    assert original_config.snowflake_ocsp_mode == OCSPMode.FAIL_OPEN

    # New config has overrides
    assert new_config.use_pooling is False
    assert new_config.trust_env is True  # unchanged
    assert new_config.snowflake_ocsp_mode == OCSPMode.FAIL_CLOSED


async def test_from_config():
    """Test creating SessionManager from existing config."""
    config = AioHttpConfig(
        use_pooling=False,
        trust_env=False,
    )

    manager = SessionManager.from_config(config)
    assert manager.config is config
    assert manager.use_pooling is False

    # Test with overrides
    manager2 = SessionManager.from_config(config, use_pooling=True)
    assert manager2.config is not config  # new config created
    assert manager2.use_pooling is True
    assert manager2.config.trust_env is False  # original value preserved


async def test_session_pool_lifecycle():
    """Test that session pool properly manages session lifecycle."""
    manager = SessionManager(use_pooling=True)

    # Get a session - should create new one
    async with manager.use_session(TEST_URL_1):
        assert TEST_HOST_1 in manager.sessions_map
        pool = manager.sessions_map[TEST_HOST_1]
        assert len(pool._active_sessions) == 1
        assert len(pool._idle_sessions) == 0

    # After context exit, session should be idle
    assert len(pool._active_sessions) == 0
    assert len(pool._idle_sessions) == 1

    # Reuse the same session
    async with manager.use_session(TEST_URL_1):
        assert len(pool._active_sessions) == 1
        assert len(pool._idle_sessions) == 0

    await manager.close()


async def test_config_immutability():
    """Test that AioHttpConfig is immutable (frozen dataclass)."""
    config = AioHttpConfig(
        use_pooling=True,
        trust_env=True,
        snowflake_ocsp_mode=OCSPMode.FAIL_OPEN,
    )

    # Attempting to modify should raise an error
    with pytest.raises(AttributeError):
        config.use_pooling = False

    with pytest.raises(AttributeError):
        config.trust_env = False

    # copy_with should be the only way to create variants
    new_config = config.copy_with(trust_env=False)
    assert config.trust_env is True
    assert new_config.trust_env is False


async def test_pickle_session_manager():
    """Test that SessionManager can be pickled and unpickled."""
    import pickle

    config = AioHttpConfig(
        use_pooling=True,
        trust_env=False,
    )
    manager = SessionManager(config)

    # Create some sessions
    async with manager.use_session(TEST_URL_1):
        pass

    # Pickle and unpickle (sessions are discarded during pickle)
    pickled = pickle.dumps(manager)
    unpickled = pickle.loads(pickled)

    assert unpickled is not manager
    assert unpickled.config.trust_env is False
    assert unpickled.use_pooling is True
    # Pool structure preserved but sessions are empty after unpickling
    assert TEST_HOST_1 in unpickled.sessions_map
    pool = unpickled.sessions_map[TEST_HOST_1]
    assert len(pool._idle_sessions) == 0
    assert len(pool._active_sessions) == 0

    await manager.close()
    await unpickled.close()


@pytest.fixture
def mock_connector_with_factory():
    """Fixture providing a mock connector factory and connector."""
    mock_connector_factory = mock.MagicMock()
    mock_connector = mock.MagicMock()
    mock_connector_factory.return_value = mock_connector
    return mock_connector, mock_connector_factory


@pytest.mark.parametrize(
    "ocsp_mode,extra_kwargs,expected_kwargs",
    [
        # Test with OCSPMode.FAIL_OPEN + extra kwargs (should all appear)
        (
            OCSPMode.FAIL_OPEN,
            {"timeout": 30, "pool_connections": 10},
            {
                "timeout": 30,
                "pool_connections": 10,
                "snowflake_ocsp_mode": OCSPMode.FAIL_OPEN,
                "ocsp_root_certs_dict_lock_timeout": -1,
                "ocsp_response_cache_file_name": None,
            },
        ),
        # Test with OCSPMode.FAIL_CLOSED + no extra kwargs
        (
            OCSPMode.FAIL_CLOSED,
            {},
            {
                "snowflake_ocsp_mode": OCSPMode.FAIL_CLOSED,
                "ocsp_root_certs_dict_lock_timeout": -1,
                "ocsp_response_cache_file_name": None,
            },
        ),
        # Checks that None values also cause kwargs name to occur
        (
            None,
            {},
            {
                "snowflake_ocsp_mode": None,
                "ocsp_root_certs_dict_lock_timeout": -1,
                "ocsp_response_cache_file_name": None,
            },
        ),
        # Test override by extra kwargs: config has FAIL_OPEN but extra_kwargs override with FAIL_CLOSED
        (
            OCSPMode.FAIL_OPEN,
            {"snowflake_ocsp_mode": OCSPMode.FAIL_CLOSED},
            {
                "snowflake_ocsp_mode": OCSPMode.FAIL_CLOSED,
                "ocsp_root_certs_dict_lock_timeout": -1,
                "ocsp_response_cache_file_name": None,
            },
        ),
    ],
)
async def test_aio_http_config_get_connector_parametrized(
    mock_connector_with_factory, ocsp_mode, extra_kwargs, expected_kwargs
):
    """Test that AioHttpConfig.get_connector properly passes kwargs and snowflake_ocsp_mode to connector factory.

    This mirrors the sync test behavior where:
    - Config attributes are passed to the factory
    - Extra kwargs can override config attributes
    - All resulting attributes appear in the factory call
    """
    mock_connector, mock_connector_factory = mock_connector_with_factory

    config = AioHttpConfig(
        connector_factory=mock_connector_factory, snowflake_ocsp_mode=ocsp_mode
    )
    result = config.get_connector(**extra_kwargs)

    # Verify the connector factory was called with correct arguments
    mock_connector_factory.assert_called_once_with(**expected_kwargs)
    assert result is mock_connector


async def test_aio_http_config_get_connector_with_real_connector_factory():
    """Test get_connector with the actual SnowflakeSSLConnectorFactory.

    Verifies that with a real factory, we get a real SnowflakeSSLConnector instance
    with the snowflake_ocsp_mode properly set.
    """
    config = AioHttpConfig(
        connector_factory=SnowflakeSSLConnectorFactory(),
        snowflake_ocsp_mode=OCSPMode.FAIL_CLOSED,
    )

    connector = config.get_connector(session_manager=SessionManager())

    # Verify we get a real SnowflakeSSLConnector instance
    assert isinstance(connector, aiohttp.BaseConnector)
    assert isinstance(connector, SnowflakeSSLConnector)
    # Verify snowflake_ocsp_mode was set correctly
    assert connector._snowflake_ocsp_mode == OCSPMode.FAIL_CLOSED
