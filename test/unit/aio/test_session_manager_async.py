#!/usr/bin/env python
from __future__ import annotations

from unittest import mock

import pytest

from snowflake.connector.aio._session_manager import (
    AioHttpConfig,
    SessionManager,
    SnowflakeSSLConnectorFactory,
)
from snowflake.connector.constants import OCSPMode

HOST_SFC_TEST_0 = "sfctest0.snowflakecomputing.com"
URL_SFC_TEST_0 = f"https://{HOST_SFC_TEST_0}:443/session/v1/login-request"

HOST_SFC_S3_STAGE = "sfc-ds2-customer-stage.s3.amazonaws.com"
URL_SFC_S3_STAGE_1 = f"https://{HOST_SFC_S3_STAGE}/rgm1-s-sfctest0/stages/"
URL_SFC_S3_STAGE_2 = f"https://{HOST_SFC_S3_STAGE}/rgm1-s-sfctst0/stages/another-url"


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


@pytest.mark.asyncio
@mock.patch(
    "snowflake.connector.aio._session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_pooling_disabled(make_session_mock):
    """When pooling is disabled every request creates and closes a new Session."""
    manager = SessionManager(use_pooling=False)

    await create_session(manager, url=URL_SFC_TEST_0)
    await create_session(manager, url=URL_SFC_TEST_0)

    # Two independent sessions were created
    assert make_session_mock.call_count == 2
    # Pooling disabled => no session pools maintained
    assert manager.sessions_map == {}

    await close_and_assert(manager, expected_pool_count=0)


@pytest.mark.asyncio
@mock.patch(
    "snowflake.connector.aio._session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_single_hostname_pooling(make_session_mock):
    """A single hostname should result in exactly one underlying Session."""
    manager = SessionManager()  # pooling enabled by default

    # Create 5 sequential sessions for the same hostname
    for _ in range(5):
        await create_session(manager, url=URL_SFC_TEST_0)

    # Only one underlying Session should have been created
    assert make_session_mock.call_count == 1

    assert list(manager.sessions_map.keys()) == [HOST_SFC_TEST_0]
    pool = manager.sessions_map[HOST_SFC_TEST_0]
    assert len(pool._idle_sessions) == 1
    assert len(pool._active_sessions) == 0

    await close_and_assert(manager, expected_pool_count=1)


@pytest.mark.asyncio
@mock.patch(
    "snowflake.connector.aio._session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_multiple_hostnames_separate_pools(make_session_mock):
    """Different hostnames (and None) should create separate pools."""
    manager = SessionManager()

    for url in [URL_SFC_TEST_0, URL_SFC_S3_STAGE_1, None]:
        await create_session(manager, num_sessions=2, url=url)

    # Two sessions created for each of the three keys (HOST_SFC_TEST_0, HOST_SFC_S3_STAGE, None)
    assert make_session_mock.call_count == 6

    for expected_host in [HOST_SFC_TEST_0, HOST_SFC_S3_STAGE, None]:
        assert expected_host in manager.sessions_map

    for pool in manager.sessions_map.values():
        assert len(pool._idle_sessions) == 2
        assert len(pool._active_sessions) == 0

    await close_and_assert(manager, expected_pool_count=3)


@pytest.mark.asyncio
@mock.patch(
    "snowflake.connector.aio._session_manager.SessionManager.make_session",
    side_effect=ORIGINAL_MAKE_SESSION,
    autospec=True,
)
async def test_reuse_sessions_within_pool(make_session_mock):
    """After many sequential sessions only one Session per hostname should exist."""
    manager = SessionManager()

    for url in [URL_SFC_TEST_0, URL_SFC_S3_STAGE_1, URL_SFC_S3_STAGE_2, None]:
        for _ in range(10):
            await create_session(manager, url=url)

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

    await close_and_assert(manager, expected_pool_count=3)


@pytest.mark.asyncio
async def test_clone_independence():
    """`clone` should return an independent manager sharing only the connector_factory."""
    manager = SessionManager()
    async with manager.use_session(URL_SFC_TEST_0):
        pass
    assert HOST_SFC_TEST_0 in manager.sessions_map

    clone = manager.clone()

    assert clone is not manager
    assert clone.connector_factory is manager.connector_factory
    assert clone.sessions_map == {}

    async with clone.use_session(URL_SFC_S3_STAGE_1):
        pass

    assert HOST_SFC_S3_STAGE in clone.sessions_map
    assert HOST_SFC_S3_STAGE not in manager.sessions_map

    await manager.close()
    await clone.close()


@pytest.mark.asyncio
async def test_connector_factory_creates_sessions():
    """Verify that connector factory creates aiohttp sessions with proper connector."""
    manager = SessionManager()

    session = manager.make_session()
    assert session is not None
    # Verify it's an aiohttp.ClientSession
    assert hasattr(session, "connector")
    assert session.connector is not None

    await session.close()


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_session_pool_lifecycle():
    """Test that session pool properly manages session lifecycle."""
    manager = SessionManager(use_pooling=True)

    # Get a session - should create new one
    async with manager.use_session(URL_SFC_TEST_0):
        assert HOST_SFC_TEST_0 in manager.sessions_map
        pool = manager.sessions_map[HOST_SFC_TEST_0]
        assert len(pool._active_sessions) == 1
        assert len(pool._idle_sessions) == 0

    # After context exit, session should be idle
    assert len(pool._active_sessions) == 0
    assert len(pool._idle_sessions) == 1

    # Reuse the same session
    async with manager.use_session(URL_SFC_TEST_0):
        assert len(pool._active_sessions) == 1
        assert len(pool._idle_sessions) == 0

    await manager.close()


@pytest.mark.asyncio
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


@pytest.mark.asyncio
async def test_pickle_session_manager():
    """Test that SessionManager can be pickled and unpickled."""
    import pickle

    config = AioHttpConfig(
        use_pooling=True,
        trust_env=False,
    )
    manager = SessionManager(config)

    # Create some sessions
    async with manager.use_session(URL_SFC_TEST_0):
        pass

    # Pickle and unpickle (sessions are discarded during pickle)
    pickled = pickle.dumps(manager)
    unpickled = pickle.loads(pickled)

    assert unpickled is not manager
    assert unpickled.config.trust_env is False
    assert unpickled.use_pooling is True
    # Pool structure preserved but sessions are empty after unpickling
    assert HOST_SFC_TEST_0 in unpickled.sessions_map
    pool = unpickled.sessions_map[HOST_SFC_TEST_0]
    assert len(pool._idle_sessions) == 0
    assert len(pool._active_sessions) == 0

    await manager.close()
    await unpickled.close()
