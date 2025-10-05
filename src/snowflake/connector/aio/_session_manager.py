from __future__ import annotations

import abc
import collections
import contextlib
import itertools
import logging
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, AsyncGenerator, Callable, Mapping

import aiohttp

from ..compat import urlparse
from ..constants import OCSPMode
from ..session_manager import BaseHttpConfig
from ..session_manager import SessionManager as SessionManagerSync
from ..session_manager import SessionPool as SessionPoolSync
from ._ssl_connector import SnowflakeSSLConnector

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)
REQUESTS_RETRY = 1  # requests library builtin retry


class ConnectorFactory(abc.ABC):
    @abc.abstractmethod
    def __call__(self, *args, **kwargs) -> aiohttp.BaseConnector:
        raise NotImplementedError()


class SnowflakeSSLConnectorFactory(ConnectorFactory):
    def __call__(self, *args, **kwargs) -> SnowflakeSSLConnector:
        return SnowflakeSSLConnector(*args, **kwargs)


@dataclass(frozen=True)
class AioHttpConfig(BaseHttpConfig):
    """HTTP configuration specific to aiohttp library.

    This configuration is created at the SnowflakeConnection level and passed down
    to SessionManager and SnowflakeRestful to ensure consistent HTTP behavior.
    """

    connector_factory: Callable[..., aiohttp.BaseConnector] = field(
        default_factory=SnowflakeSSLConnectorFactory
    )

    trust_env: bool = True
    """Trust environment variables for proxy configuration (HTTP_PROXY, HTTPS_PROXY, NO_PROXY).
    Required for proxy support set by proxy.set_proxies() in connection initialization."""

    snowflake_ocsp_mode: OCSPMode = OCSPMode.FAIL_OPEN
    """OCSP validation mode obtained from connection._ocsp_mode()."""

    def copy_with(self, **overrides: Any) -> AioHttpConfig:
        """Return a new AioHttpConfig with overrides applied."""
        return replace(self, **overrides)


class SessionPool(SessionPoolSync[aiohttp.ClientSession]):
    """Async SessionPool for aiohttp.ClientSession instances.

    Inherits all session management logic from generic SessionPool,
    specialized for aiohttp.ClientSession type.
    """

    def __init__(self, manager: SessionManager) -> None:
        super().__init__(manager)

    async def close(self) -> None:
        """Closes all active and idle sessions in this session pool."""
        if self._active_sessions:
            logger.debug(f"Closing {len(self._active_sessions)} active sessions")
        for session in itertools.chain(self._active_sessions, self._idle_sessions):
            try:
                await session.close()
            except Exception as e:
                logger.info(f"Session cleanup failed - failed to close session: {e}")
        self._active_sessions.clear()
        self._idle_sessions.clear()

    def __getstate__(self):
        """Prepare SessionPool for pickling.

        aiohttp.ClientSession objects cannot be pickled, so we discard them
        and preserve only the manager reference. Pools will be recreated empty.
        """
        return {
            "_manager": self._manager,
            "_idle_sessions": [],  # Discard unpicklable aiohttp sessions
            "_active_sessions": set(),
        }

    def __setstate__(self, state):
        """Restore SessionPool from pickle."""
        self.__dict__.update(state)


class _RequestVerbsUsingSessionMixin(abc.ABC):
    """
    Mixin that provides HTTP methods (get, post, put, etc.) mirroring aiohttp.ClientSession, maintaining their default argument behavior.
    These wrappers manage the SessionManager's use of pooled/non-pooled sessions and delegate the actual request to the corresponding session.<verb>() method.
    The subclass must implement use_requests_session to yield an *aiohttp.ClientSession* instance.
    """

    @abc.abstractmethod
    async def use_requests_session(
        self, url: str, use_pooling: bool
    ) -> AsyncGenerator[aiohttp.ClientSession]: ...

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.get(
                url, headers=headers, timeout=timeout_obj, **kwargs
            )

    async def options(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.options(
                url, headers=headers, timeout=timeout_obj, **kwargs
            )

    async def head(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.head(
                url, headers=headers, timeout=timeout_obj, **kwargs
            )

    async def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        json=None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.post(
                url,
                headers=headers,
                timeout=timeout_obj,
                data=data,
                json=json,
                **kwargs,
            )

    async def put(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.put(
                url, headers=headers, timeout=timeout_obj, data=data, **kwargs
            )

    async def patch(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.patch(
                url, headers=headers, timeout=timeout_obj, data=data, **kwargs
            )

    async def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.delete(
                url, headers=headers, timeout=timeout_obj, **kwargs
            )


class SessionManager(_RequestVerbsUsingSessionMixin, SessionManagerSync):
    """
    Async HTTP session manager for aiohttp.ClientSession instances.

    Inherits infrastructure from sync SessionManager, overrides async-specific methods.
    """

    def __init__(
        self, config: AioHttpConfig | None = None, **http_config_kwargs
    ) -> None:
        """Create a new async SessionManager."""
        if config is None:
            logger.debug("Creating a config for the async SessionManager")
            config = AioHttpConfig(**http_config_kwargs)

        # Don't call super().__init__ to avoid creating sync SessionPool
        self._cfg: AioHttpConfig = config
        self._sessions_map: dict[str | None, SessionPool] = collections.defaultdict(
            lambda: SessionPool(self)
        )

    @property
    def connector_factory(self) -> Callable[..., aiohttp.BaseConnector]:
        return self._cfg.connector_factory

    @connector_factory.setter
    def connector_factory(self, value: Callable[..., aiohttp.BaseConnector]) -> None:
        self._cfg = self._cfg.copy_with(connector_factory=value)

    def make_session(self) -> aiohttp.ClientSession:
        """Create a new aiohttp.ClientSession with configured connector."""
        connector = self._cfg.connector_factory(
            snowflake_ocsp_mode=self._cfg.snowflake_ocsp_mode,
        )

        return aiohttp.ClientSession(
            connector=connector,
            trust_env=self._cfg.trust_env,
        )

    @contextlib.asynccontextmanager
    async def use_requests_session(
        self, url: str | bytes | None = None, use_pooling: bool | None = None
    ) -> AsyncGenerator[aiohttp.ClientSession]:
        """Async version of use_requests_session yielding aiohttp.ClientSession."""
        use_pooling = use_pooling if use_pooling is not None else self.use_pooling
        if not use_pooling:
            session = self.make_session()
            try:
                yield session
            finally:
                await session.close()
        else:
            hostname = urlparse(url).hostname if url else None
            pool = self._sessions_map[hostname]
            session = pool.get_session()
            try:
                yield session
            finally:
                pool.return_session(session)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs: Any,
    ) -> aiohttp.ClientResponse:
        """Make a single HTTP request handled by this SessionManager."""
        async with self.use_requests_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=timeout_obj,
                **kwargs,
            )

    async def close(self):
        """Close all session pools asynchronously."""
        for pool in self._sessions_map.values():
            await pool.close()

    def clone(
        self,
        *,
        use_pooling: bool | None = None,
        connector_factory: ConnectorFactory | None = None,
    ) -> SessionManager:
        """Return a new async SessionManager sharing this instance's config."""
        overrides: dict[str, Any] = {}
        if use_pooling is not None:
            overrides["use_pooling"] = use_pooling
        if connector_factory is not None:
            overrides["connector_factory"] = connector_factory

        return SessionManager.from_config(self._cfg, **overrides)


async def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int | None = 3,
    session_manager: SessionManager | None = None,
    use_pooling: bool | None = None,
    **kwargs: Any,
) -> aiohttp.ClientResponse:
    """
    Convenience wrapper – requires an explicit ``session_manager``.
    """
    if session_manager is None:
        raise ValueError(
            "session_manager is required - no default session manager available"
        )

    return await session_manager.request(
        method=method,
        url=url,
        headers=headers,
        timeout=timeout,
        use_pooling=use_pooling,
        **kwargs,
    )
