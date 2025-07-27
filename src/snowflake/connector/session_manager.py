from __future__ import annotations

import abc
import collections
import contextlib
import itertools
import logging
from typing import TYPE_CHECKING, Any, Callable, Generator, Mapping

from .compat import urlparse
from .vendored import requests
from .vendored.requests import Response, Session
from .vendored.requests.adapters import BaseAdapter, HTTPAdapter
from .vendored.requests.exceptions import InvalidProxyURL
from .vendored.requests.utils import prepend_scheme_if_needed, select_proxy
from .vendored.urllib3 import PoolManager
from .vendored.urllib3.poolmanager import ProxyManager
from .vendored.urllib3.util.url import parse_url

if TYPE_CHECKING:
    from .vendored.urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

logger = logging.getLogger(__name__)

# requests parameters
REQUESTS_RETRY = 1  # requests library builtin retry


class ProxySupportAdapter(HTTPAdapter):
    """This Adapter creates proper headers for Proxy CONNECT messages."""

    def get_connection(
        self, url: str, proxies: dict | None = None
    ) -> HTTPConnectionPool | HTTPSConnectionPool:
        proxy = select_proxy(url, proxies)
        parsed_url = urlparse(url)

        if proxy:
            proxy = prepend_scheme_if_needed(proxy, "http")
            proxy_url = parse_url(proxy)
            if not proxy_url.host:
                raise InvalidProxyURL(
                    "Please check proxy URL. It is malformed"
                    " and could be missing the host."
                )
            proxy_manager = self.proxy_manager_for(proxy)

            if isinstance(proxy_manager, ProxyManager):
                # Add Host to proxy header SNOW-232777
                proxy_manager.proxy_headers["Host"] = parsed_url.hostname
            else:
                logger.debug(
                    f"Unable to set 'Host' to proxy manager of type {type(proxy_manager)} as"
                    f" it does not have attribute 'proxy_headers'."
                )
            conn = proxy_manager.connection_from_url(url)
        else:
            # Only scheme should be lower case
            url = parsed_url.geturl()
            conn = self.poolmanager.connection_from_url(url)

        return conn


class AdapterFactory(abc.ABC):
    @abc.abstractmethod
    def __call__(self, *args, **kwargs) -> BaseAdapter:
        raise NotImplementedError()


class ProxySupportAdapterFactory(AdapterFactory):
    def __call__(self, *args, **kwargs) -> ProxySupportAdapter:
        return ProxySupportAdapter(*args, **kwargs)


class SessionPool:
    def __init__(self, manager: SessionManager) -> None:
        # A stack of the idle sessions
        self._idle_sessions = []
        self._active_sessions = set()
        self._manager = manager

    def get_session(self) -> Session:
        """Returns a session from the session pool or creates a new one."""
        try:
            session = self._idle_sessions.pop()
        except IndexError:
            session = self._manager.make_session()
        self._active_sessions.add(session)
        return session

    def return_session(self, session: Session) -> None:
        """Places an active session back into the idle session stack."""
        try:
            self._active_sessions.remove(session)
        except KeyError:
            logger.debug("session doesn't exist in the active session pool. Ignored...")
        self._idle_sessions.append(session)

    def __str__(self) -> str:
        total_sessions = len(self._active_sessions) + len(self._idle_sessions)
        return (
            f"SessionPool {len(self._active_sessions)}/{total_sessions} active sessions"
        )

    def close(self) -> None:
        """Closes all active and idle sessions in this session pool."""
        if self._active_sessions:
            logger.debug(f"Closing {len(self._active_sessions)} active sessions")
        for session in itertools.chain(self._active_sessions, self._idle_sessions):
            try:
                session.close()
            except Exception as e:
                logger.info(f"Session cleanup failed - failed to close session: {e}")
        self._active_sessions.clear()
        self._idle_sessions.clear()


class _RequestVerbsUsingSessionMixin:
    """
    Mixin that provides HTTP methods (get, post, put, etc.) mirroring requests.Session, maintaining their default argument behavior (e.g., HEAD uses allow_redirects=False).
    These wrappers manage the SessionManager's use of pooled/non-pooled sessions and delegate the actual request to the corresponding session.<verb>() method.
    The subclass must implement use_requests_session to yield a *requests.Session* instance.
    """

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.get(url, headers=headers, timeout=timeout_sec, **kwargs)

    def options(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.options(url, headers=headers, timeout=timeout_sec, **kwargs)

    def head(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.head(url, headers=headers, timeout=timeout_sec, **kwargs)

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        json=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.post(
                url,
                headers=headers,
                timeout=timeout_sec,
                data=data,
                json=json,
                **kwargs,
            )

    def put(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.put(
                url, headers=headers, timeout=timeout_sec, data=data, **kwargs
            )

    def patch(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.patch(
                url, headers=headers, timeout=timeout_sec, data=data, **kwargs
            )

    def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout_sec: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.delete(url, headers=headers, timeout=timeout_sec, **kwargs)


class SessionManager(_RequestVerbsUsingSessionMixin):
    def __init__(
        self,
        use_pooling: bool = True,
        adapter_factory: Callable[..., HTTPAdapter] | None = None,
    ):
        self._use_pooling = use_pooling
        self._adapter_factory = adapter_factory or ProxySupportAdapterFactory()
        self._sessions_map: dict[str | None, SessionPool] = collections.defaultdict(
            lambda: SessionPool(self)
        )

    @property
    def use_pooling(self) -> bool:
        return self._use_pooling

    @use_pooling.setter
    def use_pooling(self, value: bool) -> None:
        self._use_pooling = value

    @property
    def adapter_factory(self) -> AdapterFactory:
        return self._adapter_factory

    @adapter_factory.setter
    def adapter_factory(self, value: AdapterFactory) -> None:
        self._adapter_factory = value

    @property
    def sessions_map(self) -> dict[str, SessionPool]:
        return self._sessions_map

    @staticmethod
    def get_session_pool_manager(session: Session, url: str) -> PoolManager | None:
        adapter_for_url: HTTPAdapter = session.get_adapter(url)
        try:
            return adapter_for_url.poolmanager
        except AttributeError as no_pool_manager_error:
            error_message = f"Unable to get pool manager from session for {url}: {no_pool_manager_error}"
            logger.error(error_message)
            if not isinstance(adapter_for_url, HTTPAdapter):
                logger.warning(
                    f"Adapter was expected to be an HTTPAdapter, got {adapter_for_url.__class__.__name__}"
                )
            else:
                logger.debug(
                    "Adapter was expected an HTTPAdapter but didn't have attribute 'poolmanager'. This is unexpected behavior."
                )
            raise ValueError(error_message)

    def _mount_adapters(self, session: requests.Session) -> None:
        try:
            # Its important that each separate session manager creates its own adapters - because they are storing internally PoolManagers - which shouldn't be reused if not in scope of the same adapter.
            adapter = self._adapter_factory(max_retries=REQUESTS_RETRY)
            if adapter is not None:
                session.mount("http://", adapter)
                session.mount("https://", adapter)
        except (TypeError, AttributeError) as no_adapter_factory_exception:
            logger.info(
                "No adapter factory found. Using session without adapter. Exception: %s",
                no_adapter_factory_exception,
            )
            return

    def make_session(self) -> Session:
        session = requests.Session()
        self._mount_adapters(session)
        return session

    @contextlib.contextmanager
    def use_requests_session(
        self, url: str | bytes | None = None, use_pooling: bool | None = None
    ) -> Generator[Session, Any, None]:
        use_pooling = use_pooling if use_pooling is not None else self._use_pooling
        if not use_pooling:
            session = self.make_session()
            try:
                yield session
            finally:
                session.close()
        else:
            hostname = urlparse(url).hostname if url else None
            pool = self._sessions_map[hostname]
            session = pool.get_session()
            try:
                yield session
            finally:
                pool.return_session(session)

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs: Any,
    ) -> Response:
        """Make a single HTTP request handled by this *SessionManager*.

        This wraps :pymeth:`use_session` so callers don’t have to manage the
        context manager themselves.
        """
        with self.use_requests_session(url, use_pooling) as session:
            return session.request(
                method=method.upper(),
                url=url,
                headers=headers,
                timeout=timeout,
                **kwargs,
            )

    def close(self):
        for pool in self._sessions_map.values():
            pool.close()

    def clone(
        self,
        *,
        use_pooling: bool | None = None,
        adapter_factory: AdapterFactory | None = None,
    ) -> SessionManager:
        """Return an independent manager that reuses the adapter_factory.
        The 'clone' and the 'original' do not share the sessions map, but by default share the same settings and adapter_factory.
        Those can be overridden using the method's arguments.
        """
        return SessionManager(
            use_pooling=self._use_pooling if use_pooling is None else use_pooling,
            adapter_factory=(
                self._adapter_factory if adapter_factory is None else adapter_factory
            ),
        )


def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int | None = 3,
    session_manager: SessionManager | None = None,
    use_pooling: bool | None = None,
    **kwargs: Any,
) -> Response:
    """Convenience wrapper – *requires* an explicit ``session_manager``.

    This keeps a one-liner API equivalent to the old
    ``snowflake.connector.http_client.request`` helper.
    """
    if session_manager is None:
        raise ValueError(
            "session_manager is required - no default session manager available"
        )

    return session_manager.request(
        method=method,
        url=url,
        headers=headers,
        timeout=timeout,
        use_pooling=use_pooling,
        **kwargs,
    )
