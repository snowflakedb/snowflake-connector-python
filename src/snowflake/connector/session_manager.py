from __future__ import annotations

import abc
import collections
import contextlib
import functools
import itertools
import logging
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Any, Callable, Generator, Mapping

from .compat import urlparse
from .proxy import get_proxy_url
from .vendored import requests
from .vendored.requests import Response, Session
from .vendored.requests.adapters import BaseAdapter, HTTPAdapter
from .vendored.requests.exceptions import InvalidProxyURL
from .vendored.requests.utils import prepend_scheme_if_needed, select_proxy
from .vendored.urllib3 import PoolManager, Retry
from .vendored.urllib3.poolmanager import ProxyManager
from .vendored.urllib3.util.url import parse_url

if TYPE_CHECKING:
    from .vendored.urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool


logger = logging.getLogger(__name__)
REQUESTS_RETRY = 1  # requests library builtin retry


def _propagate_session_manager_to_ocsp(generator_func):
    """Decorator: push self into ssl_wrap_socket ContextVar for OCSP duration.

    Designed for methods that are implemented as generator functions.
    It performs a push-pop (``set_current_session_manager`` / ``reset_current_session_manager``)
    around the execution of the generator so that any TLS handshake & OCSP
    validation triggered by the HTTP request can reuse the correct proxy /
    retry configuration.

    Can be removed, when OCSP is deprecated.
    """

    @functools.wraps(generator_func)
    def wrapper(self, *args, **kwargs):
        # Local import avoids a circular dependency at module load time.
        from snowflake.connector.ssl_wrap_socket import (
            reset_current_session_manager,
            set_current_session_manager,
        )

        context_token = set_current_session_manager(self)
        try:
            yield from generator_func(self, *args, **kwargs)
        finally:
            reset_current_session_manager(context_token)

    return wrapper


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
                # Add Host to proxy header SNOW-232777 and SNOW-694457

                # RFC 7230 / 5.4 – a proxy’s Host header must repeat the request authority
                # verbatim: <hostname>[:<port>] with IPv6 still in [brackets].  We take that
                # straight from urlparse(url).netloc, which preserves port and brackets (and case-sensitive hostname).
                # Note: netloc also keeps user-info (user:pass@host) if present in URL. The driver never sends
                # URLs with embedded credentials, so we leave them unhandled — for full support
                # we’d need to manually concatenate hostname with optional port and IPv6 brackets.
                proxy_manager.proxy_headers["Host"] = parsed_url.netloc
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


@dataclass(frozen=True)
class HttpConfig:
    """Immutable HTTP configuration shared by SessionManager instances."""

    adapter_factory: Callable[..., HTTPAdapter] = field(
        default_factory=ProxySupportAdapterFactory
    )
    use_pooling: bool = True
    max_retries: int | Retry | None = REQUESTS_RETRY
    proxy_host: str | None = None
    proxy_port: str | None = None
    proxy_user: str | None = None
    proxy_password: str | None = None

    def copy_with(self, **overrides: Any) -> HttpConfig:
        """Return a new HttpConfig with overrides applied."""
        return replace(self, **overrides)

    def get_adapter(self, **override_adapter_factory_kwargs) -> HTTPAdapter:
        # We pass here only chosen attributes as kwargs to make the arguments received by the factory as compliant with the HttpAdapter constructor interface as possible.
        # We could consider passing the whole HttpConfig as kwarg to the factory if necessary in the future.
        attributes_for_adapter_factory = frozenset(
            {
                "max_retries",
            }
        )

        self_kwargs_for_adapter_factory = {
            attr_name: getattr(self, attr_name)
            for attr_name in attributes_for_adapter_factory
        }
        self_kwargs_for_adapter_factory.update(override_adapter_factory_kwargs)
        return self.adapter_factory(**self_kwargs_for_adapter_factory)


class SessionPool:
    """
    Component responsible for storing and reusing established instances of requests.Session class.

    This approach is especially useful in scenarios where multiple requests would have to be sent
    to the same host in short period of time. Instead of repeatedly establishing a new TCP connection
    for each request, one can get a new Session instance only when there was no connection to the
    current host yet, or the workload is so high that all established sessions are already occupied.

    Sessions are created using the factory method make_session of a passed instance of the
    SessionManager class.
    """

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


class _ConfigDirectAccessMixin(abc.ABC):
    @property
    @abc.abstractmethod
    def config(self) -> HttpConfig: ...

    @config.setter
    @abc.abstractmethod
    def config(self, value) -> HttpConfig: ...

    @property
    def use_pooling(self) -> bool:
        return self.config.use_pooling

    @use_pooling.setter
    def use_pooling(self, value: bool) -> None:
        self.config = self.config.copy_with(use_pooling=value)

    @property
    def adapter_factory(self) -> Callable[..., HTTPAdapter]:
        return self.config.adapter_factory

    @adapter_factory.setter
    def adapter_factory(self, value: Callable[..., HTTPAdapter]) -> None:
        self.config = self.config.copy_with(adapter_factory=value)

    @property
    def max_retries(self) -> Retry | int:
        return self.config.max_retries

    @max_retries.setter
    def max_retries(self, value: Retry | int) -> None:
        self.config = self.config.copy_with(max_retries=value)


class _RequestVerbsUsingSessionMixin(abc.ABC):
    """
    Mixin that provides HTTP methods (get, post, put, etc.) mirroring requests.Session, maintaining their default argument behavior (e.g., HEAD uses allow_redirects=False).
    These wrappers manage the SessionManager's use of pooled/non-pooled sessions and delegate the actual request to the corresponding session.<verb>() method.
    The subclass must implement use_requests_session to yield a *requests.Session* instance.
    """

    @abc.abstractmethod
    def use_requests_session(self, url: str, use_pooling: bool) -> Session: ...

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.get(url, headers=headers, timeout=timeout, **kwargs)

    def options(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.options(url, headers=headers, timeout=timeout, **kwargs)

    def head(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.head(url, headers=headers, timeout=timeout, **kwargs)

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        json=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.post(
                url,
                headers=headers,
                timeout=timeout,
                data=data,
                json=json,
                **kwargs,
            )

    def put(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.put(
                url, headers=headers, timeout=timeout, data=data, **kwargs
            )

    def patch(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        data=None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.patch(
                url, headers=headers, timeout=timeout, data=data, **kwargs
            )

    def delete(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ):
        with self.use_requests_session(url, use_pooling) as session:
            return session.delete(url, headers=headers, timeout=timeout, **kwargs)


class SessionManager(_RequestVerbsUsingSessionMixin, _ConfigDirectAccessMixin):
    """
    Central HTTP session manager that handles all external requests from the Snowflake driver.

    **Purpose**: Replaces scattered HTTP methods (requests.request/post/get, PoolManager().request_encode,
    urllib3.HttpConnection().urlopen) with centralized configuration and optional connection pooling.

    **Two Operating Modes**:
    - use_pooling=False: One-shot sessions (create, use, close) - suitable for infrequent requests
    - use_pooling=True: Per-hostname session pools - reuses TCP connections, avoiding handshake
      and SSL/TLS negotiation overhead for repeated requests to the same host.

    **Key Benefits**:
    - Centralized HTTP configuration management and easy propagation across the codebase
    - Consistent proxy setup (SNOW-694457) and headers customization (SNOW-2043816)
    - HTTPAdapter customization for connection-level request manipulation
    - Performance optimization through connection reuse for high-traffic scenarios.

    **Usage**: Create the base session manager, then use clone() for derived managers to ensure
    proper config propagation. Pre-commit checks enforce usage to prevent code drift back to
    direct HTTP library calls.
    """

    def __init__(self, config: HttpConfig | None = None, **http_config_kwargs) -> None:
        """
        Create a new SessionManager.
        """

        if config is None:
            logger.debug("Creating a config for the SessionManager")
            config = HttpConfig(**http_config_kwargs)
        self._cfg: HttpConfig = config
        self._sessions_map: dict[str | None, SessionPool] = collections.defaultdict(
            lambda: SessionPool(self)
        )

    @classmethod
    def from_config(cls, cfg: HttpConfig, **overrides: Any) -> SessionManager:
        """Build a new manager from *cfg*, optionally overriding fields.

        Example::

            no_pool_cfg = conn._http_config.copy_with(use_pooling=False)
            manager = SessionManager.from_config(no_pool_cfg)
        """

        if overrides:
            cfg = cfg.copy_with(**overrides)
        return cls(config=cfg)

    @property
    def config(self) -> HttpConfig:
        return self._cfg

    @config.setter
    def config(self, cfg: HttpConfig) -> None:
        self._cfg = cfg

    @property
    def proxy_url(self) -> str:
        return get_proxy_url(
            self._cfg.proxy_host,
            self._cfg.proxy_port,
            self._cfg.proxy_user,
            self._cfg.proxy_password,
        )

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
            adapter = self._cfg.get_adapter()
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
        session.proxies = {"http": self.proxy_url, "https": self.proxy_url}
        return session

    @contextlib.contextmanager
    @_propagate_session_manager_to_ocsp
    def use_requests_session(
        self, url: str | bytes | None = None, use_pooling: bool | None = None
    ) -> Generator[Session, Any, None]:
        use_pooling = use_pooling if use_pooling is not None else self.use_pooling
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
        **http_config_overrides,
    ) -> SessionManager:
        """Return a new *stateless* SessionManager sharing this instance’s config.

        "Shallow clone" - the configuration object (HttpConfig) is reused as-is,
        while *stateful* aspects such as the per-host SessionPool mapping are
        reset, so the two managers do not share live `requests.Session`
        objects.
        Optional kwargs (e.g. *use_pooling* / *adapter_factory* / max_retries etc.) - overrides to create a modified
        copy of the HttpConfig before instantiation.
        """
        return SessionManager.from_config(self._cfg, **http_config_overrides)

    def __getstate__(self):
        state = self.__dict__.copy()
        # `_sessions_map` contains a defaultdict with a lambda referencing `self`,
        # which is not pickle-able.  Convert to a regular dict for serialization.
        state["_sessions_map_items"] = list(state.pop("_sessions_map").items())
        return state

    def __setstate__(self, state):
        # Restore attributes except sessions_map
        sessions_items = state.pop("_sessions_map_items", [])
        self.__dict__.update(state)
        self._sessions_map = collections.defaultdict(lambda: SessionPool(self))
        for host, pool in sessions_items:
            self._sessions_map[host] = pool


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
    """
    Convenience wrapper – requires an explicit ``session_manager``.
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
