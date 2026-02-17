from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from aiohttp import ClientRequest, ClientTimeout
from aiohttp.client import _RequestOptions
from aiohttp.client_proto import ResponseHandler
from aiohttp.connector import Connection
from aiohttp.typedefs import StrOrURL

from .. import OperationalError
from ..errorcode import ER_OCSP_RESPONSE_CERT_STATUS_REVOKED
from ..ssl_wrap_socket import FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME
from ..url_util import should_bypass_proxies
from ._ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto

if TYPE_CHECKING:
    from aiohttp.tracing import Trace
    from typing import Unpack
    from aiohttp.client import _RequestContextManager

import abc
import collections
import contextlib
import itertools
import logging
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator, Callable, Mapping

import aiohttp

from ..compat import urlparse
from ..constants import OCSPMode
from ..session_manager import BaseHttpConfig
from ..session_manager import SessionManager as SessionManagerSync
from ..session_manager import SessionPool as SessionPoolSync
from ..session_manager import _BaseConfigDirectAccessMixin

logger = logging.getLogger(__name__)


class SnowflakeSSLConnector(aiohttp.TCPConnector):
    def __init__(
        self,
        *args,
        snowflake_ocsp_mode: OCSPMode = OCSPMode.FAIL_OPEN,
        session_manager: SessionManager | None = None,
        **kwargs,
    ):
        self._snowflake_ocsp_mode = snowflake_ocsp_mode
        if session_manager is None:
            logger.warning(
                "SessionManager instance was not passed to SSLConnector - OCSP will use default settings which may be distinct from the customer's specific one. Code should always pass such instance - verify why it isn't true in the current context"
            )
            session_manager = SessionManagerFactory.get_manager()
        self._session_manager = session_manager
        if self._snowflake_ocsp_mode == OCSPMode.FAIL_OPEN and sys.version_info < (
            3,
            10,
        ):
            raise RuntimeError(
                "Async Snowflake Python Connector requires Python 3.10+ for OCSP validation related features. "
                "Please open a feature request issue in github if your want to use Python 3.9 or lower: "
                "https://github.com/snowflakedb/snowflake-connector-python/issues/new/choose."
            )

        super().__init__(*args, **kwargs)

    async def connect(
        self, req: ClientRequest, traces: list[Trace], timeout: ClientTimeout
    ) -> Connection:
        connection = await super().connect(req, traces, timeout)
        protocol = connection.protocol
        if (
            req.is_ssl()
            and protocol is not None
            and not getattr(protocol, "_snowflake_ocsp_validated", False)
        ):
            if self._snowflake_ocsp_mode == OCSPMode.DISABLE_OCSP_CHECKS:
                logger.debug(
                    "This connection does not perform OCSP checks. "
                    "Revocation status of the certificate will not be checked against OCSP Responder."
                )
            else:
                await self.validate_ocsp(
                    req.url.host,
                    protocol,
                    session_manager=self._session_manager.clone(use_pooling=False),
                )
                protocol._snowflake_ocsp_validated = True
        return connection

    async def validate_ocsp(
        self,
        hostname: str,
        protocol: ResponseHandler,
        *,
        session_manager: SessionManager,
    ):

        v = await SnowflakeOCSPAsn1Crypto(
            ocsp_response_cache_uri=FEATURE_OCSP_RESPONSE_CACHE_FILE_NAME,
            use_fail_open=self._snowflake_ocsp_mode == OCSPMode.FAIL_OPEN,
            hostname=hostname,
            # TODO (SNOW-2871292): uncomment when issues with ocsp revoked certs in tests are fixed (reapply #2559)
            # root_certs_dict_lock_timeout=FEATURE_ROOT_CERTS_DICT_LOCK_TIMEOUT,
        ).validate(hostname, protocol, session_manager=session_manager)
        if not v:
            raise OperationalError(
                msg=(
                    "The certificate is revoked or "
                    "could not be validated: hostname={}".format(hostname)
                ),
                errno=ER_OCSP_RESPONSE_CERT_STATUS_REVOKED,
            )


class ConnectorFactory(abc.ABC):
    @abc.abstractmethod
    def __call__(self, *args, **kwargs) -> aiohttp.BaseConnector:
        raise NotImplementedError()


class SnowflakeSSLConnectorFactory(ConnectorFactory):
    def __call__(
        self,
        *args,
        session_manager: SessionManager,
        **kwargs,
    ) -> SnowflakeSSLConnector:
        return SnowflakeSSLConnector(*args, session_manager=session_manager, **kwargs)


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

    def get_connector(
        self, **override_connector_factory_kwargs
    ) -> aiohttp.BaseConnector:
        # We pass here only chosen attributes as kwargs to make the arguments received by the factory as compliant with the BaseConnector constructor interface as possible.
        # We could consider passing the whole HttpConfig as kwarg to the factory if necessary in the future.
        attributes_for_connector_factory = frozenset({"snowflake_ocsp_mode"})

        self_kwargs_for_connector_factory = {
            attr_name: getattr(self, attr_name)
            for attr_name in attributes_for_connector_factory
        }
        self_kwargs_for_connector_factory.update(override_connector_factory_kwargs)
        return self.connector_factory(**self_kwargs_for_connector_factory)


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
    The subclass must implement use_session to yield an *aiohttp.ClientSession* instance.
    """

    @abc.abstractmethod
    async def use_session(
        self, url: str | bytes, use_pooling: bool
    ) -> AsyncGenerator[aiohttp.ClientSession]: ...

    async def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: int | tuple[int, int] | None = 3,
        use_pooling: bool | None = None,
        **kwargs,
    ) -> aiohttp.ClientResponse:
        if isinstance(timeout, tuple):
            connect, total = timeout
            timeout_obj = aiohttp.ClientTimeout(total=total, connect=connect)
        else:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None

        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
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
        async with self.use_session(url, use_pooling) as session:
            timeout_obj = aiohttp.ClientTimeout(total=timeout) if timeout else None
            return await session.delete(
                url, headers=headers, timeout=timeout_obj, **kwargs
            )


class _AsyncHttpConfigDirectAccessMixin(_BaseConfigDirectAccessMixin, abc.ABC):
    @property
    @abc.abstractmethod
    def config(self) -> AioHttpConfig: ...

    @config.setter
    @abc.abstractmethod
    def config(self, value) -> AioHttpConfig: ...

    @property
    def connector_factory(self) -> Callable[..., aiohttp.BaseConnector]:
        return self.config.connector_factory

    @connector_factory.setter
    def connector_factory(self, value: Callable[..., aiohttp.BaseConnector]) -> None:
        self.config: AioHttpConfig = self.config.copy_with(connector_factory=value)


class SessionManager(
    _RequestVerbsUsingSessionMixin,
    SessionManagerSync,
    _AsyncHttpConfigDirectAccessMixin,
):
    """
    Async HTTP session manager for aiohttp.ClientSession instances.

    Inherits infrastructure from sync SessionManager, overrides async-specific methods.
    """

    def __init__(
        self,
        config: AioHttpConfig | None = None,
        **http_config_kwargs,
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

    @classmethod
    def from_config(cls, cfg: AioHttpConfig, **overrides: Any) -> SessionManager:
        """Build a new manager from *cfg*, optionally overriding fields.

        Example::

            no_pool_cfg = conn._http_config.copy_with(use_pooling=False)
            manager = SessionManager.from_config(no_pool_cfg)
        """

        if overrides:
            cfg = cfg.copy_with(**overrides)
        return cls(config=cfg)

    def make_session(self, *, url: str | None = None) -> aiohttp.ClientSession:
        """Create a new aiohttp.ClientSession with configured connector."""
        connector = self._cfg.get_connector(
            session_manager=self.clone(),
            snowflake_ocsp_mode=self._cfg.snowflake_ocsp_mode,
        )
        return aiohttp.ClientSession(
            connector=connector,
            trust_env=self._cfg.trust_env,
            proxy=self.proxy_url,
        )

    @contextlib.asynccontextmanager
    async def use_session(
        self, url: str | bytes, use_pooling: bool | None = None
    ) -> AsyncGenerator[aiohttp.ClientSession]:
        """
        'url' is an obligatory parameter due to the need for correct proxy handling (i.e. bypassing caused by no_proxy settings).
        """
        use_pooling = use_pooling if use_pooling is not None else self.use_pooling
        if not use_pooling:
            session = self.make_session(url=url)
            try:
                yield session
            finally:
                await session.close()
        else:
            for session_from_pool in self._yield_session_from_pool(url):
                yield session_from_pool

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
        async with self.use_session(url, use_pooling) as session:
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
        return self.from_config(self._cfg, **http_config_overrides)


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


class ProxySessionManager(SessionManager):
    class SessionWithProxy(aiohttp.ClientSession):
        if sys.version_info >= (3, 11) and TYPE_CHECKING:

            def request(
                self,
                method: str,
                url: StrOrURL,
                **kwargs: Unpack[_RequestOptions],
            ) -> _RequestContextManager: ...

        else:

            def request(
                self, method: str, url: StrOrURL, **kwargs: Any
            ) -> _RequestContextManager:
                """Perform HTTP request."""
                # Inject Host header when proxying
                try:
                    # respect caller-provided proxy and proxy_headers if any
                    provided_proxy = kwargs.get("proxy") or self._default_proxy
                    provided_proxy_headers = kwargs.get("proxy_headers")
                    if provided_proxy is not None:
                        authority = urlparse(str(url)).netloc
                        if provided_proxy_headers is None:
                            kwargs["proxy_headers"] = {"Host": authority}
                        elif "Host" not in provided_proxy_headers:
                            provided_proxy_headers["Host"] = authority
                        else:
                            logger.debug(
                                "Host header was already set - not overriding with netloc at the ClientSession.request method level."
                            )
                except Exception:
                    logger.warning(
                        "Failed to compute proxy settings for %s",
                        urlparse(url).hostname,
                        exc_info=True,
                    )
                return super().request(method, url, **kwargs)

    def make_session(self, *, url: str | None = None) -> aiohttp.ClientSession:
        connector = self._cfg.get_connector(
            session_manager=self.clone(),
            snowflake_ocsp_mode=self._cfg.snowflake_ocsp_mode,
        )

        proxy_from_conn_params: str | None = None
        if not aiohttp.helpers.proxies_from_env():
            # TODO: This is only needed because we want to keep compatibility with the synch driver version.
            #   Otherwise, we could remove that condition and always pass proxy from conn params to the Session constructor.
            #   But in such case precedence will be reverted and it will overwrite the env vars settings.

            # We use requests.utils here (in asynch code) to keep the behaviour uniform for synch and asynch code. If we wanted each version to depict its http library's behaviour, we could use here: aiohttp.helpers.proxy_bypass(url, proxies={...}) here
            proxy_from_conn_params = (
                None
                if should_bypass_proxies(url, no_proxy=self.config.no_proxy)
                else self.proxy_url
            )
        # Construct session with base proxy set, request() may override per-URL when bypassing
        return self.SessionWithProxy(
            connector=connector,
            trust_env=self._cfg.trust_env,
            proxy=proxy_from_conn_params,
        )


class SessionManagerFactory:
    @staticmethod
    def get_manager(
        config: AioHttpConfig | None = None, **http_config_kwargs
    ) -> SessionManager:
        """Return a proxy-aware or plain async SessionManager based on config.

        If any explicit proxy parameters are provided (in config or kwargs),
        return ProxySessionManager; otherwise return the base SessionManager.
        """

        def _has_proxy_params(cfg: AioHttpConfig | None, kwargs: dict) -> bool:
            cfg_keys = (
                "proxy_host",
                "proxy_port",
            )
            in_cfg = any(getattr(cfg, k, None) for k in cfg_keys) if cfg else False
            in_kwargs = "proxy" in kwargs
            return in_cfg or in_kwargs

        if _has_proxy_params(config, http_config_kwargs):
            return ProxySessionManager(config, **http_config_kwargs)
        else:
            return SessionManager(config, **http_config_kwargs)
