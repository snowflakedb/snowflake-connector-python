from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from functools import partial, wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Generator,
    Iterable,
    MutableSequence,
    NamedTuple,
)

if TYPE_CHECKING:
    from . import SnowflakeConnection
# from contextlib import contextmanager

from .vendored import requests, urllib3

METHODS = {
    "GET",
    "PUT",
    "POST",
    "HEAD",
    "DELETE",
}

Headers = dict[str, Any]

logger = logging.getLogger(__name__)


class RequestDTO(NamedTuple):
    url: str | bytes
    method: str
    headers: Headers
    # TODO: can be added if custom logic injection wanted - but should be enriched with checks if it doesnt overwrite other args
    # kwargs: dict = {}


class ConflictDTO(NamedTuple):
    original_key: str
    value: Any
    had_conflict: bool = True


class HeadersCustomizer(ABC):
    @abstractmethod
    def applies_to(self, request: RequestDTO):
        raise NotImplementedError()

    @abstractmethod
    def is_invoked_once(self):
        """recommended to increase performance"""
        raise NotImplementedError()

    @abstractmethod
    def get_new_headers(self, request: RequestDTO) -> Headers:
        raise NotImplementedError()


class HttpInterceptor(ABC):
    class InterceptionHook(Enum):
        BEFORE_EACH_RETRY = auto()
        ONCE_BEFORE_REQUEST = auto()

    @abstractmethod
    def intercept_on(
        self, hook: HttpInterceptor.InterceptionHook, request: RequestDTO
    ) -> RequestDTO:
        raise NotImplementedError()


class HeadersCustomizerInterceptor(HttpInterceptor):
    def __init__(
        self,
        headers_customizers: Iterable[HeadersCustomizer] | None = None,
        static_headers_customizers: Iterable[HeadersCustomizer] | None = None,
        dynamic_headers_customizers: Iterable[HeadersCustomizer] | None = None,
    ):
        if headers_customizers is not None:
            self._static_headers_customizers, self._dynamic_headers_customizers = (
                self.split_customizers(headers_customizers)
            )
        else:
            self._static_headers_customizers = static_headers_customizers or []
            self._dynamic_headers_customizers = dynamic_headers_customizers or []

    @staticmethod
    def split_customizers(
        headers_customizers: Iterable[HeadersCustomizer] | None,
    ) -> tuple[MutableSequence[HeadersCustomizer], MutableSequence[HeadersCustomizer]]:
        static, dynamic = [], []
        if headers_customizers:
            for customizer in headers_customizers:
                if customizer.is_invoked_once():
                    static.append(customizer)
                else:
                    dynamic.append(customizer)
        return static, dynamic

    @staticmethod
    def iter_non_conflicting_headers(
        original_headers: Headers, other_headers: Headers, case_sensitive: bool = False
    ) -> Generator[ConflictDTO]:
        """
        Yields (key, value, is_conflicting) for each key in other_headers,
        telling you if it conflicts with original_headers.
        """
        original_keys = (
            set(original_headers)
            if case_sensitive
            else {k.lower() for k in original_headers}
        )

        for key, value in other_headers.items():
            comp_key = key if case_sensitive else key.lower()
            if comp_key in original_keys:
                yield ConflictDTO(key, value, True)
            else:
                yield ConflictDTO(key, value, False)

    def intercept_on(
        self, hook: HttpInterceptor.InterceptionHook, request: RequestDTO
    ) -> RequestDTO:
        if hook is HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY:
            return self._handle_headers_customization(
                request, self._dynamic_headers_customizers
            )
        elif hook is HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST:
            return self._handle_headers_customization(
                request, self._static_headers_customizers
            )
        return request

    # updates in place headers dict
    def _handle_headers_customization(
        self, request: RequestDTO, headers_customizers: Iterable[HeadersCustomizer]
    ) -> RequestDTO:
        # copy preventing mutation in the registered customizer
        result_headers = dict(request.headers)

        for header_customizer in headers_customizers:
            try:
                if header_customizer.applies_to(request):
                    additional_headers = header_customizer.get_new_headers(request)

                    for key, value, is_conflicting in self.iter_non_conflicting_headers(
                        result_headers, additional_headers
                    ):
                        if is_conflicting:
                            logger.warning(
                                f"Overwriting header '{key}' detected. Skipping this key."
                            )
                        else:
                            result_headers[key] = value
            except Exception as ex:
                # Custom logic failure is treated as non-fatal for the connection
                logger.warning("Unable to customize headers: %s. Skipping...", ex)

        return RequestDTO(
            url=request.url,
            method=request.method,
            headers=result_headers,
        )


def apply_interceptors(
    interceptors: Iterable[HttpInterceptor],
    hook: HttpInterceptor.InterceptionHook,
    request: RequestDTO,
) -> RequestDTO:
    for interceptor in interceptors:
        request = interceptor.intercept_on(hook, request)
    return request


class InterceptOnMixin:
    request_interceptors: MutableSequence[HttpInterceptor]

    def _intercept_on(
        self, hook: HttpInterceptor.InterceptionHook, request: RequestDTO
    ) -> RequestDTO:
        try:
            return apply_interceptors(self.request_interceptors, hook, request)
        except AttributeError as ex:
            logger.warning(
                "Mixin can be used only for classes with defined attribute or property named request_interceptors. Error: %s. Skipping...",
                ex,
            )


_original_requests_request = requests.request
_original_http_urlopen = urllib3.HTTPConnectionPool.urlopen
_original_https_urlopen = urllib3.HTTPSConnectionPool.urlopen
_original_retry_increment = urllib3.Retry.increment


def inject_interception_callback(
    intercept_fn: Callable[[HttpInterceptor.InterceptionHook, RequestDTO], RequestDTO]
) -> None:
    # Signature must match requests.request
    @wraps(_original_requests_request)
    def intercepted_requests_request(method, url, *args, headers=None, **kwargs):
        request_info = get_request_info(method, url, headers or kwargs.get("headers"))
        updated_request = intercept_fn(
            HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request_info
        )
        return _original_requests_request(
            updated_request.method,
            updated_request.url,
            *args,
            headers=updated_request.headers,
            **kwargs,
        )

    # Signature must match urllib3.HTTPConnectionPool.urlopen
    @wraps(_original_http_urlopen)
    def intercepted_http_urlopen(
        self, method, url, body=None, headers=None, retries=None, *args, **kwargs
    ):
        request_info = get_request_info(method, url, headers)
        updated_request = intercept_fn(
            HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request_info
        )
        return _original_http_urlopen(
            self,
            updated_request.method,
            updated_request.url,
            body,
            updated_request.headers,
            retries,
            *args,
            **kwargs,
        )

    # Signature must match urllib3.HTTPSConnectionPool.urlopen
    @wraps(_original_https_urlopen)
    def intercepted_https_urlopen(
        self, method, url, body=None, headers=None, retries=None, *args, **kwargs
    ):
        request_info = get_request_info(method, url, headers)
        updated_request = intercept_fn(
            HttpInterceptor.InterceptionHook.ONCE_BEFORE_REQUEST, request_info
        )
        return _original_https_urlopen(
            self,
            updated_request.method,
            updated_request.url,
            body,
            updated_request.headers,
            retries,
            *args,
            **kwargs,
        )

    # NOTE: Signature must match urllib3.Retry.increment
    @wraps(_original_retry_increment)
    def intercepted_retry_increment(
        self,
        method,
        url,
        *args,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
        **kwargs,
    ):
        response_headers = getattr(response, "headers", {}) if response else {}
        request_info = get_request_info(method, url, response_headers)
        updated_request = intercept_fn(
            HttpInterceptor.InterceptionHook.BEFORE_EACH_RETRY, request_info
        )
        return _original_retry_increment(
            self,
            updated_request.method,
            updated_request.url,
            *args,
            response=response,
            error=error,
            _pool=_pool,
            _stacktrace=_stacktrace,
            **kwargs,
        )

    requests.request = intercepted_requests_request
    urllib3.HTTPConnectionPool.urlopen = intercepted_http_urlopen
    urllib3.HTTPSConnectionPool.urlopen = intercepted_https_urlopen
    urllib3.Retry.increment = intercepted_retry_increment


def remove_interceptors():
    requests.request = _original_requests_request
    urllib3.HTTPConnectionPool.urlopen = _original_http_urlopen
    urllib3.HTTPSConnectionPool.urlopen = _original_https_urlopen
    urllib3.Retry.increment = _original_retry_increment


def inject_interceptors_for_connection(connection: SnowflakeConnection) -> None:
    intercept_fn = partial(
        apply_interceptors, interceptors=connection.request_interceptors
    )
    inject_interception_callback(intercept_fn)


def verify_method(suspected_method: Any) -> str | None:
    if suspected_method is None:
        logger.debug("verify_method: No method provided.")
        return None
    suspected_method_str = str(suspected_method).upper()
    if suspected_method_str in METHODS:
        return suspected_method_str
    logger.warning(
        f"verify_method: Unrecognized method '{suspected_method}'. Ignoring."
    )
    return None


def verify_url(suspected_url: Any) -> str | None:
    if isinstance(suspected_url, str):
        return suspected_url
    if suspected_url is not None:
        logger.warning(
            f"verify_url: Non-string url detected ({suspected_url}). Ignoring."
        )
    else:
        logger.debug("verify_url: No url provided.")
    return None


def verify_headers(suspected_headers: Any) -> dict | None:
    if isinstance(suspected_headers, dict):
        return suspected_headers
    if suspected_headers is not None:
        logger.warning(
            f"verify_headers: Non-dict headers detected ({suspected_headers}). Ignoring."
        )
    else:
        logger.debug("verify_headers: No headers provided.")
    return None


def get_request_info(
    method: Any,
    url: Any,
    headers: Any,
) -> RequestDTO:
    validated_method = verify_method(method)
    validated_url = verify_url(url)
    validated_headers = verify_headers(headers)
    return RequestDTO(
        url=validated_url, method=validated_method, headers=validated_headers
    )


# @contextmanager
# def intercepted_connection(connection):
#     inject_interceptors_for_connection(connection)
#     try:
#         yield
#     finally:
#         remove_interceptors()
