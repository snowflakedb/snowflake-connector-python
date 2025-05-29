from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any, Iterable, MutableSequence, NamedTuple

Headers = dict[str, Any]


class RequestDTO(NamedTuple):
    url: str | bytes
    method: str
    headers: Headers


logger = logging.getLogger(__name__)


class ConflictDTO(NamedTuple):
    conflicting_items: Iterable[Any]
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
        static = []
        dynamic = []
        if headers_customizers:
            for customizer in headers_customizers:
                if customizer.is_invoked_once():
                    static.append(customizer)
                else:
                    dynamic.append(customizer)
        return static, dynamic

    @staticmethod
    def would_overwrite_keys(
        original_headers: Headers, other_headers: Headers, case_sensitive: bool = False
    ) -> ConflictDTO:

        # After some time of system functioning sets of (original headers names, additional headers names) will be often reoccurring. Therefore, caching can be beneficial. But frozenset convertion would need to be done.
        try:
            if not case_sensitive:
                original_key_set = {key.lower() for key in original_headers}
                other_key_set = {key.lower() for key in other_headers}
            else:
                original_key_set = set(original_headers)
                other_key_set = set(other_headers)

            conflicting_keys = original_key_set & other_key_set
            has_conflict = bool(conflicting_keys)
        except (TypeError, AttributeError) as ex:
            # It is very rare to have original or additional headers empty - therefore zero-cost exceptions should be used
            if not original_headers or not other_headers:
                return ConflictDTO(had_conflict=False, conflicting_items=set())
            else:
                logger.warning(
                    "Unable to determine conflicting headers: %s. Skipping", ex
                )
                raise ex

        return ConflictDTO(conflicting_keys, has_conflict)

    # add argument "inplace"
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
        original_headers = dict(request.headers)
        additional_headers = {}

        for header_customizer in headers_customizers:
            try:
                if header_customizer.applies_to(request):
                    additional_headers = header_customizer.get_new_headers(request)
                    conflict_info = self.would_overwrite_keys(
                        original_headers, additional_headers
                    )
                    if conflict_info.had_conflict:
                        logger.warning(
                            "Overwriting headers detected for headers: %s. Skipping headers customization...",
                            conflict_info.conflicting_items,
                        )
                    else:
                        original_headers.update(additional_headers)
            except Exception as ex:
                logger.warning("Unable to customize headers: %s. Skipping...", ex)

        return RequestDTO(
            url=request.url,
            method=request.method,
            headers={**original_headers, **additional_headers},
        )


class InterceptOnMixin:
    request_interceptors: MutableSequence[HttpInterceptor]

    def _intercept_on(
        self, hook: HttpInterceptor.InterceptionHook, request: RequestDTO
    ) -> Any:
        try:
            for interceptor in self.request_interceptors:
                interceptor.intercept_on(hook, request)
        except AttributeError as ex:
            logger.warning(
                "Mixin can be used only for classes with defined attribute or property named request_interceptors. Error: %s. Skipping...",
                ex,
            )
