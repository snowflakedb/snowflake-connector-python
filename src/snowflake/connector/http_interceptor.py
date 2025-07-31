from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from enum import Enum, auto
from typing import Any, Generator, Iterable, MutableSequence, NamedTuple

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
        BEFORE_RETRY = auto()
        BEFORE_REQUEST_ISSUED = auto()

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
        if hook is HttpInterceptor.InterceptionHook.BEFORE_REQUEST_ISSUED:
            customizers_to_apply = (
                self._static_headers_customizers + self._dynamic_headers_customizers
            )
            return self._handle_headers_customization(request, customizers_to_apply)
        elif hook is HttpInterceptor.InterceptionHook.BEFORE_RETRY:
            return self._handle_headers_customization(
                request, self._dynamic_headers_customizers
            )
        return request

    def _handle_headers_customization(
        self, request: RequestDTO, headers_customizers: Iterable[HeadersCustomizer]
    ) -> RequestDTO:
        # copy preventing mutation in the registered customizer
        result_headers = dict(request.headers) if request.headers else {}

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
