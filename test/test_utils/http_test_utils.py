import re
import threading
from collections import deque
from typing import (
    Any,
    Deque,
    Dict,
    FrozenSet,
    Iterable,
    NamedTuple,
    Optional,
    Tuple,
    Union,
)

try:
    from snowflake.connector.http_interceptor import (
        Headers,
        HeadersCustomizer,
        RequestDTO,
    )
except ImportError:
    HeadersCustomizer = object
    RequestDTO = Tuple
    Headers = Dict


class CollectingCustomizer(HeadersCustomizer):
    def __init__(self):
        self.invocations = deque()
        self._lock = threading.Lock()

    def applies_to(self, request: RequestDTO) -> bool:
        return True

    def get_new_headers(self, request: RequestDTO) -> dict[str, str]:
        with self._lock:
            self.invocations.append(request)
        return {"test-header": "test-value"}


class StaticCollectingCustomizer(CollectingCustomizer):
    def is_invoked_once(self) -> bool:
        return True


class DynamicCollectingCustomizer(CollectingCustomizer):
    def is_invoked_once(self) -> bool:
        return False


class ExpectedRequestInfo(NamedTuple):
    method: str
    url_regexp: Optional[str] = None

    def is_matching(self, request: object) -> bool:
        if isinstance(request, RequestDTO):
            return request.method.upper() == self.method.upper() and bool(
                re.fullmatch(self.url_regexp, request.url)
            )
        elif isinstance(request, ExpectedRequestInfo):
            return (
                request.method == self.method.upper()
                and request.url_regexp == self.url_regexp
            )
        return False


class RequestTracker:
    DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS: FrozenSet[ExpectedRequestInfo] = frozenset(
        [
            ExpectedRequestInfo("GET", r".*/__admin/health"),
        ]
    )

    def __init__(
        self,
        requests: Deque[RequestDTO],
        ignored: Optional[
            Iterable[ExpectedRequestInfo]
        ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
    ):
        self.requests = requests
        self.ignored = ignored or ()
        self._last_request: Optional[RequestDTO] = None
        self._last_expected_info: Optional[ExpectedRequestInfo] = None

    @staticmethod
    def _assert_headers_were_added(
        headers: Headers,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> None:
        expected_headers = dict(expected_headers)

        headers_lowercased = {k.lower(): v for k, v in headers.items()}
        for expected_header_name, expected_header_value in expected_headers.items():
            assert (
                headers_lowercased[expected_header_name.lower()]
                == expected_header_value
            ), "Custom header not found in response"

    def _should_ignore(self, request: RequestDTO) -> bool:
        return any(ignored_info.is_matching(request) for ignored_info in self.ignored)

    def assert_request_occurred(
        self,
        expected: ExpectedRequestInfo,
        raise_on_missing: bool = True,
    ):
        for i, request in enumerate(self.requests):
            if self._should_ignore(request):
                continue

            if expected.is_matching(request):
                self._last_request = request
                self._last_expected_info = expected
                # Pop the matched request from deque, while iterating only once
                del self.requests[i]
                return request

        if raise_on_missing:
            raise AssertionError(
                f"Expected request '{expected.method} {expected.url_regexp}' not found"
            )
        else:
            return None

    def assert_request_occurred_sequentially(
        self,
        expected: ExpectedRequestInfo,
        raise_on_missing: bool = True,
        skip_previous_request_retries: bool = True,
    ) -> RequestDTO:
        while self.requests:
            request = self.requests.popleft()
            if self._should_ignore(request):
                continue

            if expected.is_matching(request):
                self._last_request = request
                self._last_expected_info = expected
                return request

            if (
                skip_previous_request_retries
                and self._last_expected_info
                and self._last_expected_info.is_matching(request)
            ):
                self._last_request = request  # skip retry
                continue

            if raise_on_missing:
                raise AssertionError(f"Unexpected request: {request}")
            else:
                return None

        if raise_on_missing:
            raise AssertionError(
                f"Expected request '{expected.method} {expected.url_regexp}' not found"
            )
        else:
            return None

    # Proxy helpers
    def assert_login_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo("POST", r".*/session/v1/login-request.*")
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_sql_query_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo("POST", r".*/queries/v1/query-request.*")
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_telemetry_send_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo("POST", r".*/telemetry/send.*")
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_disconnect_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo("POST", r".*/session\?delete=true(\&request_guid=.*)?")
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_get_chunk_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo(
                "GET",
                r".*(amazonaws|blob\.core\.windows|storage\.googleapis).*/results/.*main.*data.*\?.*",
            )
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_aws_get_accelerate_issued(
        self,
        optional: bool = True,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
    ) -> RequestDTO:
        rv = self.assert_request_occurred_sequentially(
            ExpectedRequestInfo("GET", r".*\.s3\.amazonaws.*/\?accelerate(.*)?"),
            raise_on_missing=not optional,
        )
        if rv is not None:
            self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_get_file_issued(
        self,
        filename: Optional[str] = None,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "GET",
            r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*"
            + (filename if filename else "")
            + r"(.*)?",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_multiple_put_file_issued(
        self,
        filename: Optional[str] = None,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        while self.assert_put_file_issued(filename, expected_headers, sequentially):
            continue

    def assert_put_file_issued(
        self,
        filename: Optional[str] = None,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "PUT",
            r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*stages.*"
            + (filename if filename else "")
            + r"(.*)?",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_file_head_issued(
        self,
        filename: Optional[str] = None,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "HEAD",
            r".*(amazonaws|blob\.core\.windows|storage\.googleapis).*"
            + (filename if filename else "")
            + r"(.*)?",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_post_start_for_multipart_file_issued(
        self,
        file_path: Optional[str] = None,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "POST",
            r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*/stages/.*"
            + (file_path if file_path else "")
            + r"\?uploads",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_post_end_for_multipart_on_aws_file_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "POST",
            r".*s3\.amazonaws.*/stages/.*",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_put_end_for_multipart_on_azure_file_issued(
        self,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        expected = ExpectedRequestInfo(
            "PUT",
            r".*blob\.core\.windows.*/stages/.*?comp=blocklist(.*)?",
        )
        rv = (
            self.assert_request_occurred_sequentially(expected)
            if sequentially
            else self.assert_request_occurred(expected)
        )
        self._assert_headers_were_added(rv.headers, expected_headers)
        return rv

    def assert_end_for_multipart_file_issued(
        self,
        cloud_platform: str,
        expected_headers: Union[dict[str, Any], tuple[tuple[str, Any], ...]] = (
            ("test-header", "test-value"),
        ),
        sequentially: bool = True,
    ) -> RequestDTO:
        if cloud_platform in ("aws", "dev"):
            self.assert_post_end_for_multipart_on_aws_file_issued()
        elif cloud_platform in ("azure", "dev"):
            self.assert_put_end_for_multipart_on_azure_file_issued()
