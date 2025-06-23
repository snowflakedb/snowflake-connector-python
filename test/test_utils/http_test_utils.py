import re
from collections import deque
from typing import Deque, FrozenSet, Iterable, NamedTuple, Optional

try:
    from snowflake.connector.http_interceptor import HeadersCustomizer, RequestDTO
except ImportError:
    pass


class CollectingCustomizer(HeadersCustomizer):
    def __init__(self):
        self.invocations = deque()

    def applies_to(self, request: RequestDTO) -> bool:
        return True

    def get_new_headers(self, request: RequestDTO) -> dict[str, str]:
        self.invocations.append(request)
        return {}


class StaticCollectingCustomizer(CollectingCustomizer):
    def is_invoked_once(self) -> bool:
        return True


class DynamicCollectingCustomizer(CollectingCustomizer):
    def is_invoked_once(self) -> bool:
        return False


class ExpectedRequestInfo(NamedTuple):
    method: str
    url_regexp: Optional[str] = None

    # TODO: pass parameters as well as an argument
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

    def _should_ignore(self, request: RequestDTO) -> bool:
        return any(ignored_info.is_matching(request) for ignored_info in self.ignored)

    def assert_request_occurred_after_optional_retries(
        self, expected: ExpectedRequestInfo, raise_on_missing: bool = True
    ) -> RequestDTO:
        while self.requests:
            request = self.requests.popleft()
            if self._should_ignore(request):
                continue

            if expected.is_matching(request):
                self._last_request = request
                self._last_expected_info = expected
                return request

            if self._last_expected_info and self._last_expected_info.is_matching(
                request
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
    def assert_login_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo("POST", r".*/session/v1/login-request.*")
        )

    def assert_sql_query_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo("POST", r".*/queries/v1/query-request.*")
        )

    def assert_telemetry_send_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo("POST", r".*/telemetry/send.*")
        )

    def assert_disconnect_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo("POST", r".*/session\?delete=true(\&request_guid=.*)?")
        )

    def assert_get_chunk_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "GET",
                r".*(amazonaws|blob\.core\.windows|storage\.googleapis).*?/results/.*main.*data.*\?.*",
            )
        )

    def assert_aws_get_accelerate_issued(self, optional: bool = True) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo("GET", r".*\.s3\.amazonaws.*/\?accelerate(.*)?"),
            raise_on_missing=not optional,
        )

    def assert_get_file_issued(self, filename: Optional[str] = None) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "GET",
                r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*"
                + (filename if filename else ""),
            )
        )

    def assert_put_file_issued(self, filename: Optional[str] = None) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "PUT",
                r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*/stages/.*"
                + (filename if filename else "")
                + "(.*)?",
            )
        )

    def assert_file_head_issued(self, filename: Optional[str] = None) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "HEAD",
                r".*(amazonaws|blob\.core\.windows|storage\.googleapis).*"
                + (filename if filename else ""),
            )
        )

    def assert_post_start_for_multipart_file_issued(
        self, file_path: Optional[str] = None
    ) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "POST",
                r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*/stages/.*"
                + (file_path if file_path else "")
                + r"\?uploads",
            )
        )

    def assert_post_end_for_multipart_file_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "POST",
                r".*(s3\.amazonaws|blob\.core\.windows|storage\.googleapis).*/stages/.*",
            )
        )
