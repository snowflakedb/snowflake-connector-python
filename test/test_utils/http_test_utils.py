import re
from collections import deque
from typing import Deque, FrozenSet, Iterable, NamedTuple, Optional

from snowflake.connector.http_interceptor import HeadersCustomizer, RequestDTO


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
            return request.method.upper() == self.method.upper() and re.fullmatch(
                self.url_regexp, request.url
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
        self, expected: ExpectedRequestInfo
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

            raise AssertionError(f"Unexpected request: {request}")

        raise AssertionError(
            f"Expected request '{expected.method} {expected.url_regexp}' not found"
        )

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
            ExpectedRequestInfo("POST", r".*/session\?delete=true")
        )

    def assert_get_chunk_issued(self) -> RequestDTO:
        return self.assert_request_occurred_after_optional_retries(
            ExpectedRequestInfo(
                "GET", r".*amazonaws.*/stage/results/.*/main/data.*\?.*"
            )
        )
