import re
from typing import Generator, Iterable, NamedTuple, Optional

from snowflake.connector.http_interceptor import RequestDTO


class ExpectedRequestInfo(NamedTuple):
    method: str
    url_regexp: Optional[str] = None
    params_names: Optional[list[str]] = None

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
                and request.params_names == self.params_names
            )

        return False


DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS = frozenset(
    [
        ExpectedRequestInfo("GET", url_regexp=".*/__admin/health"),
    ]
)


def assert_request_occurred_after_optional_retries(
    requests: Generator[RequestDTO, None, None],
    last_request: Optional[RequestDTO],
    expected_request: ExpectedRequestInfo,
    requests_to_ignore: Optional[
        Iterable[ExpectedRequestInfo]
    ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
) -> RequestDTO:
    """
    Returns the index after matching the expected request,
    skipping retry duplicates if needed.
    """

    requests_to_ignore = requests_to_ignore or ()
    for request in requests:
        if any(
            ignored_request.is_matching(request)
            for ignored_request in requests_to_ignore
        ):
            continue

        if expected_request.is_matching(request):
            return request

        if last_request is not None and expected_request.is_matching(last_request):
            last_request = request  # skip retry
        else:
            raise AssertionError(f"Unexpected request: {request}")

    raise AssertionError(
        f"Expected request '{expected_request.method} {expected_request.url_regexp}' not found"
    )


def assert_login_issued(
    requests: Generator[RequestDTO, None, None],
    last_request: Optional[RequestDTO],
    requests_to_ignore: Optional[
        Iterable[ExpectedRequestInfo]
    ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
) -> int:
    expected_request_info = ExpectedRequestInfo(
        "POST", r".*/session/v1/login-request(\?.*)?"
    )
    return assert_request_occurred_after_optional_retries(
        requests,
        last_request=last_request,
        expected_request=expected_request_info,
        requests_to_ignore=requests_to_ignore,
    )


def assert_sql_query_issued(
    requests: Generator[RequestDTO, None, None],
    last_request: Optional[RequestDTO],
    requests_to_ignore: Optional[
        Iterable[ExpectedRequestInfo]
    ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
) -> int:
    expected_request_info = ExpectedRequestInfo(
        "POST", r".*/queries/v1/query-request(\?.*)?"
    )
    return assert_request_occurred_after_optional_retries(
        requests,
        last_request=last_request,
        expected_request=expected_request_info,
        requests_to_ignore=requests_to_ignore,
    )


def assert_telemetry_send_issued(
    requests: Generator[RequestDTO, None, None],
    last_request: Optional[RequestDTO],
    requests_to_ignore: Optional[
        Iterable[ExpectedRequestInfo]
    ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
) -> int:
    expected_request_info = ExpectedRequestInfo("POST", r".*/telemetry/send(\?.*)?")
    return assert_request_occurred_after_optional_retries(
        requests,
        last_request=last_request,
        expected_request=expected_request_info,
        requests_to_ignore=requests_to_ignore,
    )


def assert_disconnect_issued(
    requests: Generator[RequestDTO, None, None],
    last_request: Optional[RequestDTO],
    requests_to_ignore: Optional[
        Iterable[ExpectedRequestInfo]
    ] = DEFAULT_REQUESTS_TO_IGNORE_IN_CHECKS,
) -> int:
    expected_request_info = ExpectedRequestInfo("POST", r".*/session\?delete=true")
    return assert_request_occurred_after_optional_retries(
        requests,
        last_request=last_request,
        expected_request=expected_request_info,
        requests_to_ignore=requests_to_ignore,
    )
