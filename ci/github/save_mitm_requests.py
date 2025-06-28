import csv
import json
from datetime import datetime

# Open CSV file for writing requests
f = open("test_requests.csv", "w", newline="", encoding="utf-8")
writer = csv.writer(f)

# Write CSV header
writer.writerow(
    [
        "timestamp",
        "method",
        "url",
        "host",
        "path",
        "status_code",
        "reason",
        "request_size",
        "response_size",
        "content_type",
        "duration_ms",
        "request_headers",
        "response_headers",
    ]
)


def response(flow):
    """Called when a response is received"""
    try:
        # Calculate duration
        duration_ms = (
            int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            if flow.response.timestamp_end and flow.request.timestamp_start
            else 0
        )

        # Get request/response sizes
        request_size = len(flow.request.content) if flow.request.content else 0
        response_size = len(flow.response.content) if flow.response.content else 0

        # Convert headers to JSON strings (easier to parse later)
        request_headers = json.dumps(dict(flow.request.headers))
        response_headers = json.dumps(dict(flow.response.headers))

        # Extract key info
        timestamp = datetime.now().isoformat()
        method = flow.request.method
        url = flow.request.pretty_url
        host = flow.request.pretty_host
        path = flow.request.path
        status_code = flow.response.status_code
        reason = flow.response.reason
        content_type = flow.response.headers.get("content-type", "")

        # Write row to CSV
        writer.writerow(
            [
                timestamp,
                method,
                url,
                host,
                path,
                status_code,
                reason,
                request_size,
                response_size,
                content_type,
                duration_ms,
                request_headers,
                response_headers,
            ]
        )

        f.flush()  # Ensure it's written immediately

    except Exception as e:
        # Write error row
        writer.writerow(
            [
                datetime.now().isoformat(),
                "ERROR",
                str(e),
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "",
            ]
        )
        f.flush()


def done():
    """Called when mitmproxy shuts down"""
    f.close()
