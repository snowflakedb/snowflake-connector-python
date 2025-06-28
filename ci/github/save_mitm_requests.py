import csv
import importlib.util
import json
from datetime import datetime
from pathlib import Path

# Import SecretDetector directly without package initialization
secret_detector_path = (
    Path(__file__).parent
    / ".."
    / ".."
    / "src"
    / "snowflake"
    / "connector"
    / "secret_detector.py"
)
spec = importlib.util.spec_from_file_location("secret_detector", secret_detector_path)
if spec is None or spec.loader is None:
    raise ImportError("Could not load secret_detector module")
secret_detector_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(secret_detector_module)
SecretDetector = secret_detector_module.SecretDetector

# Domains to ignore (pip/installation traffic)
IGNORE_DOMAINS = {
    "pypi.org",
    "files.pythonhosted.org",
    "example.com",  # Test domain from setup
}

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
        # Skip if domain should be ignored
        host = flow.request.pretty_host.lower()
        if any(ignored_domain in host for ignored_domain in IGNORE_DOMAINS):
            return

        # Calculate duration
        duration_ms = (
            int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            if flow.response.timestamp_end and flow.request.timestamp_start
            else 0
        )

        # Get request/response sizes
        request_size = len(flow.request.content) if flow.request.content else 0
        response_size = len(flow.response.content) if flow.response.content else 0

        # Convert headers to JSON strings and mask secrets
        request_headers_dict = dict(flow.request.headers)
        response_headers_dict = dict(flow.response.headers)

        request_headers = SecretDetector.mask_secrets(
            json.dumps(request_headers_dict)
        ).masked_text
        response_headers = SecretDetector.mask_secrets(
            json.dumps(response_headers_dict)
        ).masked_text

        # Extract key info and mask sensitive data
        timestamp = datetime.now().isoformat()
        method = flow.request.method
        url = SecretDetector.mask_secrets(flow.request.pretty_url).masked_text
        path = SecretDetector.mask_secrets(flow.request.path).masked_text
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
        # Write error row (only for non-ignored domains)
        if "host" in locals():
            host_check = locals()["host"]
        else:
            host_check = getattr(flow.request, "pretty_host", "").lower()

        if not any(ignored_domain in host_check for ignored_domain in IGNORE_DOMAINS):
            writer.writerow(
                [
                    datetime.now().isoformat(),
                    "ERROR",
                    SecretDetector.mask_secrets(str(e)).masked_text,
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
