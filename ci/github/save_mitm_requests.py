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


def clean_for_csv(value):
    """Clean a value for safe CSV output"""
    if value is None:
        return ""

    # Convert to string and handle encoding issues
    try:
        str_value = str(value)
        # Replace problematic characters
        str_value = str_value.replace("\x00", "")  # Remove null bytes
        str_value = str_value.replace("\r", "\\r")  # Escape carriage returns
        str_value = str_value.replace("\n", "\\n")  # Escape newlines
        return str_value
    except (UnicodeDecodeError, UnicodeEncodeError):
        return "[ENCODING ERROR]"


# Open CSV file for writing requests with proper encoding and quoting
f = open("test_requests.csv", "w", newline="", encoding="utf-8", errors="replace")
writer = csv.writer(f, quoting=csv.QUOTE_ALL)

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
        "error_message",
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

        # Convert headers to JSON strings and mask secrets (with proper encoding)
        try:
            request_headers_dict = dict(flow.request.headers)
            response_headers_dict = dict(flow.response.headers)

            request_headers = SecretDetector.mask_secrets(
                json.dumps(request_headers_dict, ensure_ascii=True)
            ).masked_text
            response_headers = SecretDetector.mask_secrets(
                json.dumps(response_headers_dict, ensure_ascii=True)
            ).masked_text
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            request_headers = f"[ENCODING ERROR: {str(e)}]"
            response_headers = f"[ENCODING ERROR: {str(e)}]"

        # Extract key info and mask sensitive data (with proper encoding)
        timestamp = datetime.now().isoformat()
        method = flow.request.method

        try:
            url = SecretDetector.mask_secrets(flow.request.pretty_url).masked_text
            path = SecretDetector.mask_secrets(flow.request.path).masked_text
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            url = f"[ENCODING ERROR: {str(e)}]"
            path = f"[ENCODING ERROR: {str(e)}]"

        status_code = flow.response.status_code
        reason = flow.response.reason or ""
        content_type = flow.response.headers.get("content-type", "")

        # Write row to CSV with cleaned data
        writer.writerow(
            [
                clean_for_csv(timestamp),
                clean_for_csv(method),
                clean_for_csv(url),
                clean_for_csv(host),
                clean_for_csv(path),
                clean_for_csv(status_code),
                clean_for_csv(reason),
                clean_for_csv(request_size),
                clean_for_csv(response_size),
                clean_for_csv(content_type),
                clean_for_csv(duration_ms),
                clean_for_csv(request_headers),
                clean_for_csv(response_headers),
                "",  # No error for successful requests
            ]
        )

        f.flush()  # Ensure it's written immediately

    except Exception as e:
        # Write error row (only for non-ignored domains)
        try:
            error_host = getattr(flow.request, "pretty_host", "")
            error_method = getattr(flow.request, "method", "")
        except Exception:
            error_host = ""
            error_method = ""

        # Check if we should ignore this domain
        if error_host and any(
            ignored_domain in error_host.lower() for ignored_domain in IGNORE_DOMAINS
        ):
            return

        writer.writerow(
            [
                clean_for_csv(datetime.now().isoformat()),
                clean_for_csv(error_method),
                "",  # Empty URL for errors
                clean_for_csv(error_host),
                "",  # Empty path for errors
                "",  # Empty status code for errors
                "",  # Empty reason for errors
                "",  # Empty request size for errors
                "",  # Empty response size for errors
                "",  # Empty content type for errors
                "",  # Empty duration for errors
                "",  # Empty request headers for errors
                "",  # Empty response headers for errors
                clean_for_csv(
                    SecretDetector.mask_secrets(str(e)).masked_text
                ),  # Error message
            ]
        )
        f.flush()


def done():
    """Called when mitmproxy shuts down"""
    f.close()
