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


def safe_str(value, max_length=5000):
    """Convert value to string, handling encoding issues aggressively"""
    if value is None:
        return ""

    try:
        # First attempt - normal string conversion
        result = str(value)

        # Truncate extremely long strings to prevent issues
        if len(result) > max_length:
            result = result[:max_length] + "...[TRUNCATED]"

        return result

    except (UnicodeDecodeError, UnicodeEncodeError):
        # Unicode encoding issues
        try:
            if isinstance(value, bytes):
                result = value.decode("utf-8", errors="replace")
            else:
                # Force ASCII-only representation
                result = repr(value)

            # Truncate if too long
            if len(result) > max_length:
                result = result[:max_length] + "...[TRUNCATED]"

            return result

        except Exception as e:
            return f"[ENCODING ERROR: {type(e).__name__}]"

    except Exception as e:
        # Any other string conversion issues
        try:
            # Last resort - ASCII-only repr
            result = ascii(value)
            if len(result) > max_length:
                result = result[:max_length] + "...[TRUNCATED]"
            return result
        except Exception:
            return f"[STR ERROR: {type(e).__name__}]"


# Open CSV file for writing requests with proper encoding and quoting
try:
    f = open("test_requests.csv", "w", newline="", encoding="utf-8", errors="replace")
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    print("CSV file opened successfully")

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
    f.flush()
    print("Header written and flushed successfully")
except Exception as file_error:
    print(f"CRITICAL: Failed to open/write CSV file: {file_error}")
    # Fallback to stdout if file fails
    import sys

    f = sys.stdout
    writer = csv.writer(f)
    print("Falling back to stdout output")
print("MITM script loaded and ready to capture requests...")


def response(flow):
    """Called when a response is received"""
    try:
        host = getattr(flow.request, "pretty_host", "unknown")
        method = getattr(flow.request, "method", "unknown")
        print(f"Processing {method} request to {host}")
    except Exception as debug_error:
        print(f"Debug error: {debug_error}")

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

        # Write row to CSV with safe string conversion
        writer.writerow(
            [
                safe_str(timestamp),
                safe_str(method),
                safe_str(url),
                safe_str(host),
                safe_str(path),
                safe_str(status_code),
                safe_str(reason),
                safe_str(request_size),
                safe_str(response_size),
                safe_str(content_type),
                safe_str(duration_ms),
                safe_str(request_headers),
                safe_str(response_headers),
                "",  # No error for successful requests
            ]
        )

        try:
            f.flush()  # Ensure it's written immediately
            print(f"Successfully wrote {method} {host}")
        except Exception as flush_error:
            print(f"Flush error: {flush_error}")

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
                safe_str(datetime.now().isoformat()),
                safe_str(error_method),
                "",  # Empty URL for errors
                safe_str(error_host),
                "",  # Empty path for errors
                "",  # Empty status code for errors
                "",  # Empty reason for errors
                "",  # Empty request size for errors
                "",  # Empty response size for errors
                "",  # Empty content type for errors
                "",  # Empty duration for errors
                "",  # Empty request headers for errors
                "",  # Empty response headers for errors
                safe_str(
                    SecretDetector.mask_secrets(str(e)).masked_text
                ),  # Error message
            ]
        )
        try:
            f.flush()
            print(f"Successfully wrote error for {error_method} {error_host}")
        except Exception as flush_error:
            print(f"Error flush failed: {flush_error}")


def done():
    """Called when mitmproxy shuts down"""
    f.close()
