import csv
import importlib.util
import json
import logging
from datetime import datetime
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("mitm_script.log")],
)
logger = logging.getLogger(__name__)


def safe_mitmproxy_call(func, fallback, description):
    """Safely call a mitmproxy API function with fallback"""
    try:
        return func()
    except Exception as e:
        logger.warning(f"Failed to {description}: {e}")
        return fallback


def extract_request_data(flow):
    """Extract request data safely from mitmproxy flow"""
    data = {}

    # Basic request info
    data["method"] = safe_mitmproxy_call(
        lambda: flow.request.method, "UNKNOWN", "get request method"
    )

    data["host"] = safe_mitmproxy_call(
        lambda: flow.request.pretty_host.lower(),
        safe_mitmproxy_call(
            lambda: flow.request.headers.get("host", "unknown").lower(),
            "unknown",
            "get host from headers",
        ),
        "get pretty_host",
    )

    # URLs and paths
    raw_url = safe_mitmproxy_call(
        lambda: flow.request.pretty_url,
        safe_mitmproxy_call(lambda: flow.request.url, "unknown", "get basic URL"),
        "get pretty_url",
    )

    raw_path = safe_mitmproxy_call(
        lambda: flow.request.path, "unknown", "get request path"
    )

    # Process URLs with masking
    try:
        data["url"] = SecretDetector.mask_secrets(safe_str(raw_url)).masked_text
        data["path"] = SecretDetector.mask_secrets(safe_str(raw_path)).masked_text
    except Exception as e:
        logger.error(f"Failed to mask URL/path: {e}")
        data["url"] = safe_str(raw_url)
        data["path"] = safe_str(raw_path)

    # Request headers and size
    data["headers"] = safe_mitmproxy_call(
        lambda: dict(flow.request.headers), {}, "get request headers"
    )

    data["size"] = safe_mitmproxy_call(
        lambda: len(flow.request.content) if flow.request.content else 0,
        0,
        "get request size",
    )

    return data


def extract_response_data(flow):
    """Extract response data safely from mitmproxy flow"""
    data = {}

    # Basic response info
    data["status_code"] = safe_mitmproxy_call(
        lambda: flow.response.status_code, 0, "get status code"
    )

    data["reason"] = safe_mitmproxy_call(
        lambda: flow.response.reason or "", "", "get response reason"
    )

    # Response headers and size
    data["headers"] = safe_mitmproxy_call(
        lambda: dict(flow.response.headers), {}, "get response headers"
    )

    data["size"] = safe_mitmproxy_call(
        lambda: len(flow.response.content) if flow.response.content else 0,
        0,
        "get response size",
    )

    # Content type for debugging
    data["content_type"] = data["headers"].get("content-type", "")

    return data


def extract_timing_data(flow):
    """Extract timing data safely from mitmproxy flow"""
    return safe_mitmproxy_call(
        lambda: (
            int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
            if flow.response.timestamp_end and flow.request.timestamp_start
            else 0
        ),
        0,
        "calculate duration",
    )


def process_headers_safely(request_headers, response_headers):
    """Process headers with SecretDetector masking"""
    try:
        # Log content-encoding for debugging
        content_encoding = response_headers.get("content-encoding", "none")
        content_type = response_headers.get("content-type", "unknown")
        logger.debug(
            f"Response content-encoding: {content_encoding}, content-type: {content_type}"
        )

        masked_request = SecretDetector.mask_secrets(
            json.dumps(request_headers, ensure_ascii=True)
        ).masked_text

        masked_response = SecretDetector.mask_secrets(
            json.dumps(response_headers, ensure_ascii=True)
        ).masked_text

        return masked_request, masked_response

    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        logger.warning(f"Header processing encoding error: {e}")
        return (
            f"[HEADER ENCODING ERROR: {str(e)}]",
            f"[HEADER ENCODING ERROR: {str(e)}]",
        )
    except Exception as e:
        logger.error(f"Unexpected header processing error: {e}")
        return (
            f"[HEADER ERROR: {type(e).__name__}]",
            f"[HEADER ERROR: {type(e).__name__}]",
        )


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
}


def safe_str(value, max_length=5000):
    """Convert value to string, handling multiple encoding scenarios aggressively"""
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
        # Unicode encoding issues - try multiple encodings
        if isinstance(value, bytes):
            # Try multiple common encodings
            encodings_to_try = [
                "utf-8",
                "utf-16",
                "utf-32",  # Unicode variants
                "cp1252",
                "windows-1252",  # Windows encodings
                "iso-8859-1",
                "latin1",  # Western European
                "cp437",
                "cp850",  # DOS/Windows console
                "ascii",  # Safe fallback
            ]

            for encoding in encodings_to_try:
                try:
                    result = value.decode(encoding, errors="replace")
                    if len(result) > max_length:
                        result = result[:max_length] + "...[TRUNCATED]"
                    logger.debug(f"Successfully decoded with {encoding}")
                    return result
                except (UnicodeDecodeError, LookupError):
                    continue

            # If all encodings fail, use repr for safety
            try:
                result = repr(value)
                if len(result) > max_length:
                    result = result[:max_length] + "...[TRUNCATED]"
                return result
            except Exception as e:
                return f"[BYTES ENCODING ERROR: {type(e).__name__}]"
        else:
            # Non-bytes object with encoding issues
            try:
                # Force ASCII-only representation
                result = ascii(value)
                if len(result) > max_length:
                    result = result[:max_length] + "...[TRUNCATED]"
                return result
            except Exception as e:
                return f"[OBJECT ENCODING ERROR: {type(e).__name__}]"

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
    import platform

    system_info = f"{platform.system()} {platform.release()}"
    logger.info(f"Running on: {system_info}")

    # Log proxy environment variables for debugging
    import os

    proxy_vars = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "REQUESTS_CA_BUNDLE",
    ]
    for var in proxy_vars:
        value = os.environ.get(var, "NOT_SET")
        logger.info(f"Environment {var}={value}")

    # Use UTF-8 with BOM for better Windows compatibility
    f = open(
        "test_requests.csv", "w", newline="", encoding="utf-8-sig", errors="replace"
    )
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    logger.info(
        f"CSV file opened successfully with UTF-8-sig encoding on {system_info}"
    )

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
    logger.info("Header written and flushed successfully")
except Exception as file_error:
    logger.critical(f"Failed to open/write CSV file: {file_error}")
    # Fallback to stdout if file fails
    import sys

    f = sys.stdout
    writer = csv.writer(f)
    logger.warning("Falling back to stdout output")
logger.info("MITM script loaded and ready to capture requests...")


def response(flow):
    """Called when a response is received"""
    # Debug logging
    try:
        debug_host = getattr(flow.request, "pretty_host", "unknown")
        debug_method = getattr(flow.request, "method", "unknown")
        logger.debug(f"Processing {debug_method} request to {debug_host}")
    except Exception as debug_error:
        logger.error(f"Debug error getting basic request info: {debug_error}")

    try:
        # Extract all data using helper functions
        request_data = extract_request_data(flow)
        response_data = extract_response_data(flow)
        duration_ms = extract_timing_data(flow)

        # Skip if domain should be ignored
        if any(
            ignored_domain in request_data["host"] for ignored_domain in IGNORE_DOMAINS
        ):
            return

        # Process headers with secret masking
        request_headers, response_headers = process_headers_safely(
            request_data["headers"], response_data["headers"]
        )

        # Write row to CSV with safe string conversion
        timestamp = datetime.now().isoformat()
        writer.writerow(
            [
                safe_str(timestamp),
                safe_str(request_data["method"]),
                safe_str(request_data["url"]),
                safe_str(request_data["host"]),
                safe_str(request_data["path"]),
                safe_str(response_data["status_code"]),
                safe_str(response_data["reason"]),
                safe_str(request_data["size"]),
                safe_str(response_data["size"]),
                safe_str(response_data["content_type"]),
                safe_str(duration_ms),
                safe_str(request_headers),
                safe_str(response_headers),
                "",  # No error for successful requests
            ]
        )

        try:
            f.flush()  # Ensure it's written immediately
            logger.debug(
                f"Successfully wrote {request_data['method']} {request_data['host']}"
            )
        except Exception as flush_error:
            logger.error(f"Flush error: {flush_error}")

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
            logger.debug(f"Successfully wrote error for {error_method} {error_host}")
        except Exception as flush_error:
            logger.error(f"Error flush failed: {flush_error}")


def done():
    """Called when mitmproxy shuts down"""
    f.close()
