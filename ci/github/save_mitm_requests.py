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
    try:
        debug_host = getattr(flow.request, "pretty_host", "unknown")
        debug_method = getattr(flow.request, "method", "unknown")
        logger.debug(f"Processing {debug_method} request to {debug_host}")
    except Exception as debug_error:
        logger.error(f"Debug error getting basic request info: {debug_error}")

    try:
        # Skip if domain should be ignored - wrap mitmproxy API call
        try:
            host = flow.request.pretty_host.lower()
        except Exception as host_error:
            logger.warning(f"Failed to get pretty_host: {host_error}")
            try:
                # Fallback to host header
                host = flow.request.headers.get("host", "unknown").lower()
            except Exception:
                host = "unknown"

        if any(ignored_domain in host for ignored_domain in IGNORE_DOMAINS):
            return

        # Calculate duration - wrap mitmproxy API calls
        try:
            duration_ms = (
                int((flow.response.timestamp_end - flow.request.timestamp_start) * 1000)
                if flow.response.timestamp_end and flow.request.timestamp_start
                else 0
            )
        except Exception as duration_error:
            logger.warning(f"Failed to calculate duration: {duration_error}")
            duration_ms = 0

        # Get request/response sizes - wrap mitmproxy API calls
        try:
            request_size = len(flow.request.content) if flow.request.content else 0
        except Exception as req_size_error:
            logger.warning(f"Failed to get request size: {req_size_error}")
            request_size = 0

        try:
            response_size = len(flow.response.content) if flow.response.content else 0
        except Exception as resp_size_error:
            logger.warning(f"Failed to get response size: {resp_size_error}")
            response_size = 0

        # Convert headers to JSON strings and mask secrets (with proper encoding)
        # Wrap each mitmproxy API call separately
        try:
            request_headers_dict = dict(flow.request.headers)
        except Exception as req_header_error:
            logger.warning(f"Failed to get request headers: {req_header_error}")
            request_headers_dict = {}

        try:
            response_headers_dict = dict(flow.response.headers)
        except Exception as resp_header_error:
            logger.warning(f"Failed to get response headers: {resp_header_error}")
            response_headers_dict = {}

        # Process headers safely
        try:
            # Log content-encoding and content-type for debugging
            content_encoding = response_headers_dict.get("content-encoding", "none")
            content_type = response_headers_dict.get("content-type", "unknown")
            logger.debug(
                f"Response content-encoding: {content_encoding}, content-type: {content_type}"
            )

            request_headers = SecretDetector.mask_secrets(
                json.dumps(request_headers_dict, ensure_ascii=True)
            ).masked_text
            response_headers = SecretDetector.mask_secrets(
                json.dumps(response_headers_dict, ensure_ascii=True)
            ).masked_text
        except (UnicodeDecodeError, UnicodeEncodeError) as e:
            logger.warning(f"Header processing encoding error: {e}")
            request_headers = f"[HEADER ENCODING ERROR: {str(e)}]"
            response_headers = f"[HEADER ENCODING ERROR: {str(e)}]"
        except Exception as e:
            logger.error(f"Unexpected header processing error: {e}")
            request_headers = f"[HEADER ERROR: {type(e).__name__}]"
            response_headers = f"[HEADER ERROR: {type(e).__name__}]"

        # Extract key info and mask sensitive data (with proper encoding)
        timestamp = datetime.now().isoformat()

        # Get method safely
        try:
            method = flow.request.method
        except Exception as method_error:
            logger.warning(f"Failed to get request method: {method_error}")
            method = "UNKNOWN"

        # Get URL and path safely - wrap mitmproxy API calls
        try:
            raw_url = flow.request.pretty_url
        except Exception as url_error:
            logger.warning(f"Failed to get pretty_url: {url_error}")
            try:
                raw_url = flow.request.url
            except Exception:
                raw_url = "unknown"

        try:
            raw_path = flow.request.path
        except Exception as path_error:
            logger.warning(f"Failed to get path: {path_error}")
            raw_path = "unknown"

        # Process URL and path with masking
        try:
            logger.debug(
                f"Raw URL type: {type(raw_url)}, Raw path type: {type(raw_path)}"
            )
            url = SecretDetector.mask_secrets(safe_str(raw_url)).masked_text
            path = SecretDetector.mask_secrets(safe_str(raw_path)).masked_text
        except Exception as e:
            logger.error(f"Failed to mask URL/path: {e}")
            url = safe_str(raw_url)
            path = safe_str(raw_path)

        # Get response properties safely
        try:
            status_code = flow.response.status_code
        except Exception as status_error:
            logger.warning(f"Failed to get status_code: {status_error}")
            status_code = 0

        try:
            reason = flow.response.reason or ""
        except Exception as reason_error:
            logger.warning(f"Failed to get reason: {reason_error}")
            reason = ""

        try:
            content_type = flow.response.headers.get("content-type", "")
        except Exception as content_type_error:
            logger.warning(f"Failed to get content-type: {content_type_error}")
            content_type = ""

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
            logger.debug(f"Successfully wrote {method} {host}")
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
