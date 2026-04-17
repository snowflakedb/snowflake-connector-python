"""
Diagnostic script: uploads files to Snowflake's S3 stage WITHOUT the connector's
vendored HTTP stack or OCSP monkey-patch.

Flow:
  1. Uses the Snowflake Python Connector to authenticate and send the PUT SQL to
     Snowflake GS, which returns temporary AWS credentials + bucket + path.
  2. Immediately intercepts the GS response BEFORE the connector uploads anything.
  3. Uses boto3 (standard AWS SDK) and system requests with a presigned URL to
     upload the same files directly to S3.

Connection parameters are read from a ``parameters.json`` file in the same
directory as this script.  Copy ``parameters.json.example`` to
``parameters.json`` and fill in your Snowflake credentials before running.

Required keys: account, user, host, authenticator, private_key_file.

Usage:
    pip install snowflake-connector-python boto3 requests cryptography
    python bypass_test.py
"""

import base64
import hashlib
import json
import logging
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "bypass.log")
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

# ---------------------------------------------------------------------------
# Logging — DEBUG to file, INFO to console
# ---------------------------------------------------------------------------
_LOG_FMT = (
    "%(asctime)s %(levelname)-5s %(threadName)s [%(name)s] "
    "%(filename)s:%(lineno)d %(funcName)s() - %(message)s"
)

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

fh = logging.FileHandler(LOG_FILE, mode="w")
fh.setLevel(logging.DEBUG)
fh.setFormatter(logging.Formatter(_LOG_FMT))
root_logger.addHandler(fh)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)
ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s"))
root_logger.addHandler(ch)

print(f"Debug log file: {LOG_FILE}")

import http.client

http_logger = logging.getLogger("http.client")


def _httpclient_log(*args):
    msg = " ".join(str(a) for a in args)
    if msg.startswith(("send:", "b'")) and len(msg) > 1024:
        http_logger.debug("send: <body %d bytes, omitted>", len(msg))
        return
    http_logger.debug(msg)


http.client.print = _httpclient_log
http.client.HTTPConnection.debuglevel = 1

logging.getLogger("botocore.httpsession").setLevel(logging.INFO)
logging.getLogger("botocore.parsers").setLevel(logging.INFO)
logging.getLogger("botocore.endpoint").setLevel(logging.DEBUG)
logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)

logger = logging.getLogger("bypass-upload")

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------------------
# Connection parameters — loaded from parameters.json in this directory
# ---------------------------------------------------------------------------
PARAMS_FILE = os.path.join(SCRIPT_DIR, "parameters.json")


def _load_parameters() -> dict:
    logger.info("Loading connection parameters from: %s", PARAMS_FILE)
    print(f"Loading connection parameters from: {PARAMS_FILE}")
    if not os.path.isfile(PARAMS_FILE):
        msg = (
            f"parameters.json not found at {PARAMS_FILE}\n"
            f"  Copy parameters.json.example to parameters.json and fill in "
            f"your Snowflake credentials."
        )
        logger.error(msg)
        print(f"ERROR: {msg}", file=sys.stderr)
        sys.exit(1)
    with open(PARAMS_FILE) as f:
        params = json.load(f)
    for key in ("account", "user", "host", "private_key_file"):
        if key not in params:
            logger.error("Missing required key '%s' in %s", key, PARAMS_FILE)
            sys.exit(1)
    logger.info(
        "Parameters loaded: account=%s, user=%s", params["account"], params["user"]
    )
    return params


def _load_private_key_bytes(path: str) -> bytes:
    with open(path, "rb") as key_file:
        key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend(),
        )
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


PARAMS = _load_parameters()
SF_ACCOUNT = PARAMS["account"]
SF_USER = PARAMS["user"]
SF_HOST = PARAMS.get("host", f"{SF_ACCOUNT}.snowflakecomputing.com")
SF_PRIVATE_KEY_FILE = PARAMS["private_key_file"]

# ---------------------------------------------------------------------------
# Step 1: Use the connector ONLY to get stage info from Snowflake GS
# ---------------------------------------------------------------------------
import snowflake.connector

logger.info("Connecting to Snowflake (connector used ONLY for auth + GS metadata)")
ctx = snowflake.connector.connect(
    user=SF_USER,
    account=SF_ACCOUNT,
    host=SF_HOST,
    authenticator=PARAMS.get("authenticator", "SNOWFLAKE_JWT"),
    private_key=_load_private_key_bytes(SF_PRIVATE_KEY_FILE),
)
cs = ctx.cursor()

all_files = sorted(
    f for f in os.listdir(DATA_DIR) if os.path.isfile(os.path.join(DATA_DIR, f))
)
if not all_files:
    logger.error("No files in %s", DATA_DIR)
    sys.exit(1)

first_file = os.path.join(DATA_DIR, all_files[0])
put_sql = f"PUT file://{first_file} @~/ OVERWRITE=TRUE AUTO_COMPRESS=FALSE"

logger.info("Sending PUT SQL to GS (will intercept before actual upload): %s", put_sql)
logger.info("Calling _execute_helper to get GS response without triggering upload...")

ret = cs._execute_helper(put_sql)

if not ret.get("success"):
    logger.error("GS returned failure: %s", json.dumps(ret, indent=2, default=str))
    cs.close()
    ctx.close()
    sys.exit(1)

data = ret["data"]
stage_info = data["stageInfo"]
creds = stage_info["creds"]
encryption_material = data.get("encryptionMaterial")

src_locations = data.get("src_locations", [])

logger.info("=" * 60)
logger.info("GS RESPONSE — Stage Info")
logger.info("  locationType : %s", stage_info.get("locationType"))
logger.info("  location     : %s", stage_info.get("location"))
logger.info("  region       : %s", stage_info.get("region"))
logger.info("  endPoint     : %s", stage_info.get("endPoint"))
logger.info("  stageCredType: %s", stage_info.get("stageCredType"))
logger.info("  AWS_KEY_ID   : %s...", creds.get("AWS_KEY_ID", "")[:12])
logger.info(
    "  AWS_TOKEN    : %s... (len=%d)",
    creds.get("AWS_TOKEN", "")[:12],
    len(creds.get("AWS_TOKEN", "")),
)
logger.info("  encryption   : %s", "yes" if encryption_material else "no")
logger.info("  src_locations: %s", src_locations)
logger.info("  command      : %s", data.get("command"))
logger.info("=" * 60)

if stage_info.get("locationType", "").upper() != "S3":
    logger.error(
        "Stage is not S3 (got %s). This script only supports S3.",
        stage_info.get("locationType"),
    )
    sys.exit(1)

location = stage_info["location"]
bucket_name, _, stage_path = location.partition("/")
if stage_path and not stage_path.endswith("/"):
    stage_path += "/"
region = stage_info["region"]

logger.info("Parsed: bucket=%s, path=%s, region=%s", bucket_name, stage_path, region)

cs.close()
ctx.close()
logger.info("Snowflake connection closed. Connector is no longer involved.")

# ---------------------------------------------------------------------------
# Step 2: Upload files using boto3 (standard AWS SDK — completely independent stack)
# ---------------------------------------------------------------------------
import boto3
from botocore.config import Config as BotoConfig

logger.info("")
logger.info("=" * 60)
logger.info("TEST A: Upload via boto3 (system urllib3, AWS SigV4)")
logger.info("=" * 60)

boto_session = boto3.Session(
    aws_access_key_id=creds["AWS_KEY_ID"],
    aws_secret_access_key=creds["AWS_SECRET_KEY"],
    aws_session_token=creds.get("AWS_TOKEN", ""),
    region_name=region,
)
s3_client = boto_session.client(
    "s3",
    config=BotoConfig(
        signature_version="s3v4",
        retries={"max_attempts": 1, "mode": "standard"},
        connect_timeout=10,
        read_timeout=600,
    ),
)

results_boto3 = []

for filename in all_files:
    filepath = os.path.join(DATA_DIR, filename)
    filesize = os.path.getsize(filepath)
    filesize_human = (
        f"{filesize / (1024**3):.2f} GB"
        if filesize >= 1024**3
        else (
            f"{filesize / (1024**2):.2f} MB"
            if filesize >= 1024**2
            else f"{filesize / 1024:.1f} KB"
        )
    )
    s3_key = stage_path + filename

    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)
    digest = base64.standard_b64encode(sha256.digest()).decode("utf-8")

    extra_args = {
        "ContentType": "application/octet-stream",
        "Metadata": {"sfc-digest": digest},
    }

    logger.info(
        "[boto3] [START] %s (%s) → s3://%s/%s",
        filename,
        filesize_human,
        bucket_name,
        s3_key,
    )
    start = time.time()
    try:
        s3_client.upload_file(filepath, bucket_name, s3_key, ExtraArgs=extra_args)
        elapsed = time.time() - start
        logger.info("[boto3] [OK]    %s — %.2fs", filename, elapsed)
        results_boto3.append((filename, filesize_human, "OK", f"{elapsed:.2f}s"))
    except Exception as e:
        elapsed = time.time() - start
        logger.error("[boto3] [FAIL]  %s — %.2fs — %s", filename, elapsed, e)
        results_boto3.append((filename, filesize_human, "FAIL", f"{elapsed:.2f}s"))

# ---------------------------------------------------------------------------
# Step 3: Upload via presigned URL + system requests (pure HTTP PUT, no auth headers)
# ---------------------------------------------------------------------------
import requests as system_requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry as Urllib3Retry

logger.info("")
logger.info("=" * 60)
logger.info("TEST B: Upload via presigned URL + system requests (pure HTTP PUT)")
logger.info("=" * 60)

http_session = system_requests.Session()
no_retry_adapter = HTTPAdapter(max_retries=Urllib3Retry(total=0))
http_session.mount("https://", no_retry_adapter)
http_session.mount("http://", no_retry_adapter)

results_presigned = []

for filename in all_files:
    filepath = os.path.join(DATA_DIR, filename)
    filesize = os.path.getsize(filepath)
    filesize_human = (
        f"{filesize / (1024**3):.2f} GB"
        if filesize >= 1024**3
        else (
            f"{filesize / (1024**2):.2f} MB"
            if filesize >= 1024**2
            else f"{filesize / 1024:.1f} KB"
        )
    )
    s3_key = stage_path + filename

    presigned_url = s3_client.generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket_name, "Key": s3_key},
        ExpiresIn=3600,
    )
    logger.info(
        "[presigned] URL format check: %s",
        "SigV4" if "X-Amz-Algorithm" in presigned_url else "SigV2 (UNEXPECTED)",
    )
    logger.debug("[presigned] URL for %s: %s", filename, presigned_url[:200] + "...")

    logger.info("[presigned] [START] %s (%s)", filename, filesize_human)
    start = time.time()
    try:
        with open(filepath, "rb") as f:
            resp = http_session.put(
                presigned_url,
                data=f,
                headers={"Content-Type": "application/octet-stream"},
                timeout=(10, 600),
            )
        elapsed = time.time() - start
        if resp.status_code < 300:
            logger.info(
                "[presigned] [OK]    %s — HTTP %s — %.2fs",
                filename,
                resp.status_code,
                elapsed,
            )
            results_presigned.append(
                (filename, filesize_human, "OK", f"{elapsed:.2f}s")
            )
        else:
            body = resp.text[:2048] if resp.text else "(empty)"
            logger.error(
                "[presigned] [FAIL]  %s — HTTP %s — %.2fs — %s",
                filename,
                resp.status_code,
                elapsed,
                body,
            )
            results_presigned.append(
                (
                    filename,
                    filesize_human,
                    f"HTTP {resp.status_code}",
                    f"{elapsed:.2f}s",
                )
            )
    except Exception as e:
        elapsed = time.time() - start
        logger.error(
            "[presigned] [FAIL]  %s — %.2fs — %s: %s",
            filename,
            elapsed,
            type(e).__name__,
            e,
        )
        results_presigned.append((filename, filesize_human, "FAIL", f"{elapsed:.2f}s"))

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
logger.info("")
logger.info("=" * 60)
logger.info("SUMMARY")
logger.info("=" * 60)

for label, results in [
    ("boto3 (SigV4)", results_boto3),
    ("presigned URL (pure HTTP)", results_presigned),
]:
    ok = sum(1 for r in results if r[2] == "OK")
    fail = len(results) - ok
    logger.info("")
    logger.info("--- %s: %d OK, %d FAIL ---", label, ok, fail)
    logger.info("%-30s %-10s %-15s %s", "FILE", "SIZE", "RESULT", "TIME")
    for name, size, status, elapsed in results:
        logger.info("%-30s %-10s %-15s %s", name, size, status, elapsed)

logger.info("Full debug log written to: %s", LOG_FILE)
