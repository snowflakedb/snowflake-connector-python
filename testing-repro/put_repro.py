#!/usr/bin/env python3
"""
Customer-style PUT repro:
  1. Connect via snowflake.connector (raw connector, not Snowpark)
  2. Create a named stage if it doesn't exist
  3. Generate random CSV data -> temp file
  4. PUT 'file:///...tmpXXX.csv' @STAGE AUTO_COMPRESS=FALSE PARALLEL=1 OVERWRITE=TRUE
  5. Clean up: REMOVE staged files, optionally DROP stage

Connection parameters are read from a ``parameters.json`` file in the same
directory as this script.  Copy ``parameters.json.example`` to
``parameters.json`` and fill in your Snowflake credentials before running.

Required keys: account, user, host, private_key_file (or password),
               database, schema.
Optional keys: authenticator (default SNOWFLAKE_JWT), role, warehouse,
               port (default 443), protocol (default https).
"""

import csv
import json
import logging
import os
import random
import string
import sys
import tempfile
from typing import Any, Dict

import snowflake.connector

# ---------------------------------------------------------------------------
# Logging — DEBUG to file, INFO to console
# ---------------------------------------------------------------------------
SCRIPT_DIR_EARLY = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(SCRIPT_DIR_EARLY, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "repro.log")
_LOG_FMT = (
    "%(asctime)s %(levelname)-5s %(threadName)s [%(name)s] "
    "%(filename)s:%(lineno)d %(funcName)s() - %(message)s"
)

root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

_fh = logging.FileHandler(LOG_FILE, mode="w")
_fh.setLevel(logging.DEBUG)
_fh.setFormatter(logging.Formatter(_LOG_FMT))
root_logger.addHandler(_fh)

_ch = logging.StreamHandler(sys.stdout)
_ch.setLevel(logging.INFO)
_ch.setFormatter(logging.Formatter("%(asctime)s %(levelname)-5s %(message)s"))
root_logger.addHandler(_ch)

print(f"Debug log file: {LOG_FILE}")

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
except ImportError:
    serialization = None  # type: ignore
    default_backend = None  # type: ignore

# ---------------------------------------------------------------------------
# Connection parameters — loaded from parameters.json in this directory
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARAMS_FILE = os.path.join(SCRIPT_DIR, "parameters.json")


def _load_parameters() -> Dict[str, Any]:
    print(f"Loading connection parameters from: {PARAMS_FILE}")
    if not os.path.isfile(PARAMS_FILE):
        print(
            f"ERROR: parameters.json not found at {PARAMS_FILE}\n"
            f"  Copy parameters.json.example to parameters.json and fill in "
            f"your Snowflake credentials.",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(PARAMS_FILE) as f:
        params = json.load(f)
    for key in ("account", "user", "host", "database", "schema"):
        if key not in params:
            print(
                f"ERROR: Missing required key '{key}' in {PARAMS_FILE}", file=sys.stderr
            )
            sys.exit(1)
    params.setdefault("port", 443)
    params.setdefault("protocol", "https")
    params.setdefault("authenticator", "SNOWFLAKE_JWT")
    print(f"Parameters loaded: account={params['account']}, user={params['user']}")
    return params


CONNECTION_PARAMETERS: Dict[str, Any] = _load_parameters()

STAGE_NAME = "PUT_REPRO_STAGE"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_private_key_bytes(path: str) -> bytes:
    if serialization is None or default_backend is None:
        raise RuntimeError("cryptography package required for private-key auth")
    with open(path, "rb") as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    return key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def connect(cfg: Dict[str, Any]) -> snowflake.connector.SnowflakeConnection:
    params: Dict[str, Any] = {
        "account": cfg["account"],
        "user": cfg["user"],
        "role": cfg.get("role"),
        "warehouse": cfg.get("warehouse"),
        "database": cfg.get("database"),
        "schema": cfg.get("schema"),
        "host": cfg.get("host"),
        "port": cfg.get("port"),
        "protocol": cfg.get("protocol"),
        "authenticator": cfg.get("authenticator"),
    }
    if cfg.get("private_key_file"):
        params["private_key"] = _load_private_key_bytes(cfg["private_key_file"])
    else:
        params["password"] = cfg.get("password")

    return snowflake.connector.connect(
        **{k: v for k, v in params.items() if v is not None}
    )


def generate_temp_csv(target_bytes: int) -> str:
    """Write random CSV rows to a temp file until it reaches *target_bytes*."""
    fd, path = tempfile.mkstemp(suffix=".csv", prefix="put_repro_")
    rand = random.Random(42)
    first_names = ["Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Hank"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    departments = ["Engineering", "Sales", "Marketing", "Finance", "HR", "Support"]

    with os.fdopen(fd, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "id",
                "first_name",
                "last_name",
                "email",
                "department",
                "salary",
                "hire_date",
                "notes",
            ]
        )
        row_id = 0
        while f.tell() < target_bytes:
            row_id += 1
            first = rand.choice(first_names)
            last = rand.choice(last_names)
            writer.writerow(
                [
                    row_id,
                    first,
                    last,
                    f"{first.lower()}.{last.lower()}{row_id}@example.com",
                    rand.choice(departments),
                    round(rand.uniform(40000, 200000), 2),
                    f"{rand.randint(2000, 2025):04d}-{rand.randint(1, 12):02d}-{rand.randint(1, 28):02d}",
                    "".join(
                        rand.choices(string.ascii_letters + " ", k=rand.randint(20, 60))
                    ),
                ]
            )
    actual = os.path.getsize(path)
    print(f"  temp CSV: {path}  ({actual:,} bytes)")
    return path


def fq_stage(cfg: Dict[str, Any]) -> str:
    return f"{cfg['database']}.{cfg['schema']}.{STAGE_NAME}"


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------


def main() -> None:
    target_bytes = int(sys.argv[1]) if len(sys.argv) > 1 else 5 * 1024  # default 5 KB

    print(f"[1] Generating temp CSV (~{target_bytes:,} bytes) ...")
    csv_path = generate_temp_csv(target_bytes)

    print("[2] Connecting to Snowflake (preprod) ...")
    conn = connect(CONNECTION_PARAMETERS)
    cur = conn.cursor()
    stage = fq_stage(CONNECTION_PARAMETERS)

    try:
        print(f"[3] CREATE STAGE IF NOT EXISTS {stage} ...")
        cur.execute(f"CREATE STAGE IF NOT EXISTS {stage}")

        put_sql = (
            f"PUT 'file://{csv_path}' @{stage}/ "
            f"AUTO_COMPRESS=FALSE PARALLEL=1 OVERWRITE=TRUE"
        )
        print(f"[4] {put_sql}")
        cur.execute(put_sql)
        for row in cur:
            print(f"     PUT result: {row}")

        print(f"[5] LIST @{stage} ...")
        cur.execute(f"LIST @{stage}")
        for row in cur:
            print(f"     {row}")

    finally:
        print(f"[6] Cleaning up: REMOVE @{stage}/ ...")
        try:
            cur.execute(f"REMOVE @{stage}/")
            print("     Stage files removed.")
        except Exception as exc:
            print(f"     REMOVE failed (non-fatal): {exc}")

        print(f"[7] DROP STAGE IF EXISTS {stage} ...")
        try:
            cur.execute(f"DROP STAGE IF EXISTS {stage}")
            print("     Stage dropped.")
        except Exception as exc:
            print(f"     DROP STAGE failed (non-fatal): {exc}")

        cur.close()
        conn.close()

        print(f"[8] Removing temp file {csv_path} ...")
        os.unlink(csv_path)

    print("\nDone.")


if __name__ == "__main__":
    main()
