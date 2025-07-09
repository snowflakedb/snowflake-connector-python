# sign_v4.py  (no external deps)
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse

_ALGO = "AWS4-HMAC-SHA256"
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _canonical_qs(qs: str) -> str:
    pairs = urllib.parse.parse_qsl(qs, keep_blank_values=True)
    pairs.sort()
    safe = "-_.~"
    return "&".join(
        f"{urllib.parse.quote(k, safe=safe)}=" f"{urllib.parse.quote(v, safe=safe)}"
        for k, v in pairs
    )


def sign_get_caller_identity(
    url: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    extra_headers: dict[str, str] | None = None,
    now: datetime.datetime | None = None,
) -> dict[str, str]:
    """Return SigV4 headers for STS:GetCallerIdentity."""
    now = now or datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    svc = "sts"

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    canonical_uri = urllib.parse.quote(parsed.path or "/", safe="/")
    canonical_qs = _canonical_qs(parsed.query)

    # ---------- headers (lower-case keys) ----------
    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-snowflake-audience": "snowflakecomputing.com",
    }
    if session_token:
        headers["x-amz-security-token"] = session_token
    if extra_headers:
        for k, v in extra_headers.items():
            headers[k.lower()] = v.strip()

    # CanonicalHeaders & SignedHeaders
    sorted_hdrs = sorted((k, " ".join(v.split())) for k, v in headers.items())
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted_hdrs)
    signed_headers = ";".join(k for k, _ in sorted_hdrs)

    canonical_request = "\n".join(
        [
            "POST",
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            _EMPTY_HASH,
        ]
    )
    hash_canonical = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

    # ---------- string to sign ----------
    scope = f"{date_stamp}/{region}/{svc}/aws4_request"
    string_to_sign = "\n".join([_ALGO, amz_date, scope, hash_canonical])

    # ---------- signing key ----------
    k_date = _hmac(("AWS4" + secret_key).encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, svc)
    k_signing = _hmac(k_service, "aws4_request")

    signature = hmac.new(
        k_signing, string_to_sign.encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization = (
        f"{_ALGO} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    # ---------- final headers ----------
    headers["authorization"] = authorization
    headers["x-amz-content-sha256"] = _EMPTY_HASH
    # canonicalisation used lower-case; restore Host capitalisation if desired
    return {k.title() if k == "host" else k: v for k, v in headers.items()}
