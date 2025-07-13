from __future__ import annotations

import datetime as _dt
import hashlib as _hashlib
import hmac as _hmac
import urllib.parse as _urlparse

_ALGORITHM: str = "AWS4-HMAC-SHA256"
_EMPTY_PAYLOAD_SHA256: str = _hashlib.sha256(b"").hexdigest()
_SAFE_CHARS: str = "-_.~"


def _sign(key: bytes, msg: str) -> bytes:
    """Return an HMAC-SHA256 of *msg* keyed with *key*."""
    return _hmac.new(key, msg.encode(), _hashlib.sha256).digest()


def _canonical_query_string(query: str) -> str:
    """Return the query string in canonical (sorted & URL-escaped) form."""
    pairs = _urlparse.parse_qsl(query, keep_blank_values=True)
    pairs.sort()
    return "&".join(
        f"{_urlparse.quote(k, _SAFE_CHARS)}={_urlparse.quote(v, _SAFE_CHARS)}"
        for k, v in pairs
    )


def sign_get_caller_identity(
    url: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
) -> dict[str, str]:
    """
    Return the SigV4 headers needed for a presigned POST to AWS STS
    `GetCallerIdentity`.

    Parameters:

    url
        The full STS endpoint with query parameters
        (e.g. ``https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15``)
    region
        The AWS region used for signing (``us-east-1``, ``us-gov-west-1`` …).
    access_key
        AWS access-key ID.
    secret_key
        AWS secret-access key.
    session_token
        (Optional) session token for temporary credentials.
    """
    timestamp = _dt.datetime.utcnow()
    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    short_date = timestamp.strftime("%Y%m%d")
    service = "sts"

    parsed = _urlparse.urlparse(url)

    headers: dict[str, str] = {
        "host": parsed.netloc.lower(),
        "x-amz-date": amz_date,
        "x-snowflake-audience": "snowflakecomputing.com",
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    # Canonical request
    signed_headers = ";".join(sorted(headers))  # e.g. host;x-amz-date;...
    canonical_request = "\n".join(
        (
            "POST",
            _urlparse.quote(parsed.path or "/", safe="/"),
            _canonical_query_string(parsed.query),
            "".join(f"{k}:{headers[k]}\n" for k in sorted(headers)),
            signed_headers,
            _EMPTY_PAYLOAD_SHA256,
        )
    )
    canonical_request_hash = _hashlib.sha256(canonical_request.encode()).hexdigest()

    # String to sign
    credential_scope = f"{short_date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        (_ALGORITHM, amz_date, credential_scope, canonical_request_hash)
    )

    # Signature
    key_date = _sign(("AWS4" + secret_key).encode(), short_date)
    key_region = _sign(key_date, region)
    key_service = _sign(key_region, service)
    key_signing = _sign(key_service, "aws4_request")
    signature = _hmac.new(
        key_signing, string_to_sign.encode(), _hashlib.sha256
    ).hexdigest()

    # Final Authorization header
    headers["authorization"] = (
        f"{_ALGORITHM} "
        f"Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={signature}"
    )

    return headers
