# wif_util/sign_v4.py
from __future__ import annotations

import datetime
import hashlib
import hmac
import urllib.parse as _u

_ALGO = "AWS4-HMAC-SHA256"
_EMPTY_HASH = hashlib.sha256(b"").hexdigest()
_SAFE = "-_.~"


def _h(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _canonical_qs(qs: str) -> str:
    pairs = _u.parse_qsl(qs, keep_blank_values=True)
    pairs.sort()
    return "&".join(f"{_u.quote(k, _SAFE)}={_u.quote(v, _SAFE)}" for k, v in pairs)


def sign_get_caller_identity(url, region, access_key, secret_key, session_token=None):
    now = datetime.datetime.utcnow()
    amz_d = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    svc = "sts"

    p = _u.urlparse(url)
    hdrs = {
        "host": p.netloc.lower(),
        "x-amz-date": amz_d,
        "x-snowflake-audience": "snowflakecomputing.com",
        # "x-amz-content-sha256": _EMPTY_HASH,
    }
    if session_token:
        hdrs["x-amz-security-token"] = session_token

    # ----- canonical request -----
    signed = ";".join(sorted(hdrs))
    can_req = "\n".join(
        [
            "POST",
            _u.quote(p.path or "/", safe="/"),
            _canonical_qs(p.query),
            "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs)),
            signed,
            _EMPTY_HASH,
        ]
    )
    hash_can = hashlib.sha256(can_req.encode()).hexdigest()

    # ----- string to sign -----
    scope = f"{date}/{region}/{svc}/aws4_request"
    sts = "\n".join([_ALGO, amz_d, scope, hash_can])

    # ----- HMAC chain -----
    k = _h(("AWS4" + secret_key).encode(), date)
    k = _h(k, region)
    k = _h(k, svc)
    k = _h(k, "aws4_request")
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()

    hdrs["authorization"] = (
        f"{_ALGO} Credential={access_key}/{scope}, "
        f"SignedHeaders={signed}, Signature={sig}"
    )
    return hdrs
