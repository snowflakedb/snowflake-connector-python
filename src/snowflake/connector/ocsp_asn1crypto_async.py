#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from .ocsp_asn1crypto import SnowflakeOCSPAsn1Crypto
from .ocsp_snowflake_async import SnowflakeOCSPAsync


# YICHUAN: Prioritize methods inherited SnowflakeOCSPAsync because it will only override what it needs to
class SnowflakeOCSPAsn1CryptoAsync(SnowflakeOCSPAsync, SnowflakeOCSPAsn1Crypto):
    pass
