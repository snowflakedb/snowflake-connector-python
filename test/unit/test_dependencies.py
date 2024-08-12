#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

import warnings

import cryptography.utils
import pytest


@pytest.mark.xfail(reason="Deprecation warning is expected to fail the test")
def test_cryptography_deprecated():
    deprecate_warning = cryptography.utils.deprecated(
        cryptography.utils.CryptographyDeprecationWarning,
        "test",
        "test",
        cryptography.utils.CryptographyDeprecationWarning,
    )
    warnings.warn(
        deprecate_warning.message, deprecate_warning.warning_class, stacklevel=2
    )
