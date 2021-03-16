#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

# This file houses functions and constants shared by both integration and unit tests
import os

CLOUD_PROVIDERS = {"aws", "azure", "gcp"}
PUBLIC_SKIP_TAGS = {"internal"}
RUNNING_ON_GH = os.getenv("GITHUB_ACTIONS") == "true"


def running_on_public_ci() -> bool:
    """Whether or not tests are currently running on one of our public CIs."""
    return RUNNING_ON_GH
