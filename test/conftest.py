#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#
import os
from pathlib import Path

import pytest

from . import running_on_public_ci

CLOUD_PROVIDERS = {'aws', 'azure', 'gcp'}
PUBLIC_SKIP_TAGS = {'internal'}


def pytest_collection_modifyitems(items) -> None:
    """Applies tags to tests based on folders that they are in."""
    top_test_dir = Path(__file__).parent
    for item in items:
        item_path = Path(str(item.fspath)).parent
        relative_path = item_path.relative_to(top_test_dir)
        for part in relative_path.parts:
            item.add_marker(part)
            if part in ('unit', 'pandas'):
                item.add_marker('skipolddriver')


def pytest_runtest_setup(item) -> None:
    """Ran before calling each test, used to decide whether a test should be skipped."""
    test_tags = [mark.name for mark in item.iter_markers()]

    # Get what cloud providers the test is marked for if any
    test_supported_providers = CLOUD_PROVIDERS.intersection(test_tags)
    # Default value means that we are probably running on a developer's machine, allow everything in this case
    current_provider = os.getenv('cloud_provider', 'dev')
    if test_supported_providers:
        # If test is tagged for specific cloud providers add the default cloud_provider as supported too
        test_supported_providers.add('dev')
        if current_provider not in test_supported_providers:
            pytest.skip("cannot run unit test against cloud provider {}".format(current_provider))
    if PUBLIC_SKIP_TAGS.intersection(test_tags) and running_on_public_ci():
        pytest.skip("cannot run unit test on public CI")
