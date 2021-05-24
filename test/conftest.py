#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2021 Snowflake Computing Inc. All right reserved.
#

import os
from logging import getLogger
from pathlib import Path

import pytest

from . import CLOUD_PROVIDERS, PUBLIC_SKIP_TAGS, running_on_public_ci


def pytest_collection_modifyitems(items) -> None:
    """Applies tags to tests based on folders that they are in."""
    top_test_dir = Path(__file__).parent
    for item in items:
        item_path = Path(str(item.fspath)).parent
        relative_path = item_path.relative_to(top_test_dir)
        for part in relative_path.parts:
            item.add_marker(part)
            if part in ("unit", "pandas"):
                item.add_marker("skipolddriver")


@pytest.fixture(scope="session", autouse=True)
def filter_log() -> None:
    """Sets up our SecretDetector as a logging formatter.

    A workaround to use our custom Formatter in pytest based on the discussion at
    https://github.com/pytest-dev/pytest/issues/2987
    """
    import logging
    import pathlib

    from snowflake.connector.secret_detector import SecretDetector

    if not isinstance(SecretDetector, logging.Formatter):
        # Override it if SecretDetector is not an instance of logging.Formatter
        class SecretDetector(logging.Formatter):
            def format(self, record: logging.LogRecord) -> str:
                return super().format(record)

    log_dir = os.getenv(
        "CLIENT_LOG_DIR_PATH_DOCKER", str(pathlib.Path(__file__).parent.absolute())
    )

    _logger = getLogger("snowflake.connector")
    original_log_level = _logger.getEffectiveLevel()
    # Make sure that the old handlers are unaffected by the DEBUG level set for the new handler
    for handler in _logger.handlers:
        handler.setLevel(original_log_level)
    _logger.setLevel(logging.DEBUG)
    sd = logging.FileHandler(os.path.join(log_dir, "", "..", "snowflake_ssm_rt.log"))
    sd.setLevel(logging.DEBUG)
    sd.setFormatter(
        SecretDetector(
            "%(asctime)s - %(threadName)s %(filename)s:%(lineno)d - %(funcName)s() - %(levelname)s - %(message)s"
        )
    )
    _logger.addHandler(sd)


def pytest_runtest_setup(item) -> None:
    """Ran before calling each test, used to decide whether a test should be skipped."""
    test_tags = [mark.name for mark in item.iter_markers()]

    # Get what cloud providers the test is marked for if any
    test_supported_providers = CLOUD_PROVIDERS.intersection(test_tags)
    # Default value means that we are probably running on a developer's machine, allow everything in this case
    current_provider = os.getenv("cloud_provider", "dev")
    if test_supported_providers:
        # If test is tagged for specific cloud providers add the default cloud_provider as supported too
        test_supported_providers.add("dev")
        if current_provider not in test_supported_providers:
            pytest.skip(
                "cannot run unit test against cloud provider {}".format(
                    current_provider
                )
            )
    if PUBLIC_SKIP_TAGS.intersection(test_tags) and running_on_public_ci():
        pytest.skip("cannot run unit test on public CI")
