#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2012-2020 Snowflake Computing Inc. All right reserved.
#

from pathlib import Path


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
