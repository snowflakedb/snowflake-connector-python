#
# Copyright (c) 2012-2023 Snowflake Computing Inc. All rights reserved.
#

from __future__ import annotations

from abc import ABC, abstractmethod

from src.snowflake.connector import NotSupportedError


class FileOperationParserBase(ABC):
    """Provide internal utility functions for file operation parsing."""

    @abstractmethod
    def __init__(self, connection):
        pass

    @abstractmethod
    def parse_file_operation(
        self,
        stage_location,
        local_file_name,
        target_directory,
        command_type,
        options,
        has_source_from_stream=False,
    ):
        """Converts the file operation details into a SQL and returns the SQL parsing result."""
        raise NotSupportedError


class StreamDownloaderBase(ABC):
    @abstractmethod
    def __init__(self, connection):
        pass

    @abstractmethod
    def download_as_stream(self, ret, decompress=False):
        raise NotSupportedError
