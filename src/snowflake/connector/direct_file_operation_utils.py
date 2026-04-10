from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .connection import SnowflakeConnection

import os
from abc import ABC, abstractmethod

from .constants import CMD_TYPE_UPLOAD


class FileOperationParserBase(ABC):
    """The interface of internal utility functions for file operation parsing."""

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
        pass


class StreamDownloaderBase(ABC):
    """The interface of internal utility functions for stream downloading of file."""

    @abstractmethod
    def __init__(self, connection):
        pass

    @abstractmethod
    def download_as_stream(self, ret, decompress=False):
        pass


class FileOperationParser(FileOperationParserBase):
    def __init__(self, connection: SnowflakeConnection):
        self._connection = connection

    def parse_file_operation(
        self,
        stage_location,
        local_file_name,
        target_directory,
        command_type,
        options,
        has_source_from_stream=False,
    ):
        """Parses a file operation by constructing SQL and getting the SQL parsing result from server."""
        options = options or {}
        options_in_sql = " ".join(f"{k}={v}" for k, v in options.items())

        if command_type == CMD_TYPE_UPLOAD:
            if has_source_from_stream:
                stage_location, unprefixed_local_file_name = os.path.split(
                    stage_location
                )
                local_file_name = "file://" + unprefixed_local_file_name
            sql = f"PUT {local_file_name} ? {options_in_sql}"
            params = [stage_location]
        else:
            raise NotImplementedError(f"unsupported command type: {command_type}")

        with self._connection.cursor() as cursor:
            # Send constructed SQL to server and get back parsing result.
            processed_params = cursor._connection._process_params_qmarks(params, cursor)
            return cursor._execute_helper(
                sql, binding_params=processed_params, is_internal=True
            )


class StreamDownloader(StreamDownloaderBase):
    def __init__(self, connection):
        pass

    def download_as_stream(self, ret, decompress=False):
        raise NotImplementedError("download_as_stream is not yet supported")
