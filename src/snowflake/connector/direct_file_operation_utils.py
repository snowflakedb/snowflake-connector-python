from __future__ import annotations

from typing import TYPE_CHECKING

from .errors import NotSupportedError

if TYPE_CHECKING:
    from .connection import SnowflakeConnection

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

    def _process_options_for_upload(self, options):
        """Processes the options dict returns the qmark SQL and corresponding bind values.
        Args:
            options (dict): the options dict
        Returns:
            a tuple of the qmark SQL and corresponding bind values.
        """
        options = options or {}

        options_in_sql_raw = []
        option_bind_values = []

        for k, v in options.items():
            # Check that all option names are all valid identifiers for better safety.
            if not k.isidentifier():
                raise NotSupportedError(f"unsupported option {k}")
            # Pass option value in binds for better safety.
            option_bind_values.append(v)
            options_in_sql_raw.append(f"{k}=?")
        options_in_sql = " ".join(options_in_sql_raw)

        return options_in_sql, option_bind_values

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
        options_in_sql, option_bind_values = self._process_options_for_upload(options)

        if command_type == CMD_TYPE_UPLOAD:
            if has_source_from_stream:
                assert (
                    local_file_name is None
                ), "local_file_name shall be derived from stage_location for stream uploading."
                stage_location, unprefixed_local_file_name = stage_location.rsplit(
                    "/", maxsplit=1
                )
                local_file_name = "file://" + unprefixed_local_file_name
            # Escape single quotes.
            local_file_name = local_file_name.replace("'", "''")
            # Enclose local_file_name with single quotes and pass stage path by a bind for better safety.
            sql = f"PUT '{local_file_name}' ? {options_in_sql}"
            params = [stage_location, *option_bind_values]
        else:
            raise NotSupportedError(f"unsupported command type: {command_type}")

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
        raise NotSupportedError("download_as_stream is not yet supported")
