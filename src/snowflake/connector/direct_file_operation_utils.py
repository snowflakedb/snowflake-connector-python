from __future__ import annotations

from abc import ABC, abstractmethod


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
    def __init__(self, connection):
        pass

    def parse_file_operation(
        self,
        stage_location,
        local_file_name,
        target_directory,
        command_type,
        options,
        has_source_from_stream=False,
    ):
        raise NotImplementedError("parse_file_operation is not yet supported")


class StreamDownloader(StreamDownloaderBase):
    def __init__(self, connection):
        pass

    def download_as_stream(self, ret, decompress=False):
        raise NotImplementedError("download_as_stream is not yet supported")
