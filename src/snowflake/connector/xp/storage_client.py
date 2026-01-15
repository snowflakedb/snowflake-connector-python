"""XP Storage Client.

This module provides file transfer implementation for Snowflake's Execution Platform (XP)
using _sfstream for direct stage access instead of cloud storage APIs.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

from ..constants import ResultStatus

if TYPE_CHECKING:
    from ..file_transfer_agent import SnowflakeFileMeta

logger = logging.getLogger(__name__)


class XPStorageClient:
    """Storage client for XP that uses _sfstream for file operations."""

    def __init__(
        self,
        meta: SnowflakeFileMeta,
        stage_info: dict[str, Any],
        chunk_size: int,
        credentials=None,
        unsafe_file_write: bool = False,
    ) -> None:
        """Initialize XP storage client.

        Args:
            meta: File metadata
            stage_info: Stage information from server
            chunk_size: Size of chunks for transfer
            credentials: Credentials (not used in XP)
            unsafe_file_write: Whether to skip file permission checks
        """
        self.meta = meta
        self._stage_info = stage_info
        self._chunk_size = chunk_size
        self._credentials = credentials
        self._unsafe_file_write = unsafe_file_write

        self.num_of_chunks = 1  # XP handles chunking internally
        self.successful_transfers = 0
        self.failed_transfers = 0

        import threading

        self.lock = threading.Lock()

        # Import XP modules
        try:
            import _sfstream

            self._sfstream = _sfstream
            self._FileType = _sfstream.FileType
            self._Mode = _sfstream.Mode
        except ImportError as e:
            raise RuntimeError(
                "XPStorageClient can only be used within Snowflake XP environment"
            ) from e

    def prepare_upload(self) -> None:
        """Prepare file for upload."""
        try:
            logger.debug(f"Preparing upload for {self.meta.name}")

            # Check if file exists and needs upload
            if not self.meta.overwrite:
                # Check if file already exists in stage
                # For now, we assume we need to upload
                pass

            self.meta.result_status = ResultStatus.UPLOADED

        except Exception as e:
            logger.error(f"Failed to prepare upload: {e}", exc_info=True)
            self.meta.last_error = e
            self.meta.error_details = e
            self.meta.result_status = ResultStatus.ERROR
            raise

    def upload_chunk(self, chunk_id: int) -> None:
        """Upload a file chunk via _sfstream.

        Args:
            chunk_id: ID of the chunk to upload (0-based)
        """
        try:
            logger.debug(f"Uploading chunk {chunk_id} of {self.meta.name}")

            # Construct stage path
            stage_path = self._get_stage_path()

            # Open stream for writing
            stream = self._sfstream.SfStream(
                stage_path,
                file_type=self._FileType.STAGE,
                mode=self._Mode.WRITE,
                rso_id=self._get_rso_id(),
            )

            # Write file content
            if self.meta.intermediate_stream:
                # Upload from stream
                self.meta.intermediate_stream.seek(0)
                data = self.meta.intermediate_stream.read()
                stream.write(data)
            elif self.meta.src_file_name:
                # Upload from file
                with open(self.meta.src_file_name, "rb") as f:
                    data = f.read()
                    stream.write(data)

            stream.close()

            logger.debug(f"Successfully uploaded {self.meta.name}")

        except Exception as e:
            logger.error(f"Failed to upload chunk: {e}", exc_info=True)
            self.meta.last_error = e
            self.meta.error_details = e
            raise

    def finish_upload(self) -> None:
        """Finalize upload."""
        try:
            if self.failed_transfers > 0:
                self.meta.result_status = ResultStatus.ERROR
            else:
                self.meta.result_status = ResultStatus.UPLOADED
                self.meta.dst_file_size = self.meta.src_file_size

        except Exception as e:
            logger.error(f"Failed to finish upload: {e}", exc_info=True)
            self.meta.result_status = ResultStatus.ERROR
            self.meta.error_details = e

    def delete_client_data(self) -> None:
        """Clean up client data."""
        # No cleanup needed for XP

    def prepare_download(self) -> None:
        """Prepare file for download."""
        try:
            logger.debug(f"Preparing download for {self.meta.name}")
            self.meta.result_status = ResultStatus.DOWNLOADED

        except Exception as e:
            logger.error(f"Failed to prepare download: {e}", exc_info=True)
            self.meta.last_error = e
            self.meta.error_details = e
            self.meta.result_status = ResultStatus.ERROR
            raise

    def download_chunk(self, chunk_id: int) -> None:
        """Download a file chunk via _sfstream.

        Args:
            chunk_id: ID of the chunk to download (0-based)
        """
        try:
            logger.debug(f"Downloading chunk {chunk_id} of {self.meta.name}")

            # Construct stage path
            stage_path = self._get_stage_path()

            # Open stream for reading
            stream = self._sfstream.SfStream(
                stage_path,
                file_type=self._FileType.STAGE,
                mode=self._Mode.READ,
                rso_id=self._get_rso_id(),
            )

            # Read file content
            data = stream.read()
            stream.close()

            # Store in temporary location
            self._downloaded_data = data

            logger.debug(f"Successfully downloaded {self.meta.name}")

        except Exception as e:
            logger.error(f"Failed to download chunk: {e}", exc_info=True)
            self.meta.last_error = e
            self.meta.error_details = e
            raise

    def finish_download(self) -> None:
        """Finalize download by writing to local file."""
        try:
            if self.failed_transfers > 0:
                self.meta.result_status = ResultStatus.ERROR
                return

            # Write downloaded data to file
            if hasattr(self, "_downloaded_data"):
                output_path = os.path.join(
                    self.meta.local_location,
                    self.meta.dst_file_name,
                )

                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                with open(output_path, "wb") as f:
                    f.write(self._downloaded_data)

                self.meta.dst_file_size = len(self._downloaded_data)
                self.meta.result_status = ResultStatus.DOWNLOADED

                del self._downloaded_data

        except Exception as e:
            logger.error(f"Failed to finish download: {e}", exc_info=True)
            self.meta.result_status = ResultStatus.ERROR
            self.meta.error_details = e

    def _get_stage_path(self) -> str:
        """Get the full stage path for the file."""
        location = self._stage_info.get("location", "")

        if self.meta.stage_location_type == "UPLOAD":
            # For uploads, use dst_file_name
            file_name = self.meta.dst_file_name or self.meta.name
        else:
            # For downloads, use src_file_name
            file_name = self.meta.src_file_name

        # Combine location and filename
        if location:
            return f"{location}/{file_name}"
        return file_name

    def _get_rso_id(self) -> str | None:
        """Get RSO ID from stage info if available."""
        return self._stage_info.get("rsoId")

    def download_as_stream(self, decompress: bool = False):
        """Download file as a stream.

        Args:
            decompress: Whether to decompress the stream

        Returns:
            IO stream for reading
        """
        try:
            stage_path = self._get_stage_path()

            stream = self._sfstream.SfStream(
                stage_path,
                file_type=self._FileType.STAGE,
                mode=self._Mode.READ,
                rso_id=self._get_rso_id(),
            )

            if decompress:
                import gzip
                import io

                data = stream.read()
                stream.close()
                return io.BytesIO(gzip.decompress(data))

            return stream

        except Exception as e:
            logger.error(f"Failed to download as stream: {e}", exc_info=True)
            raise
