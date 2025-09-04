#!/usr/bin/env python
from __future__ import annotations

import hashlib
import logging
import os
import platform
import threading
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from filelock import BaseFileLock, FileLock
from typing_extensions import Self

logger = logging.getLogger(__name__)


@dataclass
class CRLCacheEntry:
    """Cache entry containing a CRL and its download timestamp."""

    crl: x509.CertificateRevocationList
    download_time: datetime

    def _next_update(self) -> datetime | None:
        """A compatibility wrapper around crl.next_update."""
        return getattr(self.crl, "next_update_utc", None) or getattr(
            self.crl, "next_update", None
        )

    def is_crl_expired_by(self, ts: datetime) -> bool:
        """
        Check if the CRL has expired.

        Args:
            ts: Time to check against

        Returns:
            True if the CRL has expired, False otherwise
        """
        next_update = self._next_update()
        return next_update is not None and next_update < ts

    def is_evicted_by(self, ts: datetime, cache_validity_time: timedelta) -> bool:
        """
        Check if the cache entry should be evicted based on cache validity time.

        Args:
            ts: Current time to check against
            cache_validity_time: How long cache entries remain valid

        Returns:
            True if the entry should be evicted, False otherwise
        """
        expiry_time = self.download_time + cache_validity_time
        return expiry_time < ts


class CRLCache(ABC):
    """
    Abstract base class for CRL caches.
    """

    @abstractmethod
    def get(self, crl_url: str) -> CRLCacheEntry | None:
        """
        Get a CRL cache entry by URL.

        Args:
            crl_url: The CRL URL

        Returns:
            The cache entry if found, None otherwise
        """
        raise NotImplementedError()

    @abstractmethod
    def put(self, crl_url: str, entry: CRLCacheEntry) -> None:
        """
        Store a CRL cache entry.

        Args:
            crl_url: The CRL URL
            entry: The cache entry to store
        """
        raise NotImplementedError()

    @abstractmethod
    def cleanup(self) -> None:
        """Remove expired and evicted entries from the cache."""
        raise NotImplementedError()


class NoopCRLCache(CRLCache):
    """
    No-operation CRL cache that doesn't store anything.
    """

    # Singleton instance
    INSTANCE = None

    def __new__(cls):
        if cls.INSTANCE is None:
            cls.INSTANCE = super().__new__(cls)
        return cls.INSTANCE

    def get(self, crl_url: str) -> CRLCacheEntry | None:
        """Always returns None."""
        return None

    def put(self, crl_url: str, entry: CRLCacheEntry) -> None:
        """Does nothing."""
        pass

    def cleanup(self) -> None:
        """Does nothing."""
        pass


class CRLInMemoryCache(CRLCache):
    """
    In-memory CRL cache using a thread-safe dictionary.
    """

    def __init__(self, cache_validity_time: timedelta):
        """
        Initialize the in-memory cache.

        Args:
            cache_validity_time: How long cache entries remain valid
        """
        self._cache: dict[str, CRLCacheEntry] = {}
        self._cache_validity_time = cache_validity_time
        self._lock = threading.RLock()

    def get(self, crl_url: str) -> CRLCacheEntry | None:
        """
        Get a CRL cache entry from memory.

        Args:
            crl_url: The CRL URL

        Returns:
            The cache entry if found, None otherwise
        """
        with self._lock:
            entry = self._cache.get(crl_url)
            if entry is not None:
                logger.debug(f"Found CRL in memory cache for {crl_url}")
            return entry

    def put(self, crl_url: str, entry: CRLCacheEntry) -> None:
        """
        Store a CRL cache entry in memory.

        Args:
            crl_url: The CRL URL
            entry: The cache entry to store
        """
        with self._lock:
            self._cache[crl_url] = entry

    def cleanup(self) -> None:
        """Remove expired and evicted entries from memory cache."""
        now = datetime.now(UTC)
        logger.debug(f"Cleaning up in-memory CRL cache at {now}")

        with self._lock:
            urls_to_remove = []

            for url, entry in self._cache.items():
                expired = entry.is_crl_expired_by(now)
                evicted = entry.is_evicted_by(now, self._cache_validity_time)

                if expired or evicted:
                    logger.debug(
                        f"Removing in-memory CRL cache entry for {url}: "
                        f"expired={expired}, evicted={evicted}"
                    )
                    urls_to_remove.append(url)

            for url in urls_to_remove:
                del self._cache[url]

            removed_count = len(urls_to_remove)
            if removed_count > 0:
                logger.debug(
                    f"Removed {removed_count} expired/evicted entries from in-memory CRL cache"
                )


class CRLFileCache(CRLCache):
    """
    File-based CRL cache that persists CRLs to disk.
    """

    def __init__(
        self, cache_dir: Path | None = None, removal_delay: timedelta | None = None
    ):
        """
        Initialize the file cache.

        Args:
            cache_dir: Directory to store cached CRLs
            removal_delay: How long to wait before removing expired files

        Raises:
            OSError: If cache directory cannot be created
        """
        self._cache_file_lock_timeout = 5.0
        self._cache_dir = cache_dir or _get_default_crl_cache_path()
        self._removal_delay = removal_delay or timedelta(days=7)

        self._ensure_cache_directory_exists()

    def _ensure_cache_directory_exists(self) -> None:
        """Create the cache directory if it doesn't exist."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory created/verified: {self._cache_dir}")
        except OSError as e:
            raise OSError(f"Failed to create cache directory {self._cache_dir}: {e}")

    def _get_crl_file_path(self, crl_url: str) -> Path:
        """
        Generate a file path for the given CRL URL.

        Args:
            crl_url: The CRL URL

        Returns:
            Path to the cache file
        """
        # Create a safe filename from the URL using a hash
        url_hash = hashlib.sha256(crl_url.encode()).hexdigest()
        return self._cache_dir / f"crl_{url_hash}.der"

    def _get_crl_file_lock(self, crl_cache_file: Path) -> BaseFileLock:
        """Return a lock instance for the given CRL cache file"""
        return FileLock(
            crl_cache_file.with_suffix(".lock"),
            thread_local=True,
            timeout=self._cache_file_lock_timeout,
        )

    def get(self, crl_url: str) -> CRLCacheEntry | None:
        """
        Get a CRL cache entry from disk.

        Args:
            crl_url: The CRL URL

        Returns:
            The cache entry if found, None otherwise
        """
        crl_file_path = self._get_crl_file_path(crl_url)
        with self._get_crl_file_lock(crl_file_path):
            try:
                if crl_file_path.exists():
                    logger.debug(f"Found CRL on disk for {crl_file_path}")

                    # Get file modification time as download time
                    stat_info = crl_file_path.stat()
                    download_time = datetime.fromtimestamp(stat_info.st_mtime, tz=UTC)

                    # Read and parse the CRL
                    with open(crl_file_path, "rb") as f:
                        crl_data = f.read()

                    crl = x509.load_der_x509_crl(crl_data, backend=default_backend())
                    return CRLCacheEntry(crl, download_time)

            except Exception as e:
                logger.warning(f"Failed to read CRL from disk cache for {crl_url}: {e}")

        return None

    def put(self, crl_url: str, entry: CRLCacheEntry) -> None:
        """
        Store a CRL cache entry to disk.

        Args:
            crl_url: The CRL URL
            entry: The cache entry to store
        """
        crl_file_path = self._get_crl_file_path(crl_url)
        with self._get_crl_file_lock(crl_file_path):
            try:
                # Serialize the CRL to DER format
                crl_data = entry.crl.public_bytes(serialization.Encoding.DER)

                # Write to file
                with open(crl_file_path, "wb") as f:
                    f.write(crl_data)

                # Set file modification time to download time
                download_timestamp = entry.download_time.timestamp()
                os.utime(crl_file_path, (download_timestamp, download_timestamp))

                logger.debug(f"Stored CRL to disk cache: {crl_file_path}")

            except Exception as e:
                logger.warning(f"Failed to write CRL to disk cache for {crl_url}: {e}")

    def _is_cached_crl_file_for_removal(
        self, crl_cache_file: Path, ts: datetime
    ) -> bool:
        """Check if the given CRL cache file is by its lifetime."""
        try:
            # Get file modification time
            stat_info = crl_cache_file.stat()
            download_time = datetime.fromtimestamp(stat_info.st_mtime, tz=UTC)

            # Check if file should be removed based on removal delay
            removal_time = download_time + self._removal_delay
            return ts > removal_time
        except Exception as e:
            logger.warning(f"Error processing cache file {crl_cache_file}: {e}")
            return False

    def cleanup(self) -> None:
        """Remove expired files from disk cache."""
        now = datetime.now(UTC)
        logger.debug(f"Cleaning up file-based CRL cache at {now}")

        removed_count = 0
        try:
            for crl_file in self._cache_dir.glob("crl_*.der"):
                # double-checked locking
                if self._is_cached_crl_file_for_removal(crl_file, now):
                    with self._get_crl_file_lock(crl_file):
                        if self._is_cached_crl_file_for_removal(crl_file, now):
                            crl_file.unlink(missing_ok=True)
                            removed_count += 1
                            logger.debug(f"Removed expired file: {crl_file}")
        except Exception as e:
            logger.error(f"Error during file cache cleanup: {e}")


class CRLCacheManager:
    """
    Cache manager that coordinates between in-memory and file-based CRL caches.

    Provides automatic cleanup of expired entries and proper lifecycle management.
    """

    def __init__(
        self,
        memory_cache: CRLCache,
        file_cache: CRLCache,
        cleanup_interval: timedelta,
        start_cleanup: bool = False,
    ):
        """
        Initialize the cache manager.

        Args:
            memory_cache: In-memory cache implementation
            file_cache: File-based cache implementation
            cleanup_interval: How often to run cleanup tasks
            start_cleanup: If true, immediately starts periodic cache cleanup background task
        """
        self._memory_cache = memory_cache
        self._file_cache = file_cache
        self._cleanup_interval = cleanup_interval
        self._cleanup_executor: ThreadPoolExecutor | None = None
        self._cleanup_shutdown: threading.Event = threading.Event()
        if start_cleanup:
            self.start_periodic_cleanup()

    @classmethod
    def noop(cls) -> CRLCacheManager:
        """Create noop cache manager."""
        return cls(NoopCRLCache(), NoopCRLCache(), timedelta(seconds=0), False)

    def get(self, crl_url: str) -> CRLCacheEntry | None:
        """
        Get a CRL cache entry, checking memory cache first, then file cache.

        Args:
            crl_url: The CRL URL

        Returns:
            The cache entry if found, None otherwise
        """
        # Check memory cache first
        entry = self._memory_cache.get(crl_url)
        if entry is not None:
            return entry

        # Check file cache
        entry = self._file_cache.get(crl_url)
        if entry is not None:
            # Promote to memory cache
            self._memory_cache.put(crl_url, entry)
            return entry

        logger.debug(f"CRL not found in cache for {crl_url}")
        return None

    def put(
        self, crl_url: str, crl: x509.CertificateRevocationList, download_time: datetime
    ) -> None:
        """
        Store a CRL in both memory and file caches.

        Args:
            crl_url: The CRL URL
            crl: The CRL to store
            download_time: When the CRL was downloaded
        """
        entry = CRLCacheEntry(crl, download_time)
        self._memory_cache.put(crl_url, entry)
        self._file_cache.put(crl_url, entry)

    def start_periodic_cleanup(self) -> None:
        """Start the periodic cleanup task."""
        if self.is_periodic_cleanup_running():
            logger.debug(
                "Periodic cleanup already running, so it first be stopped before restarting."
            )
            self.stop_periodic_cleanup()

        self._cleanup_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="crl-cache-cleanup"
        )

        # Submit the cleanup task
        self._cleanup_executor.submit(self._cleanup_loop)

        logger.debug(
            f"Scheduled CRL cache cleanup task to run every {self._cleanup_interval.total_seconds()} seconds."
        )

    def stop_periodic_cleanup(self) -> None:
        """Stop the periodic cleanup task."""
        if self._cleanup_executor is None or self._cleanup_shutdown.is_set():
            return

        self._cleanup_shutdown.set()
        self._cleanup_executor.shutdown(wait=True)
        self._cleanup_shutdown.clear()
        self._cleanup_executor = None

    def is_periodic_cleanup_running(self) -> bool:
        """Check if periodic cleanup task is running."""
        return self._cleanup_executor is not None

    def _cleanup_loop(self) -> None:
        """Main cleanup loop that runs periodically."""
        while not self._cleanup_shutdown.is_set():
            logger.debug(
                f"Running periodic CRL cache cleanup with interval {self._cleanup_interval.total_seconds()} seconds"
            )
            try:
                self._memory_cache.cleanup()
            except Exception as e:
                logger.error(
                    f"An error occurred during scheduled CRL memory cache cleanup: {e}"
                )
            try:
                self._file_cache.cleanup()
            except Exception as e:
                logger.error(
                    f"An error occurred during scheduled CRL disk cache cleanup: {e}"
                )

            shutdown = self._cleanup_shutdown.wait(
                timeout=self._cleanup_interval.total_seconds()
            )
            if shutdown:
                logger.debug(
                    "CRL cache cleanup stopped gracefully by a shutdown event."
                )
                break

    def __del__(self):
        """Cleanup when the object is destroyed."""
        self.stop_periodic_cleanup()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """

        :param exc_type: the exception type if raised
        :param exc_value: the exception value if raised
        :param traceback: the exception traceback if raised

        """
        # To guarantee stopping the periodic background cleanup task
        self.stop_periodic_cleanup()


def _get_default_crl_cache_path() -> Path:
    """Return the default path to persist cached CRLs."""
    if platform.system() == "Windows":
        return Path.home() / "AppData" / "Local" / "Snowflake" / "Caches" / "crls"
    elif platform.system() == "Darwin":
        return Path.home() / "Library" / "Caches" / "Snowflake" / "crls"
    else:
        return Path.home() / ".cache" / "Snowflake" / "crls"
