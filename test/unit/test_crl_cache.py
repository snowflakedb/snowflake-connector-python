#!/usr/bin/env python
from __future__ import annotations

import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from snowflake.connector.crl_cache import (
    CRLCache,
    CRLCacheEntry,
    CRLCacheManager,
    CRLFileCache,
    CRLInMemoryCache,
    NoopCRLCache,
)


@pytest.fixture(scope="module")
def download_time():
    return datetime.now(timezone.utc) - timedelta(minutes=30)


@pytest.fixture(scope="module")
def noop_cache():
    return NoopCRLCache()


@pytest.fixture(scope="module")
def memory_cache():
    return CRLInMemoryCache(cache_validity_time=timedelta(hours=1))


@pytest.fixture(scope="module")
def disk_cache():
    with tempfile.TemporaryDirectory() as temp_dir:
        yield CRLFileCache(Path(temp_dir), timedelta(hours=1))


@pytest.fixture(scope="function")
def mem_cache_mock():
    return Mock(spec=CRLCache)


@pytest.fixture(scope="function")
def disk_cache_mock():
    return Mock(spec=CRLCache)


@pytest.fixture(scope="function")
def cache_mgr(mem_cache_mock, disk_cache_mock):
    mgr = CRLCacheManager(mem_cache_mock, disk_cache_mock)
    yield mgr


@pytest.fixture(scope="function")
def cache_factory():
    """Fixture that provides CRLCacheFactory and ensures cleanup after each test."""
    from snowflake.connector.crl_cache import CRLCacheFactory

    yield CRLCacheFactory
    # Always reset the factory after each test to prevent test pollution
    CRLCacheFactory.reset()


@pytest.fixture(scope="module")
def crl_url(crl):
    return "http://test.com/crl"


@pytest.fixture(scope="module")
def crl() -> x509.CertificateRevocationList:
    """Create a test CRL"""
    # Generate a key pair for signing
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # Create a simple issuer name
    issuer = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")])

    # Build the CRL
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer)
    builder = builder.last_update(datetime.now(timezone.utc))
    builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=1))

    # Sign the CRL
    crl = builder.sign(private_key, hashes.SHA256(), backend=default_backend())
    return crl


@pytest.fixture(scope="module")
def cache_entry(crl, download_time) -> CRLCacheEntry:
    return CRLCacheEntry(crl, download_time)


def test_cache_entry_creation(crl, download_time):
    """Test creating a cache entry"""
    entry = CRLCacheEntry(crl, download_time)

    assert entry.crl == crl
    assert entry.download_time == download_time


def test_is_crl_expired_false_when_not_expired(cache_entry):
    """Test CRL expiration check when not expired"""
    now = datetime.now(timezone.utc)

    assert not cache_entry.is_crl_expired_by(now)


def test_is_evicted_false_when_not_evicted(crl, download_time):
    """Test cache eviction check when not evicted"""
    entry = CRLCacheEntry(crl, download_time)
    current_time = datetime.now(timezone.utc)
    cache_validity = timedelta(hours=24)

    assert not entry.is_evicted_by(current_time, cache_validity)


def test_is_evicted_true_when_evicted(crl, download_time):
    """Test cache eviction check when evicted"""
    old_download_time = datetime.now(timezone.utc) - timedelta(days=2)
    entry = CRLCacheEntry(crl, old_download_time)
    current_time = datetime.now(timezone.utc)
    cache_validity = timedelta(hours=1)  # Short validity period

    assert entry.is_evicted_by(current_time, cache_validity)


def test_noop_get_returns_none(crl, crl_url, download_time, noop_cache):
    """Test that get always returns None"""
    result = noop_cache.get(crl_url)
    assert result is None


def test_noop_put_does_nothing(crl, crl_url, download_time, noop_cache):
    """Test that put does nothing"""
    # Should not raise any exceptions
    noop_cache.put(crl_url, CRLCacheEntry(crl, download_time))


def test_noop_cleanup_does_nothing(noop_cache):
    """Test that cleanup does nothing"""
    # Should not raise any exceptions
    noop_cache.cleanup()


def test_noop_singleton_behavior():
    """Test that NoopCRLCache behaves as singleton"""
    cache1 = NoopCRLCache()
    cache2 = NoopCRLCache()
    assert cache1 is cache2


def test_memory_put_and_get(crl, crl_url, download_time, memory_cache):
    """Test storing and retrieving from memory cache"""
    download_time = datetime.now(timezone.utc)
    entry = CRLCacheEntry(crl, download_time)

    memory_cache.put(crl_url, entry)
    result = memory_cache.get(crl_url)

    assert result is not None
    assert result.download_time == download_time
    assert result.crl == crl


def test_memory_get_nonexistent_returns_none(memory_cache):
    """Test that getting non-existent entry returns None"""
    result = memory_cache.get("http://nonexistent.com/crl")
    assert result is None


def test_memory_cleanup_removes_evicted_entries(
    crl, crl_url, download_time, memory_cache
):
    """Test that cleanup removes evicted entries"""
    # Add an old entry that should be evicted
    old_time = datetime.now(timezone.utc) - timedelta(hours=2)
    old_entry = CRLCacheEntry(crl, old_time)
    memory_cache.put(crl_url, old_entry)
    assert memory_cache.get(crl_url) is not None

    memory_cache.cleanup()
    assert memory_cache.get(crl_url) is None


def test_disk_put_and_get(crl, crl_url, download_time, disk_cache):
    """Test storing and retrieving from file cache"""
    # download_time = datetime.now(timezone.utc)
    entry = CRLCacheEntry(crl, download_time)

    disk_cache.put(crl_url, entry)
    result = disk_cache.get(crl_url)

    assert result is not None
    # Note: CRL comparison might not work directly, so we check the type
    assert isinstance(result.crl, x509.CertificateRevocationList)
    # Download time might be slightly different due to file system precision
    assert abs(result.download_time.timestamp() - download_time.timestamp()) < 1.0


def test_disk_get_nonexistent_returns_none(crl, download_time, disk_cache):
    """Test that getting non-existent entry returns None"""
    result = disk_cache.get("http://nonexistent.com/crl")
    assert result is None


def test_should_return_cache_entry_when_memory_cache_hit(
    crl, crl_url, download_time, cache_entry, mem_cache_mock, disk_cache_mock, cache_mgr
):
    """Test returning cache entry when memory cache has it"""
    mem_cache_mock.get.return_value = cache_entry
    result = cache_mgr.get(crl_url)

    assert result is not None
    assert result.crl == crl
    assert result.download_time == download_time
    mem_cache_mock.get.assert_called_once_with(crl_url)
    disk_cache_mock.get.assert_not_called()


def test_should_promote_file_cache_hit_to_memory_cache(
    crl, crl_url, download_time, cache_entry, mem_cache_mock, disk_cache_mock, cache_mgr
):
    """Test promoting file cache hit to memory cache"""
    mem_cache_mock.get.return_value = None
    disk_cache_mock.get.return_value = cache_entry
    result = cache_mgr.get(crl_url)

    assert result is not None
    assert result.crl == crl
    assert result.download_time == download_time
    mem_cache_mock.get.assert_called_once_with(crl_url)
    disk_cache_mock.get.assert_called_once_with(crl_url)
    mem_cache_mock.put.assert_called_once_with(crl_url, cache_entry)


def test_should_return_none_when_both_caches_miss(
    crl, crl_url, download_time, mem_cache_mock, disk_cache_mock, cache_mgr
):
    """Test returning None when both caches miss"""
    mem_cache_mock.get.return_value = None
    disk_cache_mock.get.return_value = None

    result = cache_mgr.get(crl_url)

    assert result is None
    mem_cache_mock.get.assert_called_once_with(crl_url)
    disk_cache_mock.get.assert_called_once_with(crl_url)
    mem_cache_mock.put.assert_not_called()


def test_should_put_to_both_memory_and_file_cache(
    crl, crl_url, download_time, cache_entry, cache_mgr, mem_cache_mock, disk_cache_mock
):
    """Test putting to both memory and file cache"""
    cache_mgr.put(crl_url, crl, download_time)

    # Verify both caches were called
    mem_cache_mock.put.assert_called_once()
    disk_cache_mock.put.assert_called_once()

    # Check the arguments (entry should have correct CRL and time)
    mem_put_call_args = mem_cache_mock.put.call_args[0]
    disk_put_call_args = disk_cache_mock.put.call_args[0]

    assert mem_put_call_args == (crl_url, cache_entry)
    assert disk_put_call_args == (crl_url, cache_entry)


def test_should_not_promote_to_memory_cache_when_file_cache_returns_none(
    crl, crl_url, download_time, mem_cache_mock, disk_cache_mock, cache_mgr
):
    """Test not promoting to memory cache when file cache returns None"""
    mem_cache_mock.get.return_value = None
    disk_cache_mock.get.return_value = None

    result = cache_mgr.get(crl_url)

    assert result is None
    mem_cache_mock.get.assert_called_once_with(crl_url)
    disk_cache_mock.get.assert_called_once_with(crl_url)
    mem_cache_mock.put.assert_not_called()


def test_should_create_different_cache_entries_for_same_crl_with_different_download_times(
    crl, crl_url, mem_cache_mock, disk_cache_mock, cache_mgr
):
    """Test creating different cache entries for same CRL with different download times"""
    first_put_time = datetime.now(timezone.utc) - timedelta(hours=1)
    second_put_time = datetime.now(timezone.utc)

    cache_mgr.put(crl_url, crl, first_put_time)
    cache_mgr.put(crl_url, crl, second_put_time)

    # Verify both puts were called
    assert mem_cache_mock.put.call_count == 2
    assert disk_cache_mock.put.call_count == 2

    # Check that the download times are different
    first_memory_call = mem_cache_mock.put.call_args_list[0]
    assert first_memory_call.args == (crl_url, CRLCacheEntry(crl, first_put_time))
    second_memory_call = mem_cache_mock.put.call_args_list[1]
    assert second_memory_call.args == (crl_url, CRLCacheEntry(crl, second_put_time))


def test_cleanup_loop_starts_and_stops_properly(cache_factory):
    """Test that the cleanup loop starts and stops properly"""
    # Initially by default the cleanup is not running
    assert not cache_factory.is_periodic_cleanup_running()

    # Start the cleanup loop
    cache_factory.start_periodic_cleanup(timedelta(milliseconds=50))

    # Verify cleanup executor is created
    assert cache_factory.is_periodic_cleanup_running()

    # Stop the cleanup loop
    cache_factory.stop_periodic_cleanup()

    # Verify cleanup is properly stopped
    assert not cache_factory.is_periodic_cleanup_running()


def test_cleanup_loop_calls_cleanup_on_both_caches_periodically(
    cache_factory, mem_cache_mock, disk_cache_mock
):
    """Test that the cleanup loop calls cleanup on both memory and file caches periodically"""
    # Set up singleton instances to be cleaned
    cache_factory._memory_cache_instance = mem_cache_mock
    cache_factory._file_cache_instance = disk_cache_mock

    # Start the cleanup loop
    cache_factory.start_periodic_cleanup(timedelta(milliseconds=50))

    # Wait for at least 2 cleanup cycles to occur
    time.sleep(0.15)

    # Stop the cleanup loop
    cache_factory.stop_periodic_cleanup()

    # Verify that cleanup was called on both caches at least once
    assert mem_cache_mock.cleanup.call_count >= 1
    assert disk_cache_mock.cleanup.call_count >= 1

    # Verify both caches were called the same number of times
    assert mem_cache_mock.cleanup.call_count == disk_cache_mock.cleanup.call_count


def test_cleanup_loop_handles_exceptions_gracefully(
    cache_factory, mem_cache_mock, disk_cache_mock
):
    """Test that the cleanup loop handles exceptions gracefully and continues running"""

    # Make memory cache cleanup raise an exception on first call, then work normally
    mem_cache_mock.cleanup.side_effect = [
        Exception("Mem cache cleanup failure"),
        None,
        None,
        None,
    ]
    disk_cache_mock.cleanup.side_effect = [
        None,
        Exception("Disk cache cleanup failure"),
        None,
        None,
    ]

    # Set up singleton instances to be cleaned
    cache_factory._memory_cache_instance = mem_cache_mock
    cache_factory._file_cache_instance = disk_cache_mock

    # Start the cleanup loop
    cache_factory.start_periodic_cleanup(timedelta(milliseconds=50))

    # Wait for multiple cleanup cycles to occur
    time.sleep(0.15)

    # Stop the cleanup loop
    cache_factory.stop_periodic_cleanup()

    # Verify that cleanup was attempted multiple times despite the exception
    assert mem_cache_mock.cleanup.call_count > 1
    assert disk_cache_mock.cleanup.call_count > 1


def test_cleanup_loop_stops_gracefully_with_shutdown_event(
    cache_factory, mem_cache_mock, disk_cache_mock
):
    """Test that the cleanup loop stops gracefully when shutdown event is set"""

    # Set up singleton instances to be cleaned
    cache_factory._memory_cache_instance = mem_cache_mock
    cache_factory._file_cache_instance = disk_cache_mock

    # Start cleanup with longer interval to test shutdown
    cache_factory.start_periodic_cleanup(timedelta(hours=1))

    # Give it a moment to make first cleanup cycle
    time.sleep(0.1)

    # Stop the cleanup loop - this should interrupt the wait
    cache_factory.stop_periodic_cleanup()

    # Verify cleanup was called at least once (initial call)
    assert mem_cache_mock.cleanup.call_count == 1
    assert disk_cache_mock.cleanup.call_count == 1


def test_cleanup_loop_double_stop_is_safe(cache_factory):
    """Test that calling stop_periodic_cleanup multiple times is safe"""
    # Start the cleanup loop
    cache_factory.start_periodic_cleanup(timedelta(milliseconds=50))
    assert cache_factory.is_periodic_cleanup_running()

    # Stop it once
    cache_factory.stop_periodic_cleanup()
    assert not cache_factory.is_periodic_cleanup_running()

    # Stop it again - should not raise any exceptions
    cache_factory.stop_periodic_cleanup()
    assert not cache_factory.is_periodic_cleanup_running()


def test_cleanup_loop_double_start_is_safe_and_restarts(
    cache_factory, mem_cache_mock, disk_cache_mock
):
    """Test that calling start_periodic_cleanup multiple times creates new executors"""
    # Set up singleton instances to be cleaned
    cache_factory._memory_cache_instance = mem_cache_mock
    cache_factory._file_cache_instance = disk_cache_mock

    for i in range(1, 3):
        cache_factory.start_periodic_cleanup(timedelta(hours=1))
        time.sleep(0.1)
        # The cleanup should be in the running state and by this moment successfully made exactly one additional cleanup cycle
        assert cache_factory.is_periodic_cleanup_running()
        assert mem_cache_mock.cleanup.call_count == i
        assert disk_cache_mock.cleanup.call_count == i


# New comprehensive error handling tests
def test_file_cache_directory_creation_error():
    """Test CRLFileCache handles directory creation errors gracefully"""
    import tempfile
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLFileCache

    # Create a path that would cause permission error
    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir) / "restricted"

        # Mock os.makedirs to raise PermissionError
        with patch("os.makedirs", side_effect=PermissionError("Permission denied")):
            cache = CRLFileCache(cache_dir=cache_dir)

            # Should still work, but directory operations may fail gracefully
            entry = CRLCacheEntry(b"test_crl", datetime.now(timezone.utc))
            # This should not crash even if directory creation fails
            cache.put("test_key", entry)


def test_file_cache_file_write_error():
    """Test CRLFileCache handles file write errors gracefully"""
    import tempfile
    from unittest.mock import mock_open, patch

    from snowflake.connector.crl_cache import CRLCacheEntry, CRLFileCache

    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir)
        cache = CRLFileCache(cache_dir=cache_dir)

        entry = CRLCacheEntry(b"test_crl", datetime.now(timezone.utc))

        # Mock open to raise IOError on write
        mock_file = mock_open()
        mock_file.return_value.write.side_effect = IOError("Disk full")

        with patch("builtins.open", mock_file):
            # Should not crash, but may log error
            cache.put("test_key", entry)


def test_file_cache_file_read_error():
    """Test CRLFileCache handles file read errors gracefully"""
    import tempfile
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLCacheEntry, CRLFileCache

    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir)
        cache = CRLFileCache(cache_dir=cache_dir)

        # First put a valid entry
        entry = CRLCacheEntry(b"test_crl", datetime.now(timezone.utc))
        cache.put("test_key", entry)

        # Mock open to raise IOError on read
        with patch("builtins.open", side_effect=IOError("File corrupted")):
            # Should return None instead of crashing
            result = cache.get("test_key")
            assert result is None


def test_file_cache_cleanup_file_removal_error():
    """Test CRLFileCache cleanup handles file removal errors gracefully"""
    import tempfile
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLCacheEntry, CRLFileCache

    with tempfile.TemporaryDirectory() as temp_dir:
        cache_dir = Path(temp_dir)
        cache = CRLFileCache(cache_dir=cache_dir, removal_delay=timedelta(seconds=0))

        # Put an entry that should be removed immediately
        entry = CRLCacheEntry(
            b"test_crl", datetime.now(timezone.utc) - timedelta(days=1)
        )
        cache.put("test_key", entry)

        # Mock os.remove to raise PermissionError
        with patch("os.remove", side_effect=PermissionError("File in use")):
            # Should not crash during cleanup
            cache.cleanup()


def test_factory_warning_messages_for_memory_cache():
    """Test CRLCacheFactory logs appropriate warning for memory cache parameter mismatch"""
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLCacheFactory

    try:
        # First call with one validity time
        cache1 = CRLCacheFactory.get_memory_cache(timedelta(hours=1))

        # Second call with different validity time should log warning
        with patch("snowflake.connector.crl_cache.logger.warning") as mock_warning:
            cache2 = CRLCacheFactory.get_memory_cache(timedelta(hours=2))

            # Should return same instance
            assert cache1 is cache2

            # Should have logged warning with human-readable message
            mock_warning.assert_called_once()
            warning_msg = mock_warning.call_args[0][0]
            assert "CRLs in-memory cache has already been initialized" in warning_msg
            assert "1:00:00" in warning_msg  # Original time
            assert "2:00:00" in warning_msg  # New time
    finally:
        CRLCacheFactory.reset()


def test_factory_warning_messages_for_file_cache():
    """Test CRLCacheFactory logs appropriate warning for file cache parameter mismatch"""
    import tempfile
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLCacheFactory

    try:
        with tempfile.TemporaryDirectory() as temp_dir1, tempfile.TemporaryDirectory() as temp_dir2:
            cache_dir1 = Path(temp_dir1)
            cache_dir2 = Path(temp_dir2)

            # First call with one directory and delay
            cache1 = CRLCacheFactory.get_file_cache(cache_dir1, timedelta(days=7))

            # Second call with different parameters should log warnings
            with patch("snowflake.connector.crl_cache.logger.warning") as mock_warning:
                cache2 = CRLCacheFactory.get_file_cache(cache_dir2, timedelta(days=14))

                # Should return same instance
                assert cache1 is cache2

                # Should have logged two warnings (for directory and delay)
                assert mock_warning.call_count == 2

                # Check warning messages
                warning_calls = [call[0][0] for call in mock_warning.call_args_list]
                dir_warning = next(
                    msg for msg in warning_calls if "cache directory" in msg
                )
                delay_warning = next(
                    msg for msg in warning_calls if "removal delay" in msg
                )

                assert "CRLs file cache has already been initialized" in dir_warning
                assert "CRLs file cache has already been initialized" in delay_warning
                assert str(cache_dir1) in dir_warning
                assert str(cache_dir2) in dir_warning
                assert "7 days" in delay_warning
                assert "14 days" in delay_warning
    finally:
        CRLCacheFactory.reset()


def test_platform_specific_cache_path():
    """Test _get_default_crl_cache_path returns platform-appropriate path"""
    from unittest.mock import patch

    from snowflake.connector.crl_cache import _get_default_crl_cache_path

    # Test on different platforms
    with patch("platform.system") as mock_system:
        # Test Windows
        mock_system.return_value = "Windows"
        with patch.dict(
            "os.environ", {"APPDATA": "C:\\Users\\Test\\AppData\\Roaming"}, clear=True
        ):
            path = _get_default_crl_cache_path()
            assert "AppData" in str(path)
            assert "snowflake" in str(path).lower()

        # Test macOS
        mock_system.return_value = "Darwin"
        with patch.dict("os.environ", {"HOME": "/Users/test"}, clear=True):
            path = _get_default_crl_cache_path()
            assert "Library" in str(path)
            assert "snowflake" in str(path).lower()

        # Test Linux
        mock_system.return_value = "Linux"
        with patch.dict("os.environ", {"HOME": "/home/test"}, clear=True):
            path = _get_default_crl_cache_path()
            assert ".cache" in str(path)
            assert "snowflake" in str(path).lower()


def test_atexit_handler_error_handling():
    """Test atexit cleanup handler handles errors gracefully"""
    from unittest.mock import patch

    from snowflake.connector.crl_cache import CRLCacheFactory

    try:
        # Start cleanup to register atexit handler
        CRLCacheFactory.start_periodic_cleanup(timedelta(seconds=0.1))

        # Mock stop_periodic_cleanup to raise exception
        with patch.object(
            CRLCacheFactory,
            "stop_periodic_cleanup",
            side_effect=Exception("Test error"),
        ):
            # Calling atexit handler should not raise exception
            try:
                CRLCacheFactory._atexit_cleanup_handler()
            except Exception as e:
                pytest.fail(f"Atexit handler should not raise exceptions: {e}")
    finally:
        # Manual cleanup since we mocked the stop method
        with patch.object(CRLCacheFactory, "stop_periodic_cleanup", side_effect=None):
            CRLCacheFactory.reset()
