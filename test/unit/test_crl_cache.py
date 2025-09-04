#!/usr/bin/env python
from __future__ import annotations

import tempfile
import time
from datetime import UTC, datetime, timedelta
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
    return datetime.now(UTC) - timedelta(minutes=30)


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
    with CRLCacheManager(mem_cache_mock, disk_cache_mock, timedelta(seconds=0)) as mgr:
        yield mgr


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
    builder = builder.last_update(datetime.now(UTC))
    builder = builder.next_update(datetime.now(UTC) + timedelta(days=1))

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
    now = datetime.now(UTC)

    assert not cache_entry.is_crl_expired_by(now)


def test_is_evicted_false_when_not_evicted(crl, download_time):
    """Test cache eviction check when not evicted"""
    entry = CRLCacheEntry(crl, download_time)
    current_time = datetime.now(UTC)
    cache_validity = timedelta(hours=24)

    assert not entry.is_evicted_by(current_time, cache_validity)


def test_is_evicted_true_when_evicted(crl, download_time):
    """Test cache eviction check when evicted"""
    old_download_time = datetime.now(UTC) - timedelta(days=2)
    entry = CRLCacheEntry(crl, old_download_time)
    current_time = datetime.now(UTC)
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
    download_time = datetime.now(UTC)
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
    old_time = datetime.now(UTC) - timedelta(hours=2)
    old_entry = CRLCacheEntry(crl, old_time)
    memory_cache.put(crl_url, old_entry)
    assert memory_cache.get(crl_url) is not None

    memory_cache.cleanup()
    assert memory_cache.get(crl_url) is None


def test_disk_put_and_get(crl, crl_url, download_time, disk_cache):
    """Test storing and retrieving from file cache"""
    # download_time = datetime.now(UTC)
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
    first_put_time = datetime.now(UTC) - timedelta(hours=1)
    second_put_time = datetime.now(UTC)

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


def test_cleanup_loop_starts_and_stops_properly(mem_cache_mock, disk_cache_mock):
    """Test that the cleanup loop starts and stops properly"""

    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(milliseconds=50)
    ) as manager:

        # Initially by default the cleanup is not running
        assert not manager.is_periodic_cleanup_running()

        # Start the cleanup loop
        manager.start_periodic_cleanup()

        # Verify cleanup executor is created
        assert manager.is_periodic_cleanup_running()

        # Stop the cleanup loop
        manager.stop_periodic_cleanup()

        # Verify cleanup is properly stopped
        assert not manager.is_periodic_cleanup_running()


def test_cleanup_loop_calls_cleanup_on_both_caches_periodically(
    mem_cache_mock, disk_cache_mock
):
    """Test that the cleanup loop calls cleanup on both memory and file caches periodically"""

    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(milliseconds=50)
    ) as manager:

        # Start the cleanup loop
        manager.start_periodic_cleanup()

        # Wait for at least 2 cleanup cycles to occur
        time.sleep(0.15)

        # Stop the cleanup loop
        manager.stop_periodic_cleanup()

        # Verify that cleanup was called on both caches at least once
        assert mem_cache_mock.cleanup.call_count >= 1
        assert disk_cache_mock.cleanup.call_count >= 1

        # Verify both caches were called the same number of times
        assert mem_cache_mock.cleanup.call_count == disk_cache_mock.cleanup.call_count


def test_cleanup_loop_handles_exceptions_gracefully(mem_cache_mock, disk_cache_mock):
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

    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(milliseconds=50), start_cleanup=True
    ) as manager:
        # Wait for multiple cleanup cycles to occur
        time.sleep(0.15)  # To allow for multiple cleanup cycles

        # Stop the cleanup loop
        manager.stop_periodic_cleanup()

        # Verify that cleanup was attempted multiple times despite the exception
        assert mem_cache_mock.cleanup.call_count > 1
        assert disk_cache_mock.cleanup.call_count > 1


def test_cleanup_loop_stops_gracefully_with_shutdown_event(
    mem_cache_mock, disk_cache_mock
):
    """Test that the cleanup loop stops gracefully when shutdown event is set"""

    # longer interval to test shutdown
    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(hours=1), start_cleanup=True
    ) as manager:
        # Give it a moment to make first cleanup cycle
        time.sleep(0.1)

        # Stop the cleanup loop - this should interrupt the wait
        manager.stop_periodic_cleanup()

        # Verify cleanup was called at least once (initial call)
        assert mem_cache_mock.cleanup.call_count == 1
        assert disk_cache_mock.cleanup.call_count == 1


def test_cleanup_loop_double_stop_is_safe(mem_cache_mock, disk_cache_mock):
    """Test that calling stop_periodic_cleanup multiple times is safe"""
    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(milliseconds=50)
    ) as manager:
        # Start the cleanup loop
        manager.start_periodic_cleanup()
        assert manager.is_periodic_cleanup_running()

        # Stop it once
        manager.stop_periodic_cleanup()
        assert not manager.is_periodic_cleanup_running()

        # Stop it again - should not raise any exceptions
        manager.stop_periodic_cleanup()
        assert not manager.is_periodic_cleanup_running()


def test_cleanup_loop_double_start_is_safe_and_restarts(
    mem_cache_mock, disk_cache_mock
):
    """Test that calling start_periodic_cleanup multiple times creates new executors"""
    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(hours=1), start_cleanup=False
    ) as manager:

        for i in range(1, 3):
            manager.start_periodic_cleanup()
            time.sleep(0.1)
            # The cleanup should be in the running state and by this moment successfully made exactly one additional cleanup cycle
            assert manager.is_periodic_cleanup_running()
            assert mem_cache_mock.cleanup.call_count == i
            assert disk_cache_mock.cleanup.call_count == i


def test_cleanup_loop_context_manager_stops_cleanup(mem_cache_mock, disk_cache_mock):
    """Test that using CRLCacheManager as context manager properly stops cleanup"""
    with CRLCacheManager(
        mem_cache_mock, disk_cache_mock, timedelta(milliseconds=50), start_cleanup=True
    ) as manager:
        assert manager.is_periodic_cleanup_running()
        # Let it run briefly
        time.sleep(0.1)
        assert manager.is_periodic_cleanup_running()

    # After exiting context, cleanup should be stopped
    assert not manager.is_periodic_cleanup_running()

    # Verify cleanup was called
    assert mem_cache_mock.cleanup.call_count
    assert disk_cache_mock.cleanup.call_count
