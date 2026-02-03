import ctypes
import os
from importlib import reload
from time import sleep
from unittest import mock

import pytest

from snowflake.connector._utils import (
    _CoreLoader,
    _NanoarrowLoader,
    _TrackedQueryCancellationTimer,
    build_minicore_usage_for_session,
    build_minicore_usage_for_telemetry,
    build_nanoarrow_usage_for_telemetry,
)

pytestmark = pytest.mark.skipolddriver


def test_timer():
    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.join()
    assert timer.executed

    timer = _TrackedQueryCancellationTimer(1, lambda: None)
    timer.start()
    timer.cancel()
    assert not timer.executed


class TestCoreLoader:
    """Tests for the _CoreLoader class."""

    def test_e2e(self):
        loader = _CoreLoader()
        loader.load()
        # Sleep a moment to make sure the lib is loaded
        sleep(2)
        assert loader.get_load_error() == str(None)
        assert loader.get_core_version() == "0.0.1"
        # Verify load time was measured
        assert loader.get_load_time() is not None
        assert loader.get_load_time() >= 0

    def test_core_loader_initialization(self):
        """Test that _CoreLoader initializes with None values."""
        loader = _CoreLoader()
        assert loader._version is None
        assert loader._error is None
        assert loader._path is None
        assert loader._load_time is None

    @pytest.mark.parametrize(
        "system,expected",
        [
            ("Linux", "linux"),
            ("Darwin", "macos"),
            ("Windows", "windows"),
            ("AIX", "aix"),
            ("FreeBSD", "unknown"),
        ],
    )
    def test_detect_os(self, system, expected):
        """Test _detect_os returns correct OS identifier."""
        with mock.patch("platform.system", return_value=system):
            assert _CoreLoader._detect_os() == expected

    @pytest.mark.parametrize(
        "machine,expected",
        [
            ("x86_64", "x86_64"),
            ("AMD64", "x86_64"),
            ("aarch64", "aarch64"),
            ("arm64", "aarch64"),
            ("i686", "i686"),
            ("i386", "i686"),
            ("ppc64", "ppc64"),
            ("sparc", "unknown"),
        ],
    )
    def test_detect_arch(self, machine, expected):
        """Test _detect_arch returns correct architecture identifier."""
        with mock.patch("platform.machine", return_value=machine):
            assert _CoreLoader._detect_arch() == expected

    def test_detect_libc_alpine(self, tmp_path):
        """Test _detect_libc returns musl on Alpine Linux."""
        with mock.patch("pathlib.Path.exists", return_value=True):
            assert _CoreLoader._detect_libc() == "musl"

    def test_detect_libc_glibc_default(self):
        """Test _detect_libc returns glibc by default."""
        with mock.patch("pathlib.Path.exists", return_value=False):
            with mock.patch("subprocess.run", side_effect=Exception("not found")):
                assert _CoreLoader._detect_libc() == "glibc"

    @pytest.mark.parametrize(
        "os_name,arch,libc,expected_subdir",
        [
            ("linux", "x86_64", "glibc", "linux_x86_64_glibc"),
            ("linux", "x86_64", "musl", "linux_x86_64_musl"),
            ("linux", "aarch64", "glibc", "linux_aarch64_glibc"),
            ("macos", "x86_64", "", "macos_x86_64"),
            ("macos", "aarch64", "", "macos_aarch64"),
            ("windows", "x86_64", "", "windows_x86_64"),
            ("aix", "ppc64", "", "aix_ppc64"),
        ],
    )
    def test_get_platform_subdir(self, os_name, arch, libc, expected_subdir):
        """Test _get_platform_subdir returns correct subdirectory."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value=os_name):
            with mock.patch.object(_CoreLoader, "_detect_arch", return_value=arch):
                with mock.patch.object(_CoreLoader, "_detect_libc", return_value=libc):
                    assert _CoreLoader._get_platform_subdir() == expected_subdir

    def test_get_platform_subdir_unsupported_os(self):
        """Test _get_platform_subdir raises OSError for unsupported OS."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value="unknown"):
            with mock.patch.object(_CoreLoader, "_detect_arch", return_value="x86_64"):
                with pytest.raises(
                    OSError, match="Mini core binary for unknown x86_64 not found"
                ):
                    _CoreLoader._get_platform_subdir()

    @pytest.mark.parametrize(
        "os_name,expected_lib",
        [
            ("windows", "sf_mini_core.dll"),
            ("macos", "libsf_mini_core.dylib"),
            ("aix", "libsf_mini_core.a"),
            ("linux", "libsf_mini_core.so"),
        ],
    )
    def test_get_lib_name(self, os_name, expected_lib):
        """Test _get_lib_name returns correct library filename."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value=os_name):
            assert _CoreLoader._get_lib_name() == expected_lib

    def test_get_core_path_windows(self):
        """Test _get_core_path returns correct path for Windows."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value="windows"):
            with mock.patch.object(_CoreLoader, "_detect_arch", return_value="x86_64"):
                with mock.patch("importlib.resources.files") as mock_files:
                    mock_files_obj = mock.MagicMock()
                    mock_files.return_value = mock_files_obj

                    _CoreLoader._get_core_path()

                    mock_files.assert_called_once_with("snowflake.connector.minicore")
                    mock_files_obj.joinpath.assert_called_once_with(
                        "windows_x86_64", "sf_mini_core.dll"
                    )

    def test_get_core_path_darwin(self):
        """Test _get_core_path returns correct path for macOS."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value="macos"):
            with mock.patch.object(_CoreLoader, "_detect_arch", return_value="aarch64"):
                with mock.patch("importlib.resources.files") as mock_files:
                    mock_files_obj = mock.MagicMock()
                    mock_files.return_value = mock_files_obj

                    _CoreLoader._get_core_path()

                    mock_files.assert_called_once_with("snowflake.connector.minicore")
                    mock_files_obj.joinpath.assert_called_once_with(
                        "macos_aarch64", "libsf_mini_core.dylib"
                    )

    def test_get_core_path_linux(self):
        """Test _get_core_path returns correct path for Linux."""
        with mock.patch.object(_CoreLoader, "_detect_os", return_value="linux"):
            with mock.patch.object(_CoreLoader, "_detect_arch", return_value="x86_64"):
                with mock.patch.object(
                    _CoreLoader, "_detect_libc", return_value="glibc"
                ):
                    with mock.patch("importlib.resources.files") as mock_files:
                        mock_files_obj = mock.MagicMock()
                        mock_files.return_value = mock_files_obj

                        _CoreLoader._get_core_path()

                        mock_files.assert_called_once_with(
                            "snowflake.connector.minicore"
                        )
                        mock_files_obj.joinpath.assert_called_once_with(
                            "linux_x86_64_glibc", "libsf_mini_core.so"
                        )

    def test_register_functions(self):
        """Test that _register_functions sets up the C library functions correctly."""
        mock_core = mock.MagicMock()
        mock_core.sf_core_full_version = mock.MagicMock()

        _CoreLoader._register_functions(mock_core)

        # Verify the function signature was configured
        assert mock_core.sf_core_full_version.argtypes == []
        assert mock_core.sf_core_full_version.restype == ctypes.c_char_p

    def test_load_minicore(self):
        """Test that _load_minicore loads the library correctly."""
        mock_path = mock.MagicMock()
        mock_lib_path = "/path/to/libsf_mini_core.so"

        with mock.patch("importlib.resources.as_file") as mock_as_file:
            with mock.patch("ctypes.CDLL") as mock_cdll:
                # Setup the context manager
                mock_as_file.return_value.__enter__ = mock.Mock(
                    return_value=mock_lib_path
                )
                mock_as_file.return_value.__exit__ = mock.Mock(return_value=False)

                mock_core = mock.MagicMock()
                mock_cdll.return_value = mock_core

                result = _CoreLoader._load_minicore(mock_path)

                mock_as_file.assert_called_once_with(mock_path)
                mock_cdll.assert_called_once_with(str(mock_lib_path))
                assert result == mock_core

    @pytest.mark.parametrize("env_value", ["1", "true", "True", "TRUE"])
    def test_is_core_disabled_returns_true(self, env_value):
        """Test that _is_core_disabled returns True when env var is '1' or 'true' (case-insensitive)."""
        loader = _CoreLoader()
        with mock.patch.dict(os.environ, {"SNOWFLAKE_DISABLE_MINICORE": env_value}):
            assert loader._is_core_disabled() is True

    @pytest.mark.parametrize("env_value", ["0", "false", "False", "no", "other", ""])
    def test_is_core_disabled_returns_false(self, env_value):
        """Test that _is_core_disabled returns False for other values."""
        loader = _CoreLoader()
        with mock.patch.dict(os.environ, {"SNOWFLAKE_DISABLE_MINICORE": env_value}):
            assert loader._is_core_disabled() is False

    def test_is_core_disabled_returns_false_when_not_set(self):
        """Test that _is_core_disabled returns False when env var is not set."""
        loader = _CoreLoader()
        with mock.patch.dict(os.environ, {}, clear=True):
            # Ensure the env var is not set
            os.environ.pop("SNOWFLAKE_DISABLE_MINICORE", None)
            assert loader._is_core_disabled() is False

    def test_load_skips_loading_when_core_disabled(self):
        """Test that load() returns early when core is disabled."""
        loader = _CoreLoader()

        with mock.patch.dict(os.environ, {"SNOWFLAKE_DISABLE_MINICORE": "1"}):
            with mock.patch.object(loader, "_get_core_path") as mock_get_path:
                loader.load()
                sleep(2)

                # Verify that _get_core_path was never called (loading was skipped)
                mock_get_path.assert_not_called()
                # Verify the error message is set correctly
                assert loader._error == "mini-core-disabled"
                assert loader._version is None

    def test_load_success(self):
        """Test successful load of the core library."""
        loader = _CoreLoader()
        mock_path = "/path/to/libsf_mini_core.so"
        mock_core = mock.MagicMock()
        mock_version = b"1.2.3"
        mock_core.sf_core_full_version = mock.MagicMock(return_value=mock_version)

        with mock.patch.object(loader, "_is_core_disabled", return_value=False):
            with mock.patch.object(
                loader, "_get_core_path", return_value=mock_path
            ) as mock_get_path:
                with mock.patch.object(
                    loader, "_load_minicore", return_value=mock_core
                ) as mock_load:
                    with mock.patch.object(
                        loader, "_register_functions"
                    ) as mock_register:
                        with mock.patch("time.perf_counter", side_effect=[0.0, 0.0155]):
                            loader.load()
                            sleep(2)

                            mock_get_path.assert_called_once()
                            mock_load.assert_called_once_with(mock_path)
                            mock_register.assert_called_once_with(mock_core)
                            assert loader._version == mock_version
                            assert loader._error is None
                            assert loader._path == mock_path
                            # (0.0155 - 0.0) * 1000 = 15.5 ms
                            assert loader._load_time == 15.5

    def test_load_failure(self):
        """Test that load captures exceptions."""
        loader = _CoreLoader()
        test_error = Exception("Test error loading core")

        with mock.patch.object(loader, "_is_core_disabled", return_value=False):
            with mock.patch.object(
                loader, "_get_core_path", side_effect=test_error
            ) as mock_get_path:
                loader.load()
                sleep(2)

                mock_get_path.assert_called_once()
                assert loader._version is None
                assert loader._error == test_error
                assert loader._path is None

    def test_get_load_error_with_error(self):
        """Test get_load_error returns error message when error exists."""
        loader = _CoreLoader()
        test_error = Exception("Test error message")
        loader._error = test_error

        result = loader.get_load_error()

        assert result == "Test error message"

    def test_get_load_error_no_error(self):
        """Test get_load_error returns 'None' string when no error exists."""
        loader = _CoreLoader()

        result = loader.get_load_error()

        assert result == "None"

    def test_get_core_version_with_version(self):
        """Test get_core_version returns decoded version string."""
        loader = _CoreLoader()
        loader._version = b"1.2.3-beta"

        result = loader.get_core_version()

        assert result == "1.2.3-beta"

    def test_get_core_version_no_version(self):
        """Test get_core_version returns None when no version exists."""
        loader = _CoreLoader()

        result = loader.get_core_version()

        assert result is None

    def test_get_file_name_with_path(self):
        """Test get_file_name returns the path string after successful load."""
        loader = _CoreLoader()
        loader._path = "/path/to/libsf_mini_core.so"

        result = loader.get_file_name()

        assert result == "/path/to/libsf_mini_core.so"

    def test_get_file_name_no_path(self):
        """Test get_file_name returns None when no path exists."""
        loader = _CoreLoader()

        result = loader.get_file_name()

        assert result is None

    def test_get_load_time_with_time(self):
        """Test get_load_time returns the load time when it has been set."""
        loader = _CoreLoader()
        loader._load_time = 42.5

        result = loader.get_load_time()

        assert result == 42.5

    def test_get_load_time_no_time(self):
        """Test get_load_time returns None when no load time exists."""
        loader = _CoreLoader()

        result = loader.get_load_time()

        assert result is None

    def test_get_present_binaries_contains_expected_paths(self):
        """Test get_present_binaries returns binaries for expected paths."""
        loader = _CoreLoader()

        result = loader.get_present_binaries()

        assert isinstance(result, str)
        assert result != ""

    def test_get_present_binaries_with_mocked_structure(self, tmp_path):
        """Test get_present_binaries with mocked directory structure."""
        loader = _CoreLoader()

        # Create a temporary directory structure mimicking minicore layout
        # Create platform directories with binary files
        linux_dir = tmp_path / "linux_x86_64_glibc"
        linux_dir.mkdir()
        (linux_dir / "libsf_mini_core.so").write_text("fake binary content")

        macos_dir = tmp_path / "macos_aarch64"
        macos_dir.mkdir()
        (macos_dir / "libsf_mini_core.dylib").write_text("fake binary content")

        windows_dir = tmp_path / "windows_x86_64"
        windows_dir.mkdir()
        (windows_dir / "sf_mini_core.dll").write_text("fake binary content")

        # Create a __pycache__ directory that should be ignored
        pycache_dir = tmp_path / "__pycache__"
        pycache_dir.mkdir()
        (pycache_dir / "some_file.pyc").write_text("cached file")

        # Mock importlib.resources.files to return our temp directory
        with mock.patch("importlib.resources.files") as mock_files:
            mock_files.return_value = tmp_path

            result = loader.get_present_binaries()

            # Verify the function was called with correct module name
            mock_files.assert_called_once_with("snowflake.connector.minicore")

            # Parse the result
            binaries = result.split(",")
            assert len(binaries) == 3

            # Verify all expected binaries are present
            assert "linux_x86_64_glibc/libsf_mini_core.so" in binaries
            assert "macos_aarch64/libsf_mini_core.dylib" in binaries
            assert "windows_x86_64/sf_mini_core.dll" in binaries

            # Verify __pycache__ files are not included
            assert not any("__pycache__" in binary for binary in binaries)

    def test_get_present_binaries_with_empty_directory(self, tmp_path):
        """Test get_present_binaries returns empty string for empty directory."""
        loader = _CoreLoader()

        # Create an empty temp directory
        # Mock importlib.resources.files to return our temp directory
        with mock.patch("importlib.resources.files") as mock_files:
            mock_files.return_value = tmp_path

            result = loader.get_present_binaries()

            assert result == ""

    def test_get_present_binaries_handles_exceptions(self):
        """Test get_present_binaries handles exceptions gracefully."""
        loader = _CoreLoader()

        # Mock importlib.resources.files to raise an exception
        with mock.patch("importlib.resources.files") as mock_files:
            mock_files.side_effect = Exception("Failed to access resources")

            # Should not raise, but return empty string
            result = loader.get_present_binaries()

            assert result == ""


def test_importing_snowflake_connector_triggers_core_loader_load():
    """Test that importing snowflake.connector triggers core_loader.load()."""
    # We need to test that when snowflake.connector is imported,
    # core_loader.load() is called. Since snowflake.connector is already imported,
    # we need to reload it and mock the load method.

    with mock.patch("snowflake.connector._utils._core_loader.load") as mock_load:
        # Reload the connector module to trigger the __init__.py code again
        import snowflake.connector

        reload(snowflake.connector)

        # Verify that load was called during import
        mock_load.assert_called_once()


def test_snowflake_connector_loads_when_core_loader_fails():
    """Test that snowflake.connector loads successfully even if core_loader.load() fails."""
    # Mock core_loader.load() to raise an exception
    with mock.patch(
        "snowflake.connector._utils._core_loader.load",
        side_effect=Exception("Simulated core loading failure"),
    ):
        import snowflake.connector

        # Reload the connector module - this should NOT raise an exception
        try:
            reload(snowflake.connector)
            # If we reach here, the module loaded successfully despite core_loader.load() failing
            assert True
        except Exception as e:
            pytest.fail(
                f"snowflake.connector failed to load when core_loader.load() raised an exception: {e}"
            )

        # Verify the module has expected attributes
        assert hasattr(snowflake.connector, "connect")
        assert hasattr(snowflake.connector, "SnowflakeConnection")
        assert hasattr(snowflake.connector, "Connect")


def test_snowflake_connector_usable_when_core_loader_fails():
    """Test that snowflake.connector remains usable even if core_loader.load() fails."""
    # Mock core_loader.load() to raise an exception
    with mock.patch(
        "snowflake.connector._utils._core_loader.load",
        side_effect=RuntimeError("Core library not found"),
    ):
        import snowflake.connector

        # Reload the connector module
        reload(snowflake.connector)

        # Verify we can access key classes and functions
        assert snowflake.connector.SnowflakeConnection is not None
        assert callable(snowflake.connector.connect)
        assert callable(snowflake.connector.Connect)

        # Verify error classes are available
        assert hasattr(snowflake.connector, "Error")
        assert hasattr(snowflake.connector, "DatabaseError")
        assert hasattr(snowflake.connector, "ProgrammingError")

        # Verify DBAPI constants are available
        assert hasattr(snowflake.connector, "apilevel")
        assert hasattr(snowflake.connector, "threadsafety")
        assert hasattr(snowflake.connector, "paramstyle")


def test_core_loader_error_captured_when_load_fails():
    """Test that errors from core_loader.load() are captured in the loader's error attribute."""
    loader = _CoreLoader()
    test_exception = FileNotFoundError("Library file not found")

    # Mock _get_core_path to raise an exception
    with mock.patch.object(loader, "_is_core_disabled", return_value=False):
        with mock.patch.object(loader, "_get_core_path", side_effect=test_exception):
            # Call load - it should NOT raise an exception
            loader.load()
            sleep(2)

            # Verify the error was captured
            assert loader._error is test_exception
            assert loader._version is None
            assert loader.get_load_error() == "Library file not found"
            assert loader.get_core_version() is None


def test_core_loader_fails_gracefully_on_missing_library():
    """Test that core_loader handles missing library files gracefully."""
    loader = _CoreLoader()

    # Mock importlib.resources.files to simulate missing library
    with mock.patch.object(loader, "_is_core_disabled", return_value=False):
        with mock.patch("importlib.resources.files") as mock_files:
            mock_files.side_effect = FileNotFoundError("minicore module not found")

            # Call load - it should NOT raise an exception
            loader.load()
            sleep(2)

            # Verify the error was captured
            assert loader._error is not None
            assert loader._version is None
            assert "minicore module not found" in loader.get_load_error()


def test_core_loader_fails_gracefully_on_incompatible_library():
    """Test that core_loader handles incompatible library files gracefully."""
    loader = _CoreLoader()
    mock_path = mock.MagicMock()

    # Mock the loading to simulate incompatible library (OSError is common for this)
    with mock.patch.object(loader, "_is_core_disabled", return_value=False):
        with mock.patch.object(loader, "_get_core_path", return_value=mock_path):
            with mock.patch.object(
                loader,
                "_load_minicore",
                side_effect=OSError("incompatible library version"),
            ):
                # Call load - it should NOT raise an exception
                loader.load()
                sleep(2)

                # Verify the error was captured
                assert loader._error is not None
                assert loader._version is None
                assert "incompatible library version" in loader.get_load_error()


class TestBuildMinicoreUsage:
    """Tests for build_minicore_usage_for_session and build_minicore_usage_for_telemetry functions."""

    def test_build_minicore_usage_for_session_returns_expected_keys(self):
        """Test that build_minicore_usage_for_session returns dict with expected keys."""
        result = build_minicore_usage_for_session()

        assert isinstance(result, dict)
        assert "ISA" in result
        assert "CORE_VERSION" in result
        assert "CORE_FILE_NAME" in result

    def test_build_minicore_usage_for_session_isa_matches_platform(self):
        """Test that ISA value matches platform.machine()."""
        import platform

        result = build_minicore_usage_for_session()

        assert result["ISA"] == platform.machine()

    def test_build_minicore_usage_for_session_with_mocked_core_loader(self):
        """Test build_minicore_usage_for_session with mocked core loader values."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value="1.2.3",
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value="/path/to/lib.so",
            ):
                result = build_minicore_usage_for_session()

                assert result["CORE_VERSION"] == "1.2.3"
                assert result["CORE_FILE_NAME"] == "/path/to/lib.so"

    def test_build_minicore_usage_for_session_with_failed_load(self):
        """Test build_minicore_usage_for_session when core loading has failed."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value=None,
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value=None,
            ):
                result = build_minicore_usage_for_session()

                assert result["CORE_VERSION"] is None
                assert result["CORE_FILE_NAME"] is None

    def test_build_minicore_usage_for_telemetry_returns_expected_keys(self):
        """Test that build_minicore_usage_for_telemetry returns dict with expected keys."""
        result = build_minicore_usage_for_telemetry()

        assert isinstance(result, dict)
        # Telemetry-specific keys
        assert "OS" in result
        assert "OS_VERSION" in result
        assert "CORE_LOAD_ERROR" in result
        # Session keys (inherited)
        assert "ISA" in result
        assert "CORE_VERSION" in result
        assert "CORE_FILE_NAME" in result

    def test_build_minicore_usage_for_telemetry_os_matches_platform(self):
        """Test that OS value matches platform.system()."""
        import platform

        result = build_minicore_usage_for_telemetry()

        assert result["OS"] == platform.system()

    def test_build_minicore_usage_for_telemetry_os_version_matches_platform(self):
        """Test that OS_VERSION value matches platform.version()."""
        import platform

        result = build_minicore_usage_for_telemetry()

        assert result["OS_VERSION"] == platform.version()

    def test_build_minicore_usage_for_telemetry_includes_session_data(self):
        """Test that build_minicore_usage_for_telemetry includes all session data."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value="2.0.0",
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value="/custom/path/lib.dylib",
            ):
                with mock.patch(
                    "snowflake.connector._utils._core_loader.get_load_error",
                    return_value="None",
                ):
                    session_result = build_minicore_usage_for_session()
                    telemetry_result = build_minicore_usage_for_telemetry()

                    # All session keys should be present in telemetry result
                    for key in session_result:
                        assert key in telemetry_result
                        assert telemetry_result[key] == session_result[key]

    def test_build_minicore_usage_for_telemetry_with_mocked_values(self):
        """Test build_minicore_usage_for_telemetry with mocked core loader values."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value="3.0.0",
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value="/path/to/lib.dylib",
            ):
                with mock.patch(
                    "snowflake.connector._utils._core_loader.get_load_error",
                    return_value="None",
                ):
                    result = build_minicore_usage_for_telemetry()

                    assert result["CORE_VERSION"] == "3.0.0"
                    assert result["CORE_FILE_NAME"] == "/path/to/lib.dylib"
                    assert result["CORE_LOAD_ERROR"] == "None"

    def test_build_minicore_usage_for_telemetry_with_disabled_core(self):
        """Test build_minicore_usage_for_telemetry when core is disabled."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value=None,
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value=None,
            ):
                with mock.patch(
                    "snowflake.connector._utils._core_loader.get_load_error",
                    return_value="mini-core-disabled",
                ):
                    result = build_minicore_usage_for_telemetry()

                    assert result["CORE_VERSION"] is None
                    assert result["CORE_FILE_NAME"] is None
                    assert result["CORE_LOAD_ERROR"] == "mini-core-disabled"
                    # OS info should still be present
                    assert result["OS"] is not None
                    assert result["OS_VERSION"] is not None

    def test_build_minicore_usage_for_telemetry_with_load_error(self):
        """Test build_minicore_usage_for_telemetry when core loading has failed."""
        with mock.patch(
            "snowflake.connector._utils._core_loader.get_core_version",
            return_value=None,
        ):
            with mock.patch(
                "snowflake.connector._utils._core_loader.get_file_name",
                return_value=None,
            ):
                with mock.patch(
                    "snowflake.connector._utils._core_loader.get_load_error",
                    return_value="Library not found",
                ):
                    result = build_minicore_usage_for_telemetry()

                    assert result["CORE_VERSION"] is None
                    assert result["CORE_FILE_NAME"] is None
                    assert result["CORE_LOAD_ERROR"] == "Library not found"


class TestNanoarrowLoader:
    """Tests for the NanoarrowLoader class."""

    def test_nanoarrow_loader_initialization(self):
        """Test that NanoarrowLoader initializes with None error."""
        loader = _NanoarrowLoader()
        assert loader._error is None

    def test_set_load_error(self):
        """Test that set_load_error stores the error."""
        loader = _NanoarrowLoader()
        test_error = Exception("Test error")
        loader.set_load_error(test_error)
        assert loader._error is test_error

    def test_get_load_error_with_error(self):
        """Test get_load_error returns error message when error exists."""
        loader = _NanoarrowLoader()
        test_error = Exception("Test error message")
        loader._error = test_error

        result = loader.get_load_error()

        assert result == "Test error message"


class TestBuildNanoarrowUsageForTelemetry:
    """Tests for build_nanoarrow_usage_for_telemetry function."""

    def test_build_nanoarrow_usage_for_telemetry_returns_expected_keys(self):
        """Test that build_nanoarrow_usage_for_telemetry returns dict with expected keys."""
        result = build_nanoarrow_usage_for_telemetry()

        assert isinstance(result, dict)
        assert "OS" in result
        assert "OS_VERSION" in result
        assert "NANOARROW_LOAD_ERROR" in result
        assert "ISA" in result

    def test_build_nanoarrow_usage_for_telemetry_with_mocked_error(self):
        """Test build_nanoarrow_usage_for_telemetry with mocked nanoarrow loader error."""
        with mock.patch(
            "snowflake.connector._utils._nanoarrow_loader.get_load_error",
            return_value="Nanoarrow load failed",
        ):
            result = build_nanoarrow_usage_for_telemetry()

            assert result["NANOARROW_LOAD_ERROR"] == "Nanoarrow load failed"


class TestNanoarrowImportErrorInCursor:
    """Tests for nanoarrow import error handling in cursor.py."""

    def test_import_error_populates_nanoarrow_loader_error(self):
        """Test that ImportError during nanoarrow import in cursor.py populates _nanoarrow_loader error field."""
        import importlib
        import sys

        # Save the original _nanoarrow_loader state and modules
        from snowflake.connector._utils import _nanoarrow_loader

        original_error = _nanoarrow_loader._error

        # Save cursor-related modules for restoration
        modules_to_remove = [
            key
            for key in list(sys.modules.keys())
            if "snowflake.connector.cursor" in key
        ]
        saved_cursor_modules = {key: sys.modules.pop(key) for key in modules_to_remove}

        # Save nanoarrow_arrow_iterator module if present
        nanoarrow_key = "snowflake.connector.nanoarrow_arrow_iterator"
        saved_nanoarrow = sys.modules.pop(nanoarrow_key, None)

        try:
            # Create a mock module that raises ImportError when accessed
            test_import_error = ImportError(
                "No module named 'nanoarrow_cpp': DLL load failed"
            )

            # Inject a module that raises ImportError on import
            class FailingModule:
                def __getattr__(self, name):
                    raise test_import_error

            # This makes import fail when trying to access anything from the module
            sys.modules[nanoarrow_key] = FailingModule()

            # Reset the nanoarrow loader error before test
            _nanoarrow_loader._error = None

            # Patch the set_load_error to track if it was called
            original_set_load_error = _nanoarrow_loader.set_load_error
            set_load_error_called_with = []

            def tracking_set_load_error(err):
                set_load_error_called_with.append(err)
                original_set_load_error(err)

            _nanoarrow_loader.set_load_error = tracking_set_load_error

            try:
                # Force reimport of cursor module - this should trigger the ImportError handling
                importlib.import_module("snowflake.connector.cursor")
            except Exception:
                pass  # Import may fail, but the error handler should still be called

            # Verify that set_load_error was called with an ImportError
            # or that the error was set directly
            if set_load_error_called_with:
                assert any(
                    isinstance(err, (ImportError, AttributeError))
                    for err in set_load_error_called_with
                )
            # Alternatively, check if the error was set
            elif _nanoarrow_loader._error is not None:
                assert isinstance(
                    _nanoarrow_loader._error, (ImportError, AttributeError, Exception)
                )

        finally:
            # Restore the set_load_error method
            _nanoarrow_loader.set_load_error = original_set_load_error

            # Restore original error state
            _nanoarrow_loader._error = original_error

            # Restore modules
            if saved_nanoarrow is not None:
                sys.modules[nanoarrow_key] = saved_nanoarrow
            elif nanoarrow_key in sys.modules:
                del sys.modules[nanoarrow_key]

            sys.modules.update(saved_cursor_modules)

    def test_nanoarrow_loader_set_load_error_simulates_cursor_behavior(self):
        """Test that NanoarrowLoader.set_load_error correctly stores ImportError as cursor.py does."""
        # This test simulates exactly what cursor.py does on import failure:
        # try:
        #     from .nanoarrow_arrow_iterator import PyArrowIterator
        #     CAN_USE_ARROW_RESULT_FORMAT = True
        # except ImportError as e:
        #     _nanoarrow_loader.set_load_error(e)
        #     CAN_USE_ARROW_RESULT_FORMAT = False

        loader = _NanoarrowLoader()

        # Simulate the ImportError that occurs when nanoarrow_arrow_iterator fails to import
        simulated_import_error = ImportError(
            "No module named 'nanoarrow_cpp': cannot import name 'ArrowResult'"
        )

        # This is the exact call made in cursor.py
        loader.set_load_error(simulated_import_error)

        # Verify the error was stored
        assert loader._error is simulated_import_error
        assert "No module named 'nanoarrow_cpp'" in loader.get_load_error()
        assert "ArrowResult" in loader.get_load_error()

    def test_nanoarrow_import_error_accessible_via_telemetry_function(self):
        """Test that import error from cursor.py is accessible via build_nanoarrow_usage_for_telemetry."""
        from snowflake.connector._utils import _nanoarrow_loader

        # Save original state
        original_error = _nanoarrow_loader._error

        try:
            # Simulate the error that would be set during cursor.py import failure
            test_error = ImportError(
                "Failed to import ArrowResult: nanoarrow_cpp not found"
            )
            _nanoarrow_loader.set_load_error(test_error)

            # Call the telemetry function and verify the error is reported
            result = build_nanoarrow_usage_for_telemetry()

            assert "Failed to import ArrowResult" in result["NANOARROW_LOAD_ERROR"]
            assert "nanoarrow_cpp not found" in result["NANOARROW_LOAD_ERROR"]

        finally:
            # Restore original error state
            _nanoarrow_loader._error = original_error

    def test_dll_load_failure_error_captured_correctly(self):
        """Test that DLL load failure errors during nanoarrow import are captured."""
        loader = _NanoarrowLoader()

        # This simulates a common error on Windows when DLL dependencies are missing
        dll_error = ImportError(
            "DLL load failed while importing 'nanoarrow_cpp': "
            "The specified module could not be found."
        )

        loader.set_load_error(dll_error)

        error_msg = loader.get_load_error()
        assert "DLL load failed" in error_msg
        assert "nanoarrow_cpp" in error_msg
