"""Tests for the setup.py build-time minicore pruner.

The sdist ships pre-built minicore binaries for every supported platform.
`PlatformBuildPy._prune_minicore` strips the non-native subdirs from the built
distribution so wheels and downstream sdist consumers (pip install, Homebrew,
conda-forge, nixpkgs) end up with a clean single-platform layout that passes
packaging audits which reject foreign-arch binaries.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest import mock

import pytest

pytestmark = pytest.mark.skipolddriver

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_PY = REPO_ROOT / "setup.py"


def _load_setup_module():
    """Load setup.py as a module without executing the `setup()` call.

    setup.py calls `setup(...)` at module scope, which is harmless to run but
    noisy. We only need `_minicore_native_subdir` and `PlatformBuildPy`, so
    stash `sys.argv` and rely on setuptools' no-op behaviour when no command
    is given.
    """
    spec = importlib.util.spec_from_file_location("_setup_under_test", SETUP_PY)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("sys.argv", ["setup.py", "--help-commands"]):
        spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def setup_module():
    return _load_setup_module()


MINICORE_PLATFORMS = (
    "aix_ppc64",
    "linux_aarch64_glibc",
    "linux_aarch64_musl",
    "linux_x86_64_glibc",
    "linux_x86_64_musl",
    "macos_aarch64",
    "macos_x86_64",
    "windows_x86_64",
)


@pytest.mark.parametrize(
    ("system", "machine", "libc", "expected"),
    [
        ("Linux", "x86_64", ("glibc", "2.35"), "linux_x86_64_glibc"),
        ("Linux", "aarch64", ("glibc", "2.35"), "linux_aarch64_glibc"),
        ("Linux", "x86_64", ("musl", "1.2.3"), "linux_x86_64_musl"),
        ("Linux", "aarch64", ("", ""), "linux_aarch64_musl"),
        ("Darwin", "arm64", ("", ""), "macos_aarch64"),
        ("Darwin", "x86_64", ("", ""), "macos_x86_64"),
        ("Windows", "AMD64", ("", ""), "windows_x86_64"),
        ("AIX", "ppc64", ("", ""), "aix_ppc64"),
    ],
)
def test_native_subdir_matches_platform(setup_module, system, machine, libc, expected):
    with mock.patch("platform.system", return_value=system), mock.patch(
        "platform.machine", return_value=machine
    ), mock.patch("platform.libc_ver", return_value=libc):
        assert setup_module._minicore_native_subdir() == expected


def test_native_subdir_returns_none_for_unknown_platform(setup_module):
    with mock.patch("platform.system", return_value="Haiku"), mock.patch(
        "platform.machine", return_value="x86_64"
    ), mock.patch("platform.libc_ver", return_value=("", "")):
        assert setup_module._minicore_native_subdir() is None


def _populate_fake_minicore(root: Path) -> Path:
    minicore = root / "snowflake" / "connector" / "minicore"
    minicore.mkdir(parents=True)
    (minicore / "__init__.py").write_text("")
    (minicore / "__pycache__").mkdir()
    for name in MINICORE_PLATFORMS:
        platform_dir = minicore / name
        platform_dir.mkdir()
        (platform_dir / "libsf_mini_core.so").write_bytes(b"\x7fELF-stub")
    return minicore


def test_prune_minicore_keeps_only_native_dir(setup_module, tmp_path):
    build_lib = tmp_path / "build" / "lib"
    minicore = _populate_fake_minicore(build_lib)

    cmd = setup_module.PlatformBuildPy.__new__(setup_module.PlatformBuildPy)
    cmd.build_lib = str(build_lib)

    with mock.patch.object(
        setup_module, "_minicore_native_subdir", return_value="linux_x86_64_glibc"
    ):
        cmd._prune_minicore()

    remaining = sorted(
        entry for entry in os.listdir(minicore) if not entry.startswith("__")
    )
    assert remaining == ["linux_x86_64_glibc"]
    assert (minicore / "__init__.py").exists()
    assert (minicore / "__pycache__").is_dir()


def test_prune_minicore_noop_when_platform_unknown(setup_module, tmp_path):
    build_lib = tmp_path / "build" / "lib"
    minicore = _populate_fake_minicore(build_lib)

    cmd = setup_module.PlatformBuildPy.__new__(setup_module.PlatformBuildPy)
    cmd.build_lib = str(build_lib)

    with mock.patch.object(setup_module, "_minicore_native_subdir", return_value=None):
        cmd._prune_minicore()

    remaining = sorted(
        entry for entry in os.listdir(minicore) if not entry.startswith("__")
    )
    assert remaining == list(MINICORE_PLATFORMS)


def test_prune_minicore_noop_when_directory_missing(setup_module, tmp_path):
    build_lib = tmp_path / "build" / "lib"
    build_lib.mkdir(parents=True)

    cmd = setup_module.PlatformBuildPy.__new__(setup_module.PlatformBuildPy)
    cmd.build_lib = str(build_lib)

    cmd._prune_minicore()


def test_pruner_agrees_with_runtime_loader(setup_module):
    from snowflake.connector._utils import _CoreLoader

    try:
        runtime = _CoreLoader._get_platform_subdir()
    except OSError:
        pytest.skip("runtime loader does not support this platform")
    assert setup_module._minicore_native_subdir() == runtime
