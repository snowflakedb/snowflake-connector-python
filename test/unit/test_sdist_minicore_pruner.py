"""Tests for HostOnlyMinicoreSdist in setup.py.

The sdist is expected to ship only the host platform's minicore binary.
Keeping foreign-arch binaries in the sdist failed downstream packaging audits
(Homebrew, conda-forge). Wheels come from the git tree directly and are
unaffected.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from unittest import mock

import pytest

pytestmark = pytest.mark.skipolddriver

pytest.importorskip(
    "setuptools",
    reason="setup.py imports setuptools at module scope",
)
# Some Python 3.14+ test envs ship without setuptools.command.sdist even when
# the top-level `setuptools` package is importable; guard both.
pytest.importorskip("setuptools.command.sdist")

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP_PY = REPO_ROOT / "setup.py"

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


def _load_setup_module():
    spec = importlib.util.spec_from_file_location("_setup_under_test", SETUP_PY)
    module = importlib.util.module_from_spec(spec)
    with mock.patch("sys.argv", ["setup.py", "--help-commands"]):
        spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def setup_module():
    try:
        return _load_setup_module()
    except ModuleNotFoundError as exc:
        pytest.skip(f"setup.py cannot be loaded in this env: {exc}")


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
def test_host_subdir_resolves(setup_module, system, machine, libc, expected):
    with mock.patch("platform.system", return_value=system), mock.patch(
        "platform.machine", return_value=machine
    ), mock.patch("platform.libc_ver", return_value=libc):
        assert setup_module._host_minicore_subdir() == expected


def test_host_subdir_returns_none_for_unknown_arch(setup_module):
    with mock.patch("platform.system", return_value="Linux"), mock.patch(
        "platform.machine", return_value="riscv64"
    ), mock.patch("platform.libc_ver", return_value=("glibc", "2.35")):
        assert setup_module._host_minicore_subdir() is None


def _populate_fake_tree(base_dir: Path) -> Path:
    minicore = base_dir / "src" / "snowflake" / "connector" / "minicore"
    minicore.mkdir(parents=True)
    (minicore / "__init__.py").write_text("")
    for name in MINICORE_PLATFORMS:
        platform_dir = minicore / name
        platform_dir.mkdir()
        (platform_dir / "libsf_mini_core.so").write_bytes(b"\x7fELF-stub")
    return minicore


def _make_sdist_cmd(setup_module):
    """Construct the sdist command without running its real init."""
    return setup_module.HostOnlyMinicoreSdist.__new__(
        setup_module.HostOnlyMinicoreSdist
    )


def test_make_release_tree_keeps_only_host_dir(setup_module, tmp_path):
    base_dir = tmp_path / "sdist_tree"
    minicore = _populate_fake_tree(base_dir)

    cmd = _make_sdist_cmd(setup_module)

    with mock.patch.object(
        setup_module.sdist, "make_release_tree", lambda self, b, f: None
    ), mock.patch.object(
        setup_module, "_host_minicore_subdir", return_value="linux_x86_64_glibc"
    ):
        cmd.make_release_tree(str(base_dir), [])

    remaining = sorted(entry for entry in os.listdir(minicore))
    assert remaining == ["__init__.py", "linux_x86_64_glibc"]


def test_make_release_tree_raises_for_unknown_host(setup_module, tmp_path):
    base_dir = tmp_path / "sdist_tree"
    _populate_fake_tree(base_dir)

    cmd = _make_sdist_cmd(setup_module)

    with mock.patch.object(
        setup_module.sdist, "make_release_tree", lambda self, b, f: None
    ), mock.patch.object(setup_module, "_host_minicore_subdir", return_value=None):
        with pytest.raises(RuntimeError, match="no matching"):
            cmd.make_release_tree(str(base_dir), [])


def test_make_release_tree_raises_when_host_subdir_missing(setup_module, tmp_path):
    base_dir = tmp_path / "sdist_tree"
    minicore = _populate_fake_tree(base_dir)
    # Simulate a git tree where the host dir was never populated.
    import shutil

    shutil.rmtree(minicore / "linux_x86_64_glibc")

    cmd = _make_sdist_cmd(setup_module)

    with mock.patch.object(
        setup_module.sdist, "make_release_tree", lambda self, b, f: None
    ), mock.patch.object(
        setup_module, "_host_minicore_subdir", return_value="linux_x86_64_glibc"
    ):
        with pytest.raises(RuntimeError, match="expected .* to exist"):
            cmd.make_release_tree(str(base_dir), [])


def test_make_release_tree_noop_without_minicore_dir(setup_module, tmp_path):
    base_dir = tmp_path / "sdist_tree"
    base_dir.mkdir()

    cmd = _make_sdist_cmd(setup_module)

    with mock.patch.object(
        setup_module.sdist, "make_release_tree", lambda self, b, f: None
    ):
        cmd.make_release_tree(str(base_dir), [])


def test_host_subdir_agrees_with_runtime_loader(setup_module):
    from snowflake.connector._utils import _CoreLoader

    try:
        runtime = _CoreLoader._get_platform_subdir()
    except OSError:
        pytest.skip("runtime loader does not support this platform")
    assert setup_module._host_minicore_subdir() == runtime
