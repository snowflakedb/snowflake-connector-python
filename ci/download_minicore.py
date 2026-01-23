#!/usr/bin/env python3
"""
Download minicore binary for the current platform.
Designed to be used by cibuildwheel during wheel building.

Usage:
    python scripts/download_minicore.py [VERSION]

Environment variables:
    MINICORE_VERSION - Version to download (default: 0.0.1)
    MINICORE_OUTPUT_DIR - Output directory (default: src/snowflake/connector/minicore)
"""

from __future__ import annotations

import os
import platform
import sys
import tarfile
import tempfile
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# Configuration
BASE_URL = "https://sfc-repo.snowflakecomputing.com/minicore"
DEFAULT_VERSION = "0.0.1"

# Target directory for minicore module (relative to repo root)
MINICORE_MODULE_PATH = Path("src/snowflake/connector/minicore")


def get_repo_root() -> Path:
    """Get the repository root directory."""
    current = Path(__file__).resolve().parent
    while current != current.parent:
        if (current / "pyproject.toml").exists() or (current / "setup.py").exists():
            return current
        current = current.parent
    return Path(__file__).resolve().parent.parent


def detect_os() -> str:
    """Detect the operating system."""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "macos"
    elif system == "windows":
        return "windows"
    elif system == "aix":
        return "aix"
    else:
        return "unknown"


def detect_arch() -> str:
    """Detect the CPU architecture."""
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "aarch64"
    elif machine in ("i686", "i386", "x86"):
        return "i686"
    elif machine == "ppc64":
        return "ppc64"
    else:
        return "unknown"


def detect_libc() -> str:
    """Detect libc type on Linux (glibc vs musl)."""
    if detect_os() != "linux":
        return ""

    # Check if we're on Alpine/musl
    if Path("/etc/alpine-release").exists():
        return "musl"

    # Check for musl by looking at the libc library
    try:
        import subprocess

        result = subprocess.run(
            ["ldd", "--version"],
            capture_output=True,
            text=True,
        )
        if "musl" in result.stdout.lower() or "musl" in result.stderr.lower():
            return "musl"
    except Exception:
        pass

    # Default to glibc
    return "glibc"


def get_platform_dir(os_name: str, arch: str) -> str:
    """Build platform directory name for URL."""
    if os_name == "linux":
        return f"linux_{arch}"
    elif os_name == "macos":
        return f"mac_{arch}"
    elif os_name == "windows":
        return f"windows_{arch}"
    elif os_name == "aix":
        return f"aix_{arch}"
    else:
        return ""


def get_filename_arch(os_name: str, arch: str, libc: str) -> str:
    """Build filename architecture component."""
    if os_name == "linux":
        return f"linux-{arch}-{libc}"
    elif os_name == "macos":
        return f"macos-{arch}"
    elif os_name == "windows":
        return f"windows-{arch}"
    elif os_name == "aix":
        return f"aix-{arch}"
    else:
        return ""


def build_download_url(platform_dir: str, filename_arch: str, version: str) -> str:
    """Build the download URL."""
    filename = f"sf_mini_core_{filename_arch}_{version}.tar.gz"
    return f"{BASE_URL}/{platform_dir}/{version}/{filename}"


def download_file(url: str, dest_path: Path) -> None:
    """Download a file from URL to destination path."""
    print(f"Downloading: {url}")
    request = Request(url, headers={"User-Agent": "Python/minicore-downloader"})
    try:
        with urlopen(request, timeout=60) as response:
            content = response.read()
            dest_path.write_bytes(content)
            file_size_mb = len(content) / (1024 * 1024)
            print(f"Downloaded {file_size_mb:.2f} MB")
    except HTTPError as e:
        print(f"HTTP Error {e.code}: {e.reason}", file=sys.stderr)
        raise
    except URLError as e:
        print(f"URL Error: {e.reason}", file=sys.stderr)
        raise


def extract_tar_gz(tar_path: Path, extract_to: Path) -> None:
    """Extract a tar.gz file to the specified directory."""
    print(f"Extracting to: {extract_to}")
    extract_to.mkdir(parents=True, exist_ok=True)

    with tarfile.open(tar_path, "r:gz") as tar:
        # Security check: prevent path traversal attacks
        for member in tar.getmembers():
            member_path = extract_to / member.name
            try:
                member_path.resolve().relative_to(extract_to.resolve())
            except ValueError:
                print(
                    f"Skipping potentially unsafe path: {member.name}", file=sys.stderr
                )
                continue

        # The 'filter' parameter was added in Python 3.12
        if sys.version_info >= (3, 12):
            tar.extractall(path=extract_to, filter="data")
        else:
            tar.extractall(path=extract_to)


def main() -> int:
    # Get version from environment or command line
    version = os.environ.get("MINICORE_VERSION")
    if not version and len(sys.argv) > 1:
        version = sys.argv[1]
    if not version:
        version = DEFAULT_VERSION

    # Get output directory
    output_dir_env = os.environ.get("MINICORE_OUTPUT_DIR")
    if output_dir_env:
        output_dir = Path(output_dir_env)
    else:
        repo_root = get_repo_root()
        output_dir = repo_root / MINICORE_MODULE_PATH

    # Detect platform
    os_name = detect_os()
    arch = detect_arch()
    libc = detect_libc()

    print(f"Detected OS: {os_name}")
    print(f"Detected architecture: {arch}")
    if libc:
        print(f"Detected libc: {libc}")

    if os_name == "unknown" or arch == "unknown":
        print(
            f"Error: Unsupported platform: OS={os_name}, ARCH={arch}", file=sys.stderr
        )
        return 1

    # Build URL components
    platform_dir = get_platform_dir(os_name, arch)
    filename_arch = get_filename_arch(os_name, arch, libc)

    if not platform_dir or not filename_arch:
        print(
            "Error: Could not determine platform/architecture mapping", file=sys.stderr
        )
        return 1

    url = build_download_url(platform_dir, filename_arch, version)

    print(f"Version: {version}")
    print(f"Download URL: {url}")
    print(f"Output directory: {output_dir}")

    # Download to temp file and extract
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir) / f"sf_mini_core_{filename_arch}_{version}.tar.gz"

        try:
            download_file(url, temp_path)
            extract_tar_gz(temp_path, output_dir)
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    print("Done!")

    # List extracted files
    for item in sorted(output_dir.iterdir()):
        if not item.name.startswith("__"):
            print(f"  {item.name}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
