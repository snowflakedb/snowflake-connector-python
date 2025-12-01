"""
Generate generated_full_matrix.json and generated_pr_matrix.json for GitHub Actions workflows.

Usage:
    python ci/generate_full_matrix.py

To customize, edit the configuration constants below and run the script.
"""

import json
from dataclasses import dataclass
from enum import Enum
from itertools import product
from pathlib import Path
from typing import List, Tuple

# ============================================================================
# CONFIGURATION - Edit these to customize the matrix
# ============================================================================


@dataclass
class PythonVersion:
    """Python version configuration."""

    version: str
    test_on_pr: bool = False


@dataclass
class OS:
    """Operating system configuration."""

    name: str  # GitHub Actions runner image (e.g., "ubuntu-latest")
    download_name: str  # Artifact download name (e.g., "manylinux_x86_64")


class OperatingSystem(Enum):
    """Available operating systems with their build configurations."""

    UBUNTU = OS(
        name="ubuntu-latest",
        download_name="manylinux_x86_64",
    )
    MACOS = OS(
        name="macos-latest",
        download_name="macosx_x86_64",
    )
    WINDOWS = OS(
        name="windows-latest",
        download_name="win_amd64",
    )
    WINDOWS_ARM = OS(
        name="windows-11-arm",
        download_name="win_arm64",
    )


class Python(Enum):
    """Available Python versions."""

    PY39 = PythonVersion("3.9", test_on_pr=False)
    PY310 = PythonVersion("3.10", test_on_pr=True)
    PY311 = PythonVersion("3.11", test_on_pr=False)
    PY312 = PythonVersion("3.12", test_on_pr=False)
    PY313 = PythonVersion("3.13", test_on_pr=True)


class CSP(Enum):
    """Available cloud service providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


# OS-Python combinations to exclude from all matrices
# Format: (os_name, python_version)
EXCLUSIONS: List[Tuple[str, str]] = [
    # Windows 11 ARM doesn't support Python 3.9 and 3.10
    ("windows-11-arm", "3.9"),
    ("windows-11-arm", "3.10"),
]

# Additional fields to add to each matrix entry (optional)
# Example: {"with_snowpark": "true"}
ADDITIONAL_FIELDS = {}

# Output file paths (relative to repository root)
_WORKFLOWS_DIR = Path(__file__).parent.parent / ".github" / "workflows"
FULL_MATRIX_FILE = _WORKFLOWS_DIR / "generated_full_matrix.json"
PR_MATRIX_FILE = _WORKFLOWS_DIR / "generated_pr_matrix.json"

# JSON indentation
INDENT = 2

# ============================================================================
# MATRIX GENERATION - No need to edit below this line
# ============================================================================


def _add_to_matrix(matrix: list[dict], os: OS, csp_name: str, py_config: PythonVersion):
    if (os.name, py_config.version) in EXCLUSIONS:
        return

    entry = {
        "os": os.name,
        "download_name": os.download_name,
        "python-version": py_config.version,
        "cloud-provider": csp_name,
    }

    # Add any additional fields
    if ADDITIONAL_FIELDS:
        entry.update(ADDITIONAL_FIELDS)

    matrix.append(entry)


def generate_matrix(pr_only: bool = False):
    matrix = []

    if pr_only:
        csp_to_test = list(CSP)
        for system in OperatingSystem:
            os_config = system.value
            csp_name = csp_to_test.pop(0).value if csp_to_test else CSP.AWS.value
            for py_version in Python:
                if py_version.value.test_on_pr:
                    _add_to_matrix(matrix, os_config, csp_name, py_version.value)
    else:
        operating_systems = [os_enum.value for os_enum in OperatingSystem]
        python_versions = [py_enum.value for py_enum in Python]
        cloud_providers = [csp_enum.value for csp_enum in CSP]

        for os_config, py_config, csp_name in product(
            operating_systems, python_versions, cloud_providers
        ):
            _add_to_matrix(matrix, os_config, csp_name, py_config)
    return matrix


def write_matrix(matrix: List[dict], output_file: Path) -> Path:
    output_file.write_text(json.dumps(matrix, indent=INDENT))
    return output_file.resolve()


def main():
    """Generate and write both full and PR matrix files."""
    print("Generating GitHub Actions test matrices...")
    print("=" * 70)

    # Generate full matrix (all combinations)
    print("\n🔨 Generating FULL matrix (all OS × Python × CSP)...")
    full_matrix = generate_matrix(pr_only=False)
    full_path = write_matrix(full_matrix, FULL_MATRIX_FILE)
    print(f"✓ Written to: {full_path}")

    # Generate PR matrix (strategic pairings)
    print("\n🔨 Generating PR matrix (strategic OS-CSP pairings × PR Python)...")
    pr_matrix = generate_matrix(pr_only=True)
    pr_path = write_matrix(pr_matrix, PR_MATRIX_FILE)
    print(f"✓ Written to: {pr_path}")

    # Final summary
    print(f"\n{'='*70}")
    print("✅ Successfully generated both matrices")
    print(f"{'='*70}")
    print(f"  Full matrix: {len(full_matrix):2d} combinations")
    print(
        f"  PR matrix:   {len(pr_matrix):2d} combinations (saves {len(full_matrix) - len(pr_matrix)} jobs)"
    )
    print(f"  Exclusions:  {len(EXCLUSIONS):2d}")
    print(f"{'='*70}\n")


if __name__ == "__main__":
    main()
