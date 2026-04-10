#!/usr/bin/env python3
"""
Pre-commit hook to ensure optional dependencies are always imported from .options module.
This ensures that the connector can operate in environments where these optional libraries are not available.
"""
import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

CHECKED_MODULES = [
    "boto3",
    "botocore",
    "aioboto3",
    "aiobotocore",
    "pandas",
    "pyarrow",
    "keyring",
]


@dataclass(frozen=True)
class ImportViolation:
    """Pretty prints a violation import restrictions."""

    filename: str
    line: int
    col: int
    message: str

    def __str__(self):
        return f"{self.filename}:{self.line}:{self.col}: {self.message}"


class ImportChecker(ast.NodeVisitor):
    """Checks that optional imports are only imported from .options module."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[ImportViolation] = []

    def visit_If(self, node: ast.If):
        # Always visit the condition, but ignore imports inside "if TYPE_CHECKING:" blocks
        if getattr(node.test, "id", None) == "TYPE_CHECKING":
            # Skip the body and orelse for TYPE_CHECKING blocks
            pass
        else:
            self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        """Check import statements."""
        for alias in node.names:
            self._check_import(alias.name, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from...import statements."""
        if node.module:
            # Check if importing from a checked module directly
            for module in CHECKED_MODULES:
                if node.module.startswith(module):
                    self.violations.append(
                        ImportViolation(
                            self.filename,
                            node.lineno,
                            node.col_offset,
                            f"Import from '{node.module}' is not allowed. Use 'from .options import {module}' instead",
                        )
                    )

            # Check if importing checked modules from .options (this is allowed)
            if node.module == ".options":
                # This is the correct way to import these modules
                pass
        self.generic_visit(node)

    def _check_import(self, module_name: str, line: int, col: int):
        """Check if a module import is for checked modules and not from .options."""
        for module in CHECKED_MODULES:
            if module_name.startswith(module):
                self.violations.append(
                    ImportViolation(
                        self.filename,
                        line,
                        col,
                        f"Direct import of '{module_name}' is not allowed. Use 'from .options import {module}' instead",
                    )
                )
                break


def check_file(filename: str) -> List[ImportViolation]:
    """Check a file for optional import violations."""
    try:
        tree = ast.parse(Path(filename).read_text())
    except SyntaxError:
        # gracefully handle syntax errors
        return []
    checker = ImportChecker(filename)
    checker.visit(tree)
    return checker.violations


def main():
    """Main function for pre-commit hook."""
    parser = argparse.ArgumentParser(
        description="Check that optional imports are only imported from .options module"
    )
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    parser.add_argument(
        "--show-fixes", action="store_true", help="Show suggested fixes"
    )
    args = parser.parse_args()

    all_violations = []
    for filename in args.filenames:
        if not filename.endswith(".py"):
            continue
        all_violations.extend(check_file(filename))

    # Show violations
    if all_violations:
        print("Optional import violations found:")
        print()

        for violation in all_violations:
            print(f"  {violation}")

        if args.show_fixes:
            print()
            print("How to fix:")
            print("  - Import optional modules only from .options module")
            print("  - Example:")
            print("    # CORRECT:")
            print("    from .options import boto3, botocore, installed_boto")
            print("    if installed_boto:")
            print("        SigV4Auth = botocore.auth.SigV4Auth")
            print()
            print("    # INCORRECT:")
            print("    import boto3")
            print("    from botocore.auth import SigV4Auth")
            print()
            print(
                "  - This ensures the connector works in environments where optional libraries are not installed"
            )

        print()
        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
