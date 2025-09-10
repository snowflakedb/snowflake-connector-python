#!/usr/bin/env python3
"""
Pre-commit hook to ensure optional imports are wrapped in try...except blocks.
This ensures that the connector can operate in environments where these optional libraries are not available.
"""
import argparse
import ast
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List

CHECKED_MODULES = ["boto3", "botocore"]


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
    """Checks for unwrapped optional imports."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[ImportViolation] = []

    def visit_Try(self, node: ast.Try):
        """Track entry/exit of try blocks."""
        # do not visit blocks inside try..except blocks
        pass

    def visit_Import(self, node: ast.Import):
        """Check import statements."""
        for alias in node.names:
            self._check_import(alias.name, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Check from...import statements."""
        if node.module:
            self._check_import(node.module, node.lineno, node.col_offset)
        self.generic_visit(node)

    def _check_import(self, module_name: str, line: int, col: int):
        """Check if a module import is boto-related and unwrapped."""

        for module in CHECKED_MODULES:
            if module_name.startswith(module):
                self.violations.append(
                    ImportViolation(
                        self.filename,
                        line,
                        col,
                        f"Import of '{module_name}' must be wrapped in try...except block to handle cases where {module} is not available",
                    )
                )
                break


def check_file(filename: str) -> List[ImportViolation]:
    """Check a file for boto import violations."""
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
        description="Check for unwrapped boto3/botocore imports"
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
        print("Unwrapped boto3/botocore import violations found:")
        print()

        for violation in all_violations:
            print(f"  {violation}")

        if args.show_fixes:
            print()
            print("How to fix:")
            print("  - Wrap boto3/botocore imports in try...except blocks")
            print("  - Example:")
            print("    try:")
            print("        import boto3")
            print("        from botocore.config import Config")
            print("    except ImportError:")
            print("        # Handle the case where boto3/botocore is not available")
            print("        boto3 = None")
            print("        Config = None")
            print()
            print(
                "  - This ensures the connector works in environments where AWS libraries are not installed"
            )

        print()
        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
