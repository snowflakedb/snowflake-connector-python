#!/usr/bin/env python3
"""
Pre-commit hook to prevent direct usage of requests and urllib3 calls.
Ensures all HTTP requests go through SessionManager.
"""
import argparse
import ast
import sys
from typing import List, Optional


class HTTPCallViolation:
    def __init__(self, filename: str, line: int, col: int, code: str, message: str):
        self.filename = filename
        self.line = line
        self.col = col
        self.code = code
        self.message = message

    def __str__(self):
        return f"{self.filename}:{self.line}:{self.col}: {self.code} {self.message}"


class NoNativeHTTPChecker:
    """Checker to detect direct usage of requests/urllib3 calls."""

    VIOLATIONS = {
        "SNOW001": "Direct use of requests.request() is forbidden, use SessionManager.request() instead",
        "SNOW002": "Direct use of requests.Session() is forbidden, use SessionManager.use_requests_session() instead",
        "SNOW003": "Direct use of urllib3.PoolManager() is forbidden, use SessionManager instead",
        "SNOW004": "Direct HTTP method calls (requests.get, etc.) are forbidden, use SessionManager instead",
        "SNOW005": "Direct use of PoolManager.request() is forbidden, use SessionManager instead",
    }

    # Files that are allowed to use native HTTP calls
    EXEMPT_PATTERNS = [
        "session_manager.py",
        "vendored/",
        "conftest.py",
        "mock_utils.py",
    ]

    # Test file patterns (more specific)
    TEST_PATTERNS = [
        "/test/",
        "test/",
        "_test.py",
    ]

    # Files that are temporarily allowed with warnings
    TEMPORARY_EXEMPT_PATTERNS = [
        ("auth/_oauth_base.py", "SNOW-2229411"),
        ("telemetry_oob.py", "SNOW-694457"),
    ]

    def __init__(self, filename: str):
        self.filename = filename

    def is_exempt(self) -> bool:
        """Check if the file is exempt from HTTP call restrictions."""
        # Check general exemptions
        if any(pattern in self.filename for pattern in self.EXEMPT_PATTERNS):
            return True

        # Check test file patterns (only if in test directory or ends with _test.py)
        for pattern in self.TEST_PATTERNS:
            if pattern in self.filename:
                return True

        return False

    def is_temporarily_exempt(self) -> Optional[str]:
        """Check if the file is temporarily exempt and return the JIRA ticket."""
        for pattern, ticket in self.TEMPORARY_EXEMPT_PATTERNS:
            if pattern in self.filename:
                return ticket
        return None

    def check_file(self) -> List[HTTPCallViolation]:
        """Check a file for HTTP call violations."""
        if self.is_exempt():
            return []

        # Check for temporary exemptions
        temp_ticket = self.is_temporarily_exempt()
        if temp_ticket:
            return []  # Skip checking but will show warning in main()

        try:
            with open(self.filename, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        violations = []
        for node in ast.walk(tree):
            violation = self._check_node(node)
            if violation:
                violations.append(violation)

        return violations

    def _check_node(self, node: ast.AST) -> Optional[HTTPCallViolation]:
        """Check a single AST node for violations."""
        # requests.request() calls
        if self._is_requests_request_call(node):
            return HTTPCallViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                "SNOW001",
                self.VIOLATIONS["SNOW001"],
            )

        # requests.Session() instantiation
        if self._is_requests_session_instantiation(node):
            return HTTPCallViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                "SNOW002",
                self.VIOLATIONS["SNOW002"],
            )

        # urllib3.PoolManager() instantiation
        if self._is_urllib3_poolmanager_instantiation(node):
            return HTTPCallViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                "SNOW003",
                self.VIOLATIONS["SNOW003"],
            )

        # Direct HTTP method calls (requests.get, etc.)
        if self._is_requests_http_method_call(node):
            return HTTPCallViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                "SNOW004",
                self.VIOLATIONS["SNOW004"],
            )

        # PoolManager().request() calls
        if self._is_poolmanager_request_call(node):
            return HTTPCallViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                "SNOW005",
                self.VIOLATIONS["SNOW005"],
            )

        return None

    def _is_requests_request_call(self, node: ast.AST) -> bool:
        """Check if node is a requests.request() call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "request"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
        )

    def _is_requests_session_instantiation(self, node: ast.AST) -> bool:
        """Check if node is a requests.Session() instantiation."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "Session"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
        )

    def _is_urllib3_poolmanager_instantiation(self, node: ast.AST) -> bool:
        """Check if node is a urllib3.PoolManager() instantiation."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "PoolManager"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "urllib3"
        )

    def _is_requests_http_method_call(self, node: ast.AST) -> bool:
        """Check if node is a direct HTTP method call on requests module."""
        http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in http_methods
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "requests"
        )

    def _is_poolmanager_request_call(self, node: ast.AST) -> bool:
        """Check if node is a PoolManager().request() or .request_encode_body() call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("request", "request_encode_body")
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Attribute)
            and node.func.value.func.attr == "PoolManager"
            and isinstance(node.func.value.func.value, ast.Name)
            and node.func.value.func.value.id == "urllib3"
        )


def main():
    """Main function for pre-commit hook."""
    parser = argparse.ArgumentParser(description="Check for native HTTP calls")
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    parser.add_argument(
        "--show-fixes", action="store_true", help="Show suggested fixes"
    )
    args = parser.parse_args()

    all_violations = []
    temp_exempt_files = []

    for filename in args.filenames:
        if not filename.endswith(".py"):
            continue

        checker = NoNativeHTTPChecker(filename)

        # Check for temporary exemptions
        temp_ticket = checker.is_temporarily_exempt()
        if temp_ticket:
            temp_exempt_files.append((filename, temp_ticket))
            continue

        violations = checker.check_file()
        all_violations.extend(violations)

    # Show warnings for temporarily exempt files
    if temp_exempt_files:
        print("⚠️  Files temporarily exempt from HTTP call checks:")
        for filename, ticket in temp_exempt_files:
            print(f"  {filename} (tracked in {ticket})")
        print()

    if all_violations:
        print("❌ Native HTTP call violations found:")
        print()

        for violation in all_violations:
            print(f"  {violation}")

        print()
        if args.show_fixes:
            print("💡 How to fix:")
            print("  - Replace requests.request() with session_manager.request()")
            print(
                "  - Replace requests.Session() with session_manager.use_requests_session()"
            )
            print(
                "  - Replace urllib3.PoolManager() with session from session_manager.use_requests_session()"
            )
            print("  - Use connection.rest.use_requests_session() when available")
            print()

        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
