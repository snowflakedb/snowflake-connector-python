#!/usr/bin/env python3
"""
Enhanced pre-commit hook to prevent direct usage of requests and urllib3 calls.
Ensures all HTTP requests go through SessionManager.
This version tracks imports and catches alias patterns in a single AST pass.
"""
import argparse
import ast
import sys
from typing import Dict, List, Optional, Set, Tuple


class HTTPCallViolation:
    def __init__(self, filename: str, line: int, col: int, code: str, message: str):
        self.filename = filename
        self.line = line
        self.col = col
        self.code = code
        self.message = message

    def __str__(self):
        return f"{self.filename}:{self.line}:{self.col}: {self.code} {self.message}"


class SinglePassChecker(ast.NodeVisitor):
    """Single-pass AST visitor that tracks imports and finds violations simultaneously."""

    def __init__(self, filename: str):
        self.filename = filename
        self.violations: List[HTTPCallViolation] = []

        # Import tracking
        self.aliases: Dict[str, Tuple[str, Optional[str]]] = {}
        self.direct_imports: Set[str] = set()
        self.direct_import_sources: Dict[str, str] = {}

        # Violation definitions
        self.VIOLATIONS = {
            "SNOW001": "Direct use of requests.request() is forbidden, use SessionManager.request() instead",
            "SNOW002": "Direct use of requests.Session() is forbidden, use SessionManager.use_requests_session() instead",
            "SNOW003": "Direct use of urllib3.PoolManager() is forbidden, use SessionManager instead",
            "SNOW004": "Direct HTTP method calls (requests.get, etc.) are forbidden, use SessionManager instead",
            "SNOW005": "Direct use of PoolManager.request() is forbidden, use SessionManager instead",
            "SNOW006": "Direct import of HTTP methods from requests is forbidden, use SessionManager instead",
            "SNOW007": "Direct import of PoolManager from urllib3 is forbidden, use SessionManager instead",
            "SNOW008": "Direct import of Session from requests is forbidden, use SessionManager instead",
            "SNOW009": "Use of aliased requests/urllib3 calls is forbidden, use SessionManager instead",
        }

    def visit_Import(self, node: ast.Import):
        """Handle 'import module as alias' statements."""
        for alias in node.names:
            module_name = alias.name
            alias_name = alias.asname if alias.asname else alias.name
            self.aliases[alias_name] = (module_name, None)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Handle 'from module import name as alias' statements."""
        if node.module:
            # Track imports
            for alias in node.names:
                if alias.name == "*":
                    continue

                import_name = alias.name
                alias_name = alias.asname if alias.asname else alias.name

                self.aliases[alias_name] = (node.module, import_name)
                self.direct_imports.add(alias_name)
                self.direct_import_sources[alias_name] = node.module

            # Check for violations in import statement itself
            violation = self._check_import_from_violation(node)
            if violation:
                self.violations.append(violation)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Handle function calls."""
        violation = self._check_call_violation(node)
        if violation:
            self.violations.append(violation)
        self.generic_visit(node)

    def _check_import_from_violation(
        self, node: ast.ImportFrom
    ) -> Optional[HTTPCallViolation]:
        """Check ImportFrom nodes for forbidden imports."""
        for alias in node.names:
            if alias.name == "*":
                continue

            import_name = alias.name

            # Check for HTTP method imports from requests
            if self._is_requests_module(node.module) and import_name in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "request",
            }:
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW006",
                    self.VIOLATIONS["SNOW006"],
                )

            # Check for PoolManager import from urllib3
            if self._is_urllib3_module(node.module) and import_name == "PoolManager":
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW007",
                    self.VIOLATIONS["SNOW007"],
                )

            # Check for Session import from requests
            if self._is_requests_module(node.module) and import_name == "Session":
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW008",
                    self.VIOLATIONS["SNOW008"],
                )

        return None

    def _check_call_violation(self, node: ast.Call) -> Optional[HTTPCallViolation]:
        """Check Call nodes for violations."""

        # Direct function calls (e.g., get(), post() from direct imports)
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            # Check if it's a directly imported HTTP method
            if self._is_direct_http_method(func_name):
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW006",
                    f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
                )

            # Check if it's a directly imported PoolManager
            if self._is_direct_poolmanager(func_name):
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW007",
                    f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
                )

            # Check if it's a directly imported Session
            if self._is_direct_session(func_name):
                return HTTPCallViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    "SNOW008",
                    f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
                )

        # Attribute calls (e.g., req.get(), alias.PoolManager())
        elif isinstance(node.func, ast.Attribute):
            return self._check_attribute_call_violation(node)

        return None

    def _check_attribute_call_violation(
        self, node: ast.Call
    ) -> Optional[HTTPCallViolation]:
        """Check attribute calls for violations."""
        if not isinstance(node.func, ast.Attribute):
            return None

        attr_name = node.func.attr

        # Get the object being called
        if isinstance(node.func.value, ast.Name):
            obj_name = node.func.value.id

            # Check for aliased requests calls
            if self._is_requests_related(obj_name):
                if attr_name == "request":
                    return HTTPCallViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        "SNOW009",
                        f"Aliased requests.request() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
                    )
                elif attr_name == "Session":
                    return HTTPCallViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        "SNOW009",
                        f"Aliased requests.Session() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
                    )
                elif attr_name in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                }:
                    return HTTPCallViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        "SNOW009",
                        f"Aliased requests.{attr_name}() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
                    )

            # Check for aliased urllib3 calls
            elif self._is_urllib3_related(obj_name):
                if attr_name == "PoolManager":
                    return HTTPCallViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        "SNOW009",
                        f"Aliased urllib3.PoolManager() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
                    )

        # Original checks for direct module usage (fallback)
        return self._check_original_patterns(node)

    def _check_original_patterns(self, node: ast.Call) -> Optional[HTTPCallViolation]:
        """Check original patterns for backward compatibility."""
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

    # Helper methods for checking patterns
    def _is_requests_related(self, name: str) -> bool:
        """Check if a name refers to requests module or its components."""
        if name in self.aliases:
            module, _ = self.aliases[name]
            return self._is_requests_module(module)
        return name == "requests"

    def _is_urllib3_related(self, name: str) -> bool:
        """Check if a name refers to urllib3 module or its components."""
        if name in self.aliases:
            module, _ = self.aliases[name]
            return self._is_urllib3_module(module)
        return name == "urllib3"

    def _is_direct_http_method(self, name: str) -> bool:
        """Check if name is a directly imported HTTP method."""
        if name in self.direct_import_sources:
            source_module = self.direct_import_sources[name]
            return self._is_requests_module(source_module) and name in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "request",
            }
        return False

    def _is_direct_poolmanager(self, name: str) -> bool:
        """Check if name is a directly imported PoolManager."""
        if name in self.direct_import_sources:
            source_module = self.direct_import_sources[name]
            return self._is_urllib3_module(source_module) and name == "PoolManager"
        return False

    def _is_direct_session(self, name: str) -> bool:
        """Check if name is a directly imported Session."""
        if name in self.direct_import_sources:
            source_module = self.direct_import_sources[name]
            return self._is_requests_module(source_module) and name == "Session"
        return False

    def _is_requests_module(self, module: str) -> bool:
        """Check if module is requests-related (including vendored)."""
        return (
            module == "requests" or "requests" in module or module.endswith(".requests")
        )

    def _is_urllib3_module(self, module: str) -> bool:
        """Check if module is urllib3-related (including vendored)."""
        return module == "urllib3" or "urllib3" in module or module.endswith(".urllib3")

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


class OptimizedNoNativeHTTPChecker:
    """Optimized checker using single-pass AST traversal."""

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
        ("telemetry_oob.py", "SNOW-2259522"),
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
        """Check a file for HTTP call violations using single-pass AST traversal."""
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

        # Single pass: collect imports and check violations simultaneously
        visitor = SinglePassChecker(self.filename)
        visitor.visit(tree)

        return visitor.violations


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

        checker = OptimizedNoNativeHTTPChecker(filename)

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
            print("  - Replace urllib3.PoolManager() with SessionManager")
            print("  - Replace direct HTTP method imports with SessionManager usage")
            print("  - Use connection.rest.use_requests_session() when available")
            print()

        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
