#!/usr/bin/env python3
"""
Pre-commit hook to prevent direct usage of requests and urllib3 calls.
Ensures all HTTP requests go through SessionManager.
"""
import argparse
import ast
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class ViolationType(Enum):
    """Types of HTTP violations."""

    REQUESTS_REQUEST = "SNOW001"
    REQUESTS_SESSION = "SNOW002"
    URLLIB3_POOLMANAGER = "SNOW003"
    REQUESTS_HTTP_METHOD = "SNOW004"
    POOLMANAGER_REQUEST = "SNOW005"
    DIRECT_HTTP_IMPORT = "SNOW006"
    DIRECT_POOL_IMPORT = "SNOW007"
    DIRECT_SESSION_IMPORT = "SNOW008"
    ALIASED_CALL = "SNOW009"


@dataclass(frozen=True)
class HTTPViolation:
    """Represents a violation of HTTP call restrictions."""

    filename: str
    line: int
    col: int
    violation_type: ViolationType
    message: str

    def __str__(self):
        return f"{self.filename}:{self.line}:{self.col}: {self.violation_type.value} {self.message}"


class ModulePattern:
    """Utility class for module pattern matching."""

    REQUESTS_MODULES = {"requests"}
    URLLIB3_MODULES = {"urllib3"}
    HTTP_METHODS = {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "request",
    }
    POOL_MANAGERS = {"PoolManager", "ProxyManager"}

    @classmethod
    def is_requests_module(cls, module: str) -> bool:
        """Check if module is requests-related (including vendored)."""
        return (
            module in cls.REQUESTS_MODULES
            or "requests" in module
            or module.endswith(".requests")
        )

    @classmethod
    def is_urllib3_module(cls, module: str) -> bool:
        """Check if module is urllib3-related (including vendored)."""
        return (
            module in cls.URLLIB3_MODULES
            or "urllib3" in module
            or module.endswith(".urllib3")
        )

    @classmethod
    def is_http_method(cls, name: str) -> bool:
        """Check if name is an HTTP method."""
        return name in cls.HTTP_METHODS

    @classmethod
    def is_pool_manager(cls, name: str) -> bool:
        """Check if name is a pool manager class."""
        return name in cls.POOL_MANAGERS


class ImportTracker:
    """Tracks imports and their usage context."""

    def __init__(self):
        self.aliases: Dict[str, Tuple[str, Optional[str]]] = {}
        self.direct_imports: Set[str] = set()
        self.direct_import_sources: Dict[str, str] = {}
        self.type_hint_only: Set[str] = set()
        self.runtime_usage: Set[str] = set()

    def add_import(
        self, alias_name: str, module: str, import_name: Optional[str] = None
    ):
        """Add an import mapping."""
        self.aliases[alias_name] = (module, import_name)
        if import_name:  # from module import name
            self.direct_imports.add(alias_name)
            self.direct_import_sources[alias_name] = module

    def add_type_hint_usage(self, name: str):
        """Mark a name as used in type hints."""
        self.type_hint_only.add(name)

    def add_runtime_usage(self, name: str):
        """Mark a name as used at runtime."""
        self.runtime_usage.add(name)

    def is_requests_related(self, name: str) -> bool:
        """Check if name refers to requests module or its components."""
        if name == "requests":
            return True
        if name in self.aliases:
            module, _ = self.aliases[name]
            return ModulePattern.is_requests_module(module)
        return False

    def is_urllib3_related(self, name: str) -> bool:
        """Check if name refers to urllib3 module or its components."""
        if name == "urllib3":
            return True
        if name in self.aliases:
            module, _ = self.aliases[name]
            return ModulePattern.is_urllib3_module(module)
        return False

    def get_import_source(self, name: str) -> Optional[str]:
        """Get the source module for a directly imported name."""
        return self.direct_import_sources.get(name)

    def is_runtime(self, name: str) -> bool:
        """Check if name is used at runtime (not just type hints)."""
        return name in self.runtime_usage or name not in self.type_hint_only


class ViolationDetector:
    """Detects different types of HTTP violations."""

    def __init__(self, filename: str, import_tracker: ImportTracker):
        self.filename = filename
        self.import_tracker = import_tracker

    def check_import_from(self, node: ast.ImportFrom) -> List[HTTPViolation]:
        """Check ImportFrom nodes for forbidden imports."""
        if not node.module:
            return []

        violations = []
        for alias in node.names:
            if alias.name == "*":
                continue

            violation = self._check_single_import(node, alias.name)
            if violation:
                violations.append(violation)

        return violations

    def _check_single_import(
        self, node: ast.ImportFrom, import_name: str
    ) -> Optional[HTTPViolation]:
        """Check a single import for violations."""
        # HTTP method imports from requests
        if ModulePattern.is_requests_module(
            node.module
        ) and ModulePattern.is_http_method(import_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.DIRECT_HTTP_IMPORT,
                "Direct import of HTTP methods from requests is forbidden, use SessionManager instead",
            )

        # Pool manager and Session imports are checked later in get_runtime_import_violations
        # to allow type hints usage

        return None

    def check_call(self, node: ast.Call) -> Optional[HTTPViolation]:
        """Check function calls for violations."""
        if isinstance(node.func, ast.Name):
            return self._check_direct_call(node)
        elif isinstance(node.func, ast.Attribute):
            return self._check_attribute_call(node)
        return None

    def _check_direct_call(self, node: ast.Call) -> Optional[HTTPViolation]:
        """Check direct function calls (from imports)."""
        func_name = node.func.id
        source_module = self.import_tracker.get_import_source(func_name)

        if not source_module:
            return None

        # HTTP method calls
        if ModulePattern.is_requests_module(
            source_module
        ) and ModulePattern.is_http_method(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.DIRECT_HTTP_IMPORT,
                f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
            )

        # Pool manager instantiation
        if ModulePattern.is_urllib3_module(
            source_module
        ) and ModulePattern.is_pool_manager(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.DIRECT_POOL_IMPORT,
                f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
            )

        # Session instantiation
        if ModulePattern.is_requests_module(source_module) and func_name == "Session":
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.DIRECT_SESSION_IMPORT,
                f"Direct use of imported '{func_name}()' is forbidden, use SessionManager instead",
            )

        return None

    def _check_attribute_call(self, node: ast.Call) -> Optional[HTTPViolation]:
        """Check attribute calls (module.function or alias.function)."""
        if not isinstance(node.func.value, ast.Name):
            return self._check_chained_call(node)

        obj_name = node.func.value.id
        attr_name = node.func.attr

        # Direct module calls (requests.get, urllib3.PoolManager)
        if obj_name == "requests":
            return self._check_requests_module_call(node, attr_name)
        elif obj_name == "urllib3":
            return self._check_urllib3_module_call(node, attr_name)

        # Aliased calls
        if self.import_tracker.is_requests_related(obj_name):
            return self._check_aliased_requests_call(node, obj_name, attr_name)
        elif self.import_tracker.is_urllib3_related(obj_name):
            return self._check_aliased_urllib3_call(node, obj_name, attr_name)

        return None

    def _check_requests_module_call(
        self, node: ast.Call, attr_name: str
    ) -> Optional[HTTPViolation]:
        """Check direct requests module calls."""
        if attr_name == "request":
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_REQUEST,
                "Direct use of requests.request() is forbidden, use SessionManager.request() instead",
            )
        elif attr_name == "Session":
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_SESSION,
                "Direct use of requests.Session() is forbidden, use SessionManager.use_requests_session() instead",
            )
        elif ModulePattern.is_http_method(attr_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_HTTP_METHOD,
                "Direct HTTP method calls (requests.get, etc.) are forbidden, use SessionManager instead",
            )
        return None

    def _check_urllib3_module_call(
        self, node: ast.Call, attr_name: str
    ) -> Optional[HTTPViolation]:
        """Check direct urllib3 module calls."""
        if ModulePattern.is_pool_manager(attr_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.URLLIB3_POOLMANAGER,
                "Direct use of urllib3.PoolManager/ProxyManager() is forbidden, use SessionManager instead",
            )
        return None

    def _check_aliased_requests_call(
        self, node: ast.Call, obj_name: str, attr_name: str
    ) -> Optional[HTTPViolation]:
        """Check aliased requests calls."""
        if attr_name in {"request", "Session"} or ModulePattern.is_http_method(
            attr_name
        ):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.ALIASED_CALL,
                f"Aliased requests.{attr_name}() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
            )
        return None

    def _check_aliased_urllib3_call(
        self, node: ast.Call, obj_name: str, attr_name: str
    ) -> Optional[HTTPViolation]:
        """Check aliased urllib3 calls."""
        if ModulePattern.is_pool_manager(attr_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.ALIASED_CALL,
                f"Aliased urllib3.{attr_name}() call ('{obj_name}.{attr_name}') is forbidden, use SessionManager instead",
            )
        return None

    def _check_chained_call(self, node: ast.Call) -> Optional[HTTPViolation]:
        """Check chained calls like PoolManager().request()."""
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Attribute)
            and isinstance(node.func.value.func.value, ast.Name)
        ):

            obj_name = node.func.value.func.value.id
            class_name = node.func.value.func.attr
            method_name = node.func.attr

            if (
                obj_name == "urllib3"
                and ModulePattern.is_pool_manager(class_name)
                and method_name in {"request", "request_encode_body"}
            ):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.POOLMANAGER_REQUEST,
                    "Direct use of PoolManager.request() is forbidden, use SessionManager instead",
                )
        return None

    def get_runtime_import_violations(self) -> List[HTTPViolation]:
        """Check for Session and PoolManager imports that are used at runtime."""
        violations = []

        for import_name in self.import_tracker.direct_imports:
            source_module = self.import_tracker.get_import_source(import_name)
            if not source_module:
                continue

            # Only flag Session imports that are used at runtime
            if (
                ModulePattern.is_requests_module(source_module)
                and import_name == "Session"
                and self.import_tracker.is_runtime(import_name)
            ):
                violations.append(
                    HTTPViolation(
                        self.filename,
                        1,
                        0,  # Line number not available for import analysis
                        ViolationType.DIRECT_SESSION_IMPORT,
                        "Direct import of Session from requests for runtime use is forbidden, use SessionManager instead",
                    )
                )

            # Only flag PoolManager/ProxyManager imports that are used at runtime
            if (
                ModulePattern.is_urllib3_module(source_module)
                and ModulePattern.is_pool_manager(import_name)
                and self.import_tracker.is_runtime(import_name)
            ):
                violations.append(
                    HTTPViolation(
                        self.filename,
                        1,
                        0,  # Line number not available for import analysis
                        ViolationType.DIRECT_POOL_IMPORT,
                        "Direct import of PoolManager/ProxyManager from urllib3 for runtime use is forbidden, use SessionManager instead",
                    )
                )

        return violations


class TypeHintExtractor(ast.NodeVisitor):
    """Extracts type hint information from AST nodes."""

    def __init__(self, import_tracker: ImportTracker):
        self.import_tracker = import_tracker

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Extract type hints from function definitions."""
        self._extract_from_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Extract type hints from async function definitions."""
        self._extract_from_function(node)
        self.generic_visit(node)

    def _extract_from_function(self, node):
        """Extract type hints from function signature."""
        # Return type annotation
        if node.returns:
            self._extract_type_names(node.returns)

        # Parameter type annotations
        for arg in node.args.args:
            if arg.annotation:
                self._extract_type_names(arg.annotation)

    def _extract_type_names(self, annotation_node):
        """Extract type names from annotation nodes."""
        if isinstance(annotation_node, ast.Name):
            self.import_tracker.add_type_hint_usage(annotation_node.id)
        elif isinstance(annotation_node, ast.Attribute):
            if isinstance(annotation_node.value, ast.Name):
                self.import_tracker.add_type_hint_usage(annotation_node.value.id)
        elif isinstance(annotation_node, ast.Subscript):
            self._extract_from_subscript(annotation_node)

    def _extract_from_subscript(self, node: ast.Subscript):
        """Extract type names from generic types like List[T], Generator[T, None, None]."""
        if isinstance(node.value, ast.Name):
            self.import_tracker.add_type_hint_usage(node.value.id)

        # Handle the subscript part
        if isinstance(node.slice, ast.Name):
            self.import_tracker.add_type_hint_usage(node.slice.id)
        elif hasattr(node.slice, "elts"):  # Tuple of types
            for elt in node.slice.elts:
                if isinstance(elt, ast.Name):
                    self.import_tracker.add_type_hint_usage(elt.id)


class HTTPAnalyzer(ast.NodeVisitor):
    """Main analyzer that orchestrates the detection process."""

    def __init__(self, filename: str):
        self.filename = filename
        self.import_tracker = ImportTracker()
        self.detector = ViolationDetector(filename, self.import_tracker)
        self.type_hint_extractor = TypeHintExtractor(self.import_tracker)
        self.violations: List[HTTPViolation] = []

    def visit_Import(self, node: ast.Import):
        """Handle import statements."""
        for alias in node.names:
            module_name = alias.name
            alias_name = alias.asname if alias.asname else alias.name
            self.import_tracker.add_import(alias_name, module_name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Handle from...import statements."""
        if node.module:
            for alias in node.names:
                if alias.name == "*":
                    continue

                import_name = alias.name
                alias_name = alias.asname if alias.asname else alias.name
                self.import_tracker.add_import(alias_name, node.module, import_name)

            # Check for import violations
            violations = self.detector.check_import_from(node)
            self.violations.extend(violations)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Handle function calls."""
        # Track runtime usage
        self._track_runtime_usage(node)

        # Check for violations
        violation = self.detector.check_call(node)
        if violation:
            self.violations.append(violation)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Handle function definitions for type hint extraction."""
        self.type_hint_extractor.visit_FunctionDef(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Handle async function definitions for type hint extraction."""
        self.type_hint_extractor.visit_AsyncFunctionDef(node)
        self.generic_visit(node)

    def _track_runtime_usage(self, node: ast.Call):
        """Track which imports are used at runtime."""
        if isinstance(node.func, ast.Name):
            self.import_tracker.add_runtime_usage(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Name
        ):
            self.import_tracker.add_runtime_usage(node.func.value.id)

    def get_all_violations(self) -> List[HTTPViolation]:
        """Get all violations including runtime import violations."""
        runtime_violations = self.detector.get_runtime_import_violations()
        return self.violations + runtime_violations


class FileChecker:
    """Handles file-level checking logic."""

    EXEMPT_PATTERNS = [
        "session_manager.py",
        "vendored/",
    ]

    TEST_PATTERNS = [
        "/test/",
        "test/",
        "conftest.py",
        "_test.py",
        "mock_utils.py",
    ]

    TEMPORARY_EXEMPT_PATTERNS = [
        ("auth/_oauth_base.py", "SNOW-2229411"),
        ("telemetry_oob.py", "SNOW-2259522"),
    ]

    def __init__(self, filename: str):
        self.filename = filename

    def is_exempt(self) -> bool:
        """Check if file is exempt from all checks."""
        return any(pattern in self.filename for pattern in self.EXEMPT_PATTERNS) or any(
            pattern in self.filename for pattern in self.TEST_PATTERNS
        )

    def get_temporary_exemption(self) -> Optional[str]:
        """Get JIRA ticket for temporary exemption, if any."""
        for pattern, ticket in self.TEMPORARY_EXEMPT_PATTERNS:
            if pattern in self.filename:
                return ticket
        return None

    def check_file(self) -> List[HTTPViolation]:
        """Check a file for HTTP violations."""
        if self.is_exempt():
            return []

        if self.get_temporary_exemption():
            return []  # Handled by caller

        try:
            with open(self.filename, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError):
            return []

        try:
            tree = ast.parse(content)
        except SyntaxError:
            return []

        analyzer = HTTPAnalyzer(self.filename)
        analyzer.visit(tree)
        return analyzer.get_all_violations()


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

        checker = FileChecker(filename)
        temp_ticket = checker.get_temporary_exemption()

        if temp_ticket:
            temp_exempt_files.append((filename, temp_ticket))
        else:
            violations = checker.check_file()
            all_violations.extend(violations)

    # Show temporary exemptions
    if temp_exempt_files:
        print("Files temporarily exempt from HTTP call checks:")
        for filename, ticket in temp_exempt_files:
            print(f"  {filename} (tracked in {ticket})")
        print()

    # Show violations
    if all_violations:
        print("Native HTTP call violations found:")
        print()

        for violation in all_violations:
            print(f"  {violation}")

        if args.show_fixes:
            print()
            print("How to fix:")
            print("  - Replace requests.request() with session_manager.request()")
            print(
                "  - Replace requests.Session() with session_manager.use_requests_session()"
            )
            print("  - Replace urllib3.PoolManager/ProxyManager() with SessionManager")
            print("  - Replace direct HTTP method imports with SessionManager usage")
            print("  - Use connection.rest.use_requests_session() when available")

        print()
        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
