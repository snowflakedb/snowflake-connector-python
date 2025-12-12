#!/usr/bin/env python3
"""
Pre-commit hook to prevent direct usage of requests, urllib3, and aiohttp calls.
Ensures all HTTP requests go through SessionManager.
"""

import argparse
import ast
import sys

from dataclasses import dataclass
from enum import Enum
from pathlib import PurePath


class ViolationType(Enum):
    """Types of HTTP violations."""

    REQUESTS_REQUEST = "SNOW001"
    REQUESTS_SESSION = "SNOW002"
    URLLIB3_POOLMANAGER = "SNOW003"
    REQUESTS_HTTP_METHOD = "SNOW004"
    DIRECT_HTTP_IMPORT = "SNOW006"
    DIRECT_POOL_IMPORT = "SNOW007"
    DIRECT_SESSION_IMPORT = "SNOW008"
    STAR_IMPORT = "SNOW010"
    URLLIB3_DIRECT_API = "SNOW011"
    AIOHTTP_CLIENT_SESSION = "SNOW012"
    AIOHTTP_REQUEST = "SNOW013"
    DIRECT_AIOHTTP_IMPORT = "SNOW014"


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


@dataclass(frozen=True)
class ImportInfo:
    """Information about an import statement."""

    module: str
    imported_name: str | None  # None for module imports
    alias_name: str
    line: int
    col: int


class ModulePattern:
    """Utility class for module pattern matching."""

    # Core module names
    REQUESTS_MODULES = {"requests"}
    URLLIB3_MODULES = {"urllib3"}
    AIOHTTP_MODULES = {"aiohttp"}

    # HTTP-related symbols
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
    URLLIB3_APIS = {"request", "urlopen", "HTTPConnectionPool", "HTTPSConnectionPool"}
    AIOHTTP_SESSIONS = {"ClientSession"}
    AIOHTTP_APIS = {"request"}

    @classmethod
    def is_requests_module(cls, module_or_symbol: str) -> bool:
        """Check if module or symbol is requests-related."""
        if not module_or_symbol:
            return False

        # Exact match
        if module_or_symbol in cls.REQUESTS_MODULES:
            return True

        # Dotted path ending in .requests
        if module_or_symbol.endswith(".requests"):
            return True

        # Known vendored paths
        if "vendored.requests" in module_or_symbol:
            return True

        return False

    @classmethod
    def is_urllib3_module(cls, module_or_symbol: str) -> bool:
        """Check if module or symbol is urllib3-related."""
        if not module_or_symbol:
            return False

        # Exact match
        if module_or_symbol in cls.URLLIB3_MODULES:
            return True

        # Dotted path ending in .urllib3
        if module_or_symbol.endswith(".urllib3"):
            return True

        # Known vendored paths
        if "vendored.urllib3" in module_or_symbol:
            return True

        return False

    @classmethod
    def is_aiohttp_module(cls, module_or_symbol: str) -> bool:
        """Check if module or symbol is aiohttp-related."""
        if not module_or_symbol:
            return False

        # Exact match
        if module_or_symbol in cls.AIOHTTP_MODULES:
            return True

        # Dotted path ending in .aiohttp
        if module_or_symbol.endswith(".aiohttp"):
            return True

        return False

    @classmethod
    def is_http_method(cls, name: str) -> bool:
        """Check if name is an HTTP method."""
        return name in cls.HTTP_METHODS

    @classmethod
    def is_pool_manager(cls, name: str) -> bool:
        """Check if name is a pool manager class."""
        return name in cls.POOL_MANAGERS

    @classmethod
    def is_urllib3_api(cls, name: str) -> bool:
        """Check if name is a urllib3 API function."""
        return name in cls.URLLIB3_APIS

    @classmethod
    def is_aiohttp_session(cls, name: str) -> bool:
        """Check if name is an aiohttp session class."""
        return name in cls.AIOHTTP_SESSIONS

    @classmethod
    def is_aiohttp_api(cls, name: str) -> bool:
        """Check if name is an aiohttp API function."""
        return name in cls.AIOHTTP_APIS


class ImportContext:
    """Tracks all import-related information."""

    def __init__(self):
        # Map alias_name -> ImportInfo
        self.imports: dict[str, ImportInfo] = {}

        # Track what's used where
        self.type_hint_usage: set[str] = set()
        self.runtime_usage: set[str] = set()

        # Track variable assignments (basic aliasing)
        self.variable_aliases: dict[str, str] = {}  # var_name -> original_name

        # Track star imports
        self.star_imports: set[str] = set()  # modules with star imports

        # Track TYPE_CHECKING context
        self.in_type_checking: bool = False
        self.type_checking_imports: set[str] = set()

    def add_import(self, import_info: ImportInfo):
        """Add an import."""
        self.imports[import_info.alias_name] = import_info

        # Mark TYPE_CHECKING imports
        if self.in_type_checking:
            self.type_checking_imports.add(import_info.alias_name)

    def add_star_import(self, module: str):
        """Add a star import."""
        self.star_imports.add(module)

    def add_type_hint_usage(self, name: str):
        """Mark a name as used in type hints."""
        self.type_hint_usage.add(name)

    def add_runtime_usage(self, name: str):
        """Mark a name as used at runtime."""
        self.runtime_usage.add(name)

    def add_variable_alias(self, var_name: str, original_name: str):
        """Track variable aliasing: var = original."""
        self.variable_aliases[var_name] = original_name

    def resolve_name(self, name: str) -> str:
        """Resolve a name through variable aliases transitively (A→B→C)."""
        seen = set()
        current = name
        max_depth = 10  # Prevent infinite loops

        while current in self.variable_aliases and current not in seen and max_depth > 0:
            seen.add(current)
            current = self.variable_aliases[current]
            max_depth -= 1

        return current

    def is_requests_related(self, name: str) -> bool:
        """Check if name refers to requests module or its components."""
        resolved_name = self.resolve_name(name)

        # Direct requests module
        if resolved_name == "requests":
            return True

        # Check import info
        if resolved_name in self.imports:
            import_info = self.imports[resolved_name]
            return ModulePattern.is_requests_module(import_info.module) or (
                import_info.imported_name and ModulePattern.is_requests_module(import_info.imported_name)
            )

        # Check star imports
        for module in self.star_imports:
            if ModulePattern.is_requests_module(module):
                return True

        return False

    def is_urllib3_related(self, name: str) -> bool:
        """Check if name refers to urllib3 module or its components."""
        resolved_name = self.resolve_name(name)

        # Direct urllib3 module
        if resolved_name == "urllib3":
            return True

        # Check import info
        if resolved_name in self.imports:
            import_info = self.imports[resolved_name]
            return ModulePattern.is_urllib3_module(import_info.module) or (
                import_info.imported_name and ModulePattern.is_urllib3_module(import_info.imported_name)
            )

        # Check star imports
        for module in self.star_imports:
            if ModulePattern.is_urllib3_module(module):
                return True

        return False

    def is_aiohttp_related(self, name: str) -> bool:
        """Check if name refers to aiohttp module or its components."""
        resolved_name = self.resolve_name(name)

        # Direct aiohttp module
        if resolved_name == "aiohttp":
            return True

        # Check import info
        if resolved_name in self.imports:
            import_info = self.imports[resolved_name]
            return ModulePattern.is_aiohttp_module(import_info.module) or (
                import_info.imported_name and ModulePattern.is_aiohttp_module(import_info.imported_name)
            )

        # Check star imports
        for module in self.star_imports:
            if ModulePattern.is_aiohttp_module(module):
                return True

        return False

    def is_runtime(self, name: str) -> bool:
        """Check if name is used at runtime (has actual runtime usage)."""
        return (
            name in self.runtime_usage and name not in self.type_checking_imports and name not in self.type_hint_usage
        )

    def get_import_location(self, name: str) -> tuple[int, int]:
        """Get line/col for an import."""
        if name in self.imports:
            import_info = self.imports[name]
            return import_info.line, import_info.col
        return 1, 0  # Fallback


class ASTHelper:
    """Helper functions for AST analysis."""

    @staticmethod
    def get_attribute_chain(node: ast.AST) -> list[str] | None:
        """Extract attribute chain from AST node (e.g., requests.sessions.Session -> ['requests', 'sessions', 'Session'])."""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)
            return list(reversed(parts))

        return None

    @staticmethod
    def is_type_checking_test(node: ast.expr) -> bool:
        """Check if expression is TYPE_CHECKING test."""
        if isinstance(node, ast.Name):
            return node.id == "TYPE_CHECKING"
        elif isinstance(node, ast.Attribute):
            chain = ASTHelper.get_attribute_chain(node)
            return chain and chain[-1] == "TYPE_CHECKING"
        return False


class ContextBuilder(ast.NodeVisitor):
    """First pass: builds complete import and usage context."""

    def __init__(self):
        self.context = ImportContext()

    def visit_Import(self, node: ast.Import):
        """Handle import statements."""
        for alias in node.names:
            module_name = alias.name
            alias_name = alias.asname if alias.asname else alias.name

            import_info = ImportInfo(
                module=module_name,
                imported_name=None,
                alias_name=alias_name,
                line=node.lineno,
                col=node.col_offset,
            )
            self.context.add_import(import_info)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Handle from...import statements."""
        if not node.module:
            self.generic_visit(node)
            return

        for alias in node.names:
            if alias.name == "*":
                self.context.add_star_import(node.module)
                continue

            import_name = alias.name
            alias_name = alias.asname if alias.asname else alias.name

            import_info = ImportInfo(
                module=node.module,
                imported_name=import_name,
                alias_name=alias_name,
                line=node.lineno,
                col=node.col_offset,
            )
            self.context.add_import(import_info)

        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """Handle if statements, tracking TYPE_CHECKING blocks."""
        is_type_checking = ASTHelper.is_type_checking_test(node.test)

        if is_type_checking:
            old_state = self.context.in_type_checking
            self.context.in_type_checking = True

            # Visit the body
            for stmt in node.body:
                self.visit(stmt)

            self.context.in_type_checking = old_state

            # Visit else clause normally
            for stmt in node.orelse:
                self.visit(stmt)
        else:
            self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """Handle variable assignments for basic aliasing and attribute aliasing."""
        if len(node.targets) == 1:
            target = node.targets[0]

            # Handle simple variable assignments: var = value
            if isinstance(target, ast.Name):
                var_name = target.id

                # Handle Name = Name aliasing (e.g., r = requests)
                if isinstance(node.value, ast.Name):
                    original_name = node.value.id
                    self.context.add_variable_alias(var_name, original_name)

                # Handle Name = Attribute aliasing (e.g., v = snowflake.connector.vendored.requests)
                elif isinstance(node.value, ast.Attribute):
                    dotted_chain = ASTHelper.get_attribute_chain(node.value)
                    if dotted_chain:
                        # Handle level1 = self.req_lib (where req_lib is already an alias)
                        if (
                            len(dotted_chain) == 2
                            and dotted_chain[0] == "self"
                            and dotted_chain[1] in self.context.variable_aliases
                        ):
                            # level1 gets the same alias as req_lib
                            aliased_module = self.context.variable_aliases[dotted_chain[1]]
                            self.context.add_variable_alias(var_name, aliased_module)
                        else:
                            # Handle v = snowflake.connector.vendored.requests
                            full_path = ".".join(dotted_chain)
                            # Check if this points to a requests, urllib3, or aiohttp module
                            if (
                                ModulePattern.is_requests_module(full_path)
                                or ModulePattern.is_urllib3_module(full_path)
                                or ModulePattern.is_aiohttp_module(full_path)
                            ):
                                self.context.add_variable_alias(var_name, full_path)

            # Handle attribute assignments: self.attr = value
            elif isinstance(target, ast.Attribute):
                # For self.req_lib = requests, track req_lib as an alias
                if (
                    isinstance(target.value, ast.Name)
                    and target.value.id == "self"
                    and isinstance(node.value, ast.Name)
                ):
                    attr_name = target.attr  # req_lib
                    original_name = node.value.id  # requests
                    self.context.add_variable_alias(attr_name, original_name)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """Handle annotated assignments."""
        if node.annotation:
            self._extract_type_names(node.annotation)

        # Handle assignment part for aliasing
        if isinstance(node.target, ast.Name) and node.value and isinstance(node.value, ast.Name):
            var_name = node.target.id
            original_name = node.value.id
            self.context.add_variable_alias(var_name, original_name)

        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Extract type hints from function definitions."""
        self._extract_function_types(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        """Extract type hints from async function definitions."""
        self._extract_function_types(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Track runtime usage of names."""
        self._track_runtime_usage(node)
        self.generic_visit(node)

    def _extract_function_types(self, node):
        """Extract type annotations from function signature."""
        # Return type
        if node.returns:
            self._extract_type_names(node.returns)

        # Parameter types
        for arg in node.args.args:
            if arg.annotation:
                self._extract_type_names(arg.annotation)

    def _extract_type_names(self, annotation_node):
        """Extract names from type annotations, including string annotations (PEP 563)."""
        if isinstance(annotation_node, ast.Name):
            self.context.add_type_hint_usage(annotation_node.id)
        elif isinstance(annotation_node, ast.Attribute):
            if isinstance(annotation_node.value, ast.Name):
                self.context.add_type_hint_usage(annotation_node.value.id)
        elif isinstance(annotation_node, ast.Subscript):
            self._extract_from_subscript(annotation_node)
        elif isinstance(annotation_node, ast.BinOp) and isinstance(annotation_node.op, ast.BitOr):
            # PEP 604 unions: Session | None
            self._extract_type_names(annotation_node.left)
            self._extract_type_names(annotation_node.right)
        elif isinstance(annotation_node, ast.Tuple):
            # Tuple types
            for elt in annotation_node.elts:
                self._extract_type_names(elt)
        elif isinstance(annotation_node, ast.Constant) and isinstance(annotation_node.value, str):
            # String annotations (PEP 563): "Session", "List[Session]", etc.
            self._extract_from_string_annotation(annotation_node.value)

    def _extract_from_string_annotation(self, annotation_str: str):
        """Parse string annotation and extract type names."""
        try:
            # Parse the string as a Python expression
            parsed = ast.parse(annotation_str, mode="eval")
            # Extract type names from the parsed expression
            self._extract_type_names(parsed.body)
        except SyntaxError:
            # If parsing fails, try simple name extraction
            # Handle basic cases like "Session", "Session | None"
            import re

            # Match Python identifiers that could be type names
            names = re.findall(r"\b([A-Z][a-zA-Z0-9_]*)\b", annotation_str)
            for name in names:
                if name in ["Session", "PoolManager", "ProxyManager", "ClientSession"]:
                    self.context.add_type_hint_usage(name)

    def _extract_from_subscript(self, node: ast.Subscript):
        """Extract type names from generic types."""
        # Base type (e.g., List in List[Session])
        if isinstance(node.value, ast.Name):
            self.context.add_type_hint_usage(node.value.id)

        # Handle subscript content
        if isinstance(node.slice, ast.Name):
            self.context.add_type_hint_usage(node.slice.id)
        elif isinstance(node.slice, ast.Tuple):
            for elt in node.slice.elts:
                self._extract_type_names(elt)
        elif hasattr(node.slice, "elts"):  # Older Python compatibility
            for elt in node.slice.elts:
                self._extract_type_names(elt)

    def _track_runtime_usage(self, node: ast.Call):
        """Track which names are used at runtime."""
        if isinstance(node.func, ast.Name):
            self.context.add_runtime_usage(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            chain = ASTHelper.get_attribute_chain(node.func)
            if chain:
                self.context.add_runtime_usage(chain[0])


class ViolationAnalyzer:
    """Second pass: analyzes violations using complete context."""

    def __init__(self, filename: str, context: ImportContext):
        self.filename = filename
        self.context = context
        self.violations: list[HTTPViolation] = []

    def analyze_imports(self):
        """Analyze import violations."""
        for _alias_name, import_info in self.context.imports.items():
            violations = self._check_import_violation(import_info)
            self.violations.extend(violations)

    def analyze_calls(self, tree: ast.AST):
        """Analyze call violations."""
        visitor = CallAnalyzer(self.filename, self.context, self.violations)
        visitor.visit(tree)

    def analyze_star_imports(self):
        """Analyze star import violations."""
        for module in self.context.star_imports:
            if (
                ModulePattern.is_requests_module(module)
                or ModulePattern.is_urllib3_module(module)
                or ModulePattern.is_aiohttp_module(module)
            ):
                self.violations.append(
                    HTTPViolation(
                        self.filename,
                        1,
                        0,  # Line info not preserved for star imports
                        ViolationType.STAR_IMPORT,
                        f"Star import from {module} is forbidden, import specific names and use SessionManager instead",
                    )
                )

    def _check_import_violation(self, import_info: ImportInfo) -> list[HTTPViolation]:
        """Check a single import for violations."""
        violations = []

        # Always flag HTTP method imports from requests
        if (
            import_info.imported_name
            and ModulePattern.is_requests_module(import_info.module)
            and ModulePattern.is_http_method(import_info.imported_name)
        ):
            violations.append(
                HTTPViolation(
                    self.filename,
                    import_info.line,
                    import_info.col,
                    ViolationType.DIRECT_HTTP_IMPORT,
                    f"Direct import of {import_info.imported_name} from requests is forbidden, use SessionManager instead",
                )
            )

        # Flag Session/PoolManager/ClientSession imports only if used at runtime
        if import_info.imported_name and self.context.is_runtime(import_info.alias_name):
            if ModulePattern.is_requests_module(import_info.module) and import_info.imported_name == "Session":
                violations.append(
                    HTTPViolation(
                        self.filename,
                        import_info.line,
                        import_info.col,
                        ViolationType.DIRECT_SESSION_IMPORT,
                        "Direct import of Session from requests for runtime use is forbidden, use SessionManager instead",
                    )
                )

            elif ModulePattern.is_urllib3_module(import_info.module) and ModulePattern.is_pool_manager(
                import_info.imported_name
            ):
                violations.append(
                    HTTPViolation(
                        self.filename,
                        import_info.line,
                        import_info.col,
                        ViolationType.DIRECT_POOL_IMPORT,
                        f"Direct import of {import_info.imported_name} from urllib3 for runtime use is forbidden, use SessionManager instead",
                    )
                )

            elif ModulePattern.is_aiohttp_module(import_info.module) and ModulePattern.is_aiohttp_session(
                import_info.imported_name
            ):
                violations.append(
                    HTTPViolation(
                        self.filename,
                        import_info.line,
                        import_info.col,
                        ViolationType.DIRECT_AIOHTTP_IMPORT,
                        f"Direct import of {import_info.imported_name} from aiohttp for runtime use is forbidden, use SessionManager instead",
                    )
                )

        return violations


class CallAnalyzer(ast.NodeVisitor):
    """Analyzes function calls for violations."""

    def __init__(self, filename: str, context: ImportContext, violations: list[HTTPViolation]):
        self.filename = filename
        self.context = context
        self.violations = violations

    def visit_Call(self, node: ast.Call):
        """Check function calls for violations."""
        violation = self._check_call_violation(node)
        if violation:
            self.violations.append(violation)

            # If this is a chained call, don't visit the inner call to avoid duplicates
            if self._is_chained_call(node):
                return

        self.generic_visit(node)

    def _check_call_violation(self, node: ast.Call) -> HTTPViolation | None:
        """Check a single call for violations."""
        # First check for chained calls like Session().get() or PoolManager().request()
        chained_violation = self._check_chained_calls(node)
        if chained_violation:
            return chained_violation

        # Get attribute chain
        chain = ASTHelper.get_attribute_chain(node.func)
        if not chain:
            return self._check_direct_call(node)

        # Handle various call patterns
        if len(chain) == 1:
            return self._check_direct_call(node)
        elif len(chain) == 2:
            return self._check_two_part_call(node, chain)
        else:
            return self._check_multi_part_call(node, chain)

    def _check_direct_call(self, node: ast.Call) -> HTTPViolation | None:
        """Check direct function calls."""
        if not isinstance(node.func, ast.Name):
            return None

        func_name = node.func.id
        resolved_name = self.context.resolve_name(func_name)

        # Check if it's a directly imported function
        if resolved_name in self.context.imports:
            import_info = self.context.imports[resolved_name]

            # HTTP methods from requests
            if (
                import_info.imported_name
                and ModulePattern.is_requests_module(import_info.module)
                and ModulePattern.is_http_method(import_info.imported_name)
            ):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.DIRECT_HTTP_IMPORT,
                    f"Direct use of imported {import_info.imported_name}() is forbidden, use SessionManager instead",
                )

            # Session/PoolManager/ClientSession instantiation
            if import_info.imported_name == "Session" and ModulePattern.is_requests_module(import_info.module):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.DIRECT_SESSION_IMPORT,
                    "Direct use of imported Session() is forbidden, use SessionManager instead",
                )

            if (
                import_info.imported_name
                and ModulePattern.is_pool_manager(import_info.imported_name)
                and ModulePattern.is_urllib3_module(import_info.module)
            ):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.DIRECT_POOL_IMPORT,
                    f"Direct use of imported {import_info.imported_name}() is forbidden, use SessionManager instead",
                )

            if (
                import_info.imported_name
                and ModulePattern.is_aiohttp_session(import_info.imported_name)
                and ModulePattern.is_aiohttp_module(import_info.module)
            ):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.AIOHTTP_CLIENT_SESSION,
                    f"Direct use of imported {import_info.imported_name}() is forbidden, use SessionManager instead",
                )

        # Check star imports
        for module in self.context.star_imports:
            if ModulePattern.is_requests_module(module) and ModulePattern.is_http_method(func_name):
                return HTTPViolation(
                    self.filename,
                    node.lineno,
                    node.col_offset,
                    ViolationType.STAR_IMPORT,
                    f"Use of {func_name}() from star import is forbidden, use SessionManager instead",
                )

        return None

    def _is_chained_call(self, node: ast.Call) -> bool:
        """Check if this is a chained call that we detected."""
        return isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call)

    def _check_chained_calls(self, node: ast.Call) -> HTTPViolation | None:
        """Check for chained calls like requests.Session().get(), urllib3.PoolManager().request(), or aiohttp.ClientSession().get()."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            inner_chain = ASTHelper.get_attribute_chain(node.func.value.func)
            if inner_chain and len(inner_chain) >= 2:
                inner_module, inner_func = inner_chain[0], inner_chain[-1]
                outer_method = node.func.attr

                # Check for requests.Session().method()
                if (
                    (inner_module == "requests" or self.context.is_requests_related(inner_module))
                    and inner_func == "Session"
                    and ModulePattern.is_http_method(outer_method)
                ):
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.REQUESTS_SESSION,
                        f"Chained call requests.Session().{outer_method}() is forbidden, use SessionManager instead",
                    )

                # Check for urllib3.PoolManager().method()
                if (
                    (inner_module == "urllib3" or self.context.is_urllib3_related(inner_module))
                    and ModulePattern.is_pool_manager(inner_func)
                    and outer_method in {"request", "urlopen", "request_encode_body"}
                ):
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.URLLIB3_POOLMANAGER,
                        f"Chained call urllib3.{inner_func}().{outer_method}() is forbidden, use SessionManager instead",
                    )

                # Check for aiohttp.ClientSession().method()
                if (
                    (inner_module == "aiohttp" or self.context.is_aiohttp_related(inner_module))
                    and ModulePattern.is_aiohttp_session(inner_func)
                    and ModulePattern.is_http_method(outer_method)
                ):
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.AIOHTTP_CLIENT_SESSION,
                        f"Chained call aiohttp.{inner_func}().{outer_method}() is forbidden, use SessionManager instead",
                    )

        return None

    def _check_two_part_call(self, node: ast.Call, chain: list[str]) -> HTTPViolation | None:
        """Check two-part calls like module.function or instance.method."""
        module_name, func_name = chain
        resolved_module = self.context.resolve_name(module_name)

        # Direct module calls
        if module_name == "requests" or self.context.is_requests_related(resolved_module):
            return self._check_requests_call(node, func_name)
        elif module_name == "urllib3" or self.context.is_urllib3_related(resolved_module):
            return self._check_urllib3_call(node, func_name)
        elif module_name == "aiohttp" or self.context.is_aiohttp_related(resolved_module):
            return self._check_aiohttp_call(node, func_name)

        # Check for aliased module calls (e.g., v = vendored.requests; v.get())
        if module_name in self.context.variable_aliases:
            aliased_module = self.context.variable_aliases[module_name]
            if ModulePattern.is_requests_module(aliased_module):
                return self._check_requests_call(node, func_name)
            elif ModulePattern.is_urllib3_module(aliased_module):
                return self._check_urllib3_call(node, func_name)
            elif ModulePattern.is_aiohttp_module(aliased_module):
                return self._check_aiohttp_call(node, func_name)

        return None

    def _check_multi_part_call(self, node: ast.Call, chain: list[str]) -> HTTPViolation | None:
        """Check multi-part calls like requests.sessions.Session, aiohttp.client.ClientSession or self.req_lib.get."""
        if len(chain) >= 3:
            module_name = chain[0]

            if module_name == "requests" or self.context.is_requests_related(module_name):
                # requests.sessions.Session, requests.api.request, etc.
                func_name = chain[-1]
                if func_name == "Session":
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.REQUESTS_SESSION,
                        f"Direct use of {'.'.join(chain)}() is forbidden, use SessionManager instead",
                    )
                elif ModulePattern.is_http_method(func_name):
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.REQUESTS_HTTP_METHOD,
                        f"Direct use of {'.'.join(chain)}() is forbidden, use SessionManager instead",
                    )

            elif module_name == "aiohttp" or self.context.is_aiohttp_related(module_name):
                # aiohttp.client.ClientSession, etc.
                func_name = chain[-1]
                if ModulePattern.is_aiohttp_session(func_name):
                    return HTTPViolation(
                        self.filename,
                        node.lineno,
                        node.col_offset,
                        ViolationType.AIOHTTP_CLIENT_SESSION,
                        f"Direct use of {'.'.join(chain)}() is forbidden, use SessionManager instead",
                    )

            # Check for aliased calls like self.req_lib.get() where req_lib is an alias
            elif len(chain) >= 3:
                # For patterns like self.req_lib.get(), check if req_lib is an alias
                potential_alias = chain[1]  # req_lib in self.req_lib.get
                func_name = chain[-1]  # get in self.req_lib.get

                if potential_alias in self.context.variable_aliases:
                    aliased_module = self.context.variable_aliases[potential_alias]
                    if ModulePattern.is_requests_module(aliased_module) and ModulePattern.is_http_method(func_name):
                        return HTTPViolation(
                            self.filename,
                            node.lineno,
                            node.col_offset,
                            ViolationType.REQUESTS_HTTP_METHOD,
                            f"Direct use of aliased {chain[0]}.{potential_alias}.{func_name}() is forbidden, use SessionManager instead",
                        )
                    elif ModulePattern.is_urllib3_module(aliased_module) and ModulePattern.is_pool_manager(func_name):
                        return HTTPViolation(
                            self.filename,
                            node.lineno,
                            node.col_offset,
                            ViolationType.URLLIB3_POOLMANAGER,
                            f"Direct use of aliased {chain[0]}.{potential_alias}.{func_name}() is forbidden, use SessionManager instead",
                        )
                    elif ModulePattern.is_aiohttp_module(aliased_module) and ModulePattern.is_aiohttp_session(
                        func_name
                    ):
                        return HTTPViolation(
                            self.filename,
                            node.lineno,
                            node.col_offset,
                            ViolationType.AIOHTTP_CLIENT_SESSION,
                            f"Direct use of aliased {chain[0]}.{potential_alias}.{func_name}() is forbidden, use SessionManager instead",
                        )

        return None

    def _check_requests_call(self, node: ast.Call, func_name: str) -> HTTPViolation | None:
        """Check requests module calls."""
        if func_name == "request":
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_REQUEST,
                "Direct use of requests.request() is forbidden, use SessionManager.request() instead",
            )
        elif func_name == "Session":
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_SESSION,
                "Direct use of requests.Session() is forbidden, use SessionManager.use_session() instead",
            )
        elif ModulePattern.is_http_method(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.REQUESTS_HTTP_METHOD,
                f"Direct use of requests.{func_name}() is forbidden, use SessionManager instead",
            )
        return None

    def _check_urllib3_call(self, node: ast.Call, func_name: str) -> HTTPViolation | None:
        """Check urllib3 module calls."""
        if ModulePattern.is_pool_manager(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.URLLIB3_POOLMANAGER,
                f"Direct use of urllib3.{func_name}() is forbidden, use SessionManager instead",
            )
        elif ModulePattern.is_urllib3_api(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.URLLIB3_DIRECT_API,
                f"Direct use of urllib3.{func_name}() is forbidden, use SessionManager instead",
            )
        return None

    def _check_aiohttp_call(self, node: ast.Call, func_name: str) -> HTTPViolation | None:
        """Check aiohttp module calls."""
        if ModulePattern.is_aiohttp_session(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.AIOHTTP_CLIENT_SESSION,
                f"Direct use of aiohttp.{func_name}() is forbidden, use SessionManager instead",
            )
        elif ModulePattern.is_aiohttp_api(func_name):
            return HTTPViolation(
                self.filename,
                node.lineno,
                node.col_offset,
                ViolationType.AIOHTTP_REQUEST,
                f"Direct use of aiohttp.{func_name}() is forbidden, use SessionManager instead",
            )
        return None


class FileChecker:
    """Handles file-level checking logic with proper glob path matching."""

    EXEMPT_PATTERNS = [
        "**/session_manager.py",
        "**/_session_manager.py",
        "**/vendored/**/*",
    ]

    TEST_PATTERNS = [
        "**/test/**",
        "**/*_test.py",
        "**/test_*.py",
        "**/conftest.py",
        "conftest.py",
        "**/mock_utils.py",
        "mock_utils.py",
    ]

    TEMPORARY_EXEMPT_PATTERNS = [
        ("**/auth/_oauth_base.py", "SNOW-2229411"),
        ("**/telemetry_oob.py", "SNOW-2259522"),
    ]

    def __init__(self, filename: str):
        self.filename = filename
        self.path = PurePath(filename)

    def is_exempt(self) -> bool:
        """Check if file is exempt from all checks."""
        # Check exempt patterns first
        if any(self.path.match(pattern) for pattern in self.EXEMPT_PATTERNS):
            return True

        # Check test patterns (exempt test files)
        if any(self.path.match(pattern) for pattern in self.TEST_PATTERNS):
            return True

        return False

    def get_temporary_exemption(self) -> str | None:
        """Get JIRA ticket for temporary exemption, if any."""
        temp_patterns = [pattern for pattern, _ in self.TEMPORARY_EXEMPT_PATTERNS]
        for i, pattern in enumerate(temp_patterns):
            if self.path.match(pattern):
                return self.TEMPORARY_EXEMPT_PATTERNS[i][1]
        return None

    def check_file(self) -> tuple[list[HTTPViolation], list[str]]:
        """Check a file for HTTP violations."""
        if self.is_exempt():
            return [], []

        temp_ticket = self.get_temporary_exemption()
        if temp_ticket:
            return [], []  # Handled by caller

        try:
            with open(self.filename, encoding="utf-8") as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return [], [f"Skipped {self.filename}: {e}"]

        try:
            tree = ast.parse(content)
        except SyntaxError as e:
            return [], [f"Skipped {self.filename}: syntax error at line {e.lineno}"]

        # Two-pass analysis
        # Pass 1: Build context
        context_builder = ContextBuilder()
        context_builder.visit(tree)

        # Pass 2: Analyze violations
        analyzer = ViolationAnalyzer(self.filename, context_builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)
        analyzer.analyze_star_imports()

        return analyzer.violations, []


def main():
    """Main function for pre-commit hook."""
    parser = argparse.ArgumentParser(description="Check for native HTTP calls")
    parser.add_argument("filenames", nargs="*", help="Filenames to check")
    parser.add_argument("--show-fixes", action="store_true", help="Show suggested fixes")
    args = parser.parse_args()

    all_violations = []
    temp_exempt_files = []
    skipped_files = []

    for filename in args.filenames:
        if not filename.endswith(".py"):
            continue

        checker = FileChecker(filename)

        # Check for temporary exemption first
        temp_ticket = checker.get_temporary_exemption()
        if temp_ticket:
            temp_exempt_files.append((filename, temp_ticket))
        else:
            violations, skip_messages = checker.check_file()
            all_violations.extend(violations)
            skipped_files.extend(skip_messages)

    # Show skipped files
    if skipped_files:
        print("Skipped files (syntax/encoding errors):")
        for message in skipped_files:
            print(f"  {message}")
        print()

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
            print("  - Replace requests.request() with SessionManager.request()")
            print("  - Replace requests.Session() with SessionManager.use_session()")
            print("  - Replace urllib3.PoolManager/ProxyManager() with session from session_manager.use_session()")
            print("  - Replace aiohttp.ClientSession() with async SessionManager.use_session()")
            print("  - Replace direct HTTP method imports with SessionManager usage")
            print("  - Use SessionManager for all HTTP operations (sync and async)")

        print()
        print(f"Found {len(all_violations)} violation(s)")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
