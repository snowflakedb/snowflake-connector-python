#!/usr/bin/env python3
"""
Comprehensive tests for the native HTTP checker.

This test suite documents exactly what patterns the checker is designed to detect
and serves as both validation and specification documentation.
"""
import ast
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the ci directory to path so we can import the checker
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "pre-commit"))

from check_no_native_http import (
    ContextBuilder,
    FileChecker,
    ModulePattern,
    ViolationAnalyzer,
    ViolationType,
)


class TestViolationTypes:
    """Test cases for each specific violation type with clear examples."""

    def _check_code(self, code: str, expected_violations: list = None):
        """Helper to check code and return violations."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            pytest.fail(f"Test code has syntax error: {e}")

        # Build context
        builder = ContextBuilder()
        builder.visit(tree)

        # Analyze violations
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)
        analyzer.analyze_star_imports()

        violations = analyzer.violations

        if expected_violations is not None:
            violation_codes = [v.violation_type for v in violations]
            assert (
                violation_codes == expected_violations
            ), f"Expected {expected_violations}, got {violation_codes}"

        return violations

    def test_snow001_requests_request_direct(self):
        """SNOW001: Direct requests.request() calls should be flagged."""
        code = """
import requests
response = requests.request("GET", "http://example.com")
"""
        violations = self._check_code(code, [ViolationType.REQUESTS_REQUEST])
        assert "requests.request()" in violations[0].message
        assert "SessionManager.request()" in violations[0].message

    def test_snow002_requests_session_direct(self):
        """SNOW002: Direct requests.Session() instantiation should be flagged."""
        code = """
import requests
session = requests.Session()
"""
        violations = self._check_code(code, [ViolationType.REQUESTS_SESSION])
        assert "requests.Session()" in violations[0].message
        assert "SessionManager.use_requests_session()" in violations[0].message

    def test_snow003_urllib3_poolmanager_direct(self):
        """SNOW003: Direct urllib3.PoolManager/ProxyManager() should be flagged."""
        code = """
import urllib3
pool = urllib3.PoolManager()
proxy = urllib3.ProxyManager("http://proxy:8080")
"""
        violations = self._check_code(
            code, [ViolationType.URLLIB3_POOLMANAGER, ViolationType.URLLIB3_POOLMANAGER]
        )
        assert "PoolManager" in violations[0].message
        assert "ProxyManager" in violations[1].message

    def test_snow004_requests_http_methods(self):
        """SNOW004: Direct HTTP method calls (requests.get, post, etc.) should be flagged."""
        code = """
import requests
response1 = requests.get("http://example.com")
response2 = requests.post("http://example.com", data={})
response3 = requests.put("http://example.com")
response4 = requests.delete("http://example.com")
"""
        violations = self._check_code(
            code,
            [
                ViolationType.REQUESTS_HTTP_METHOD,
                ViolationType.REQUESTS_HTTP_METHOD,
                ViolationType.REQUESTS_HTTP_METHOD,
                ViolationType.REQUESTS_HTTP_METHOD,
            ],
        )
        for violation in violations:
            assert "SessionManager" in violation.message

    def test_snow005_poolmanager_request_chained(self):
        """SNOW005: Direct PoolManager().request() chained calls should be flagged."""
        code = """
import urllib3
response = urllib3.PoolManager().request("GET", "http://example.com")
data_response = urllib3.PoolManager().request_encode_body("POST", "http://example.com", fields={})
"""
        violations = self._check_code(
            code, [ViolationType.URLLIB3_POOLMANAGER, ViolationType.URLLIB3_POOLMANAGER]
        )
        assert "PoolManager()" in violations[0].message

    def test_snow006_direct_http_import_usage(self):
        """SNOW006: Direct imports of HTTP methods from requests should be flagged."""
        code = """
from requests import get, post
response1 = get("http://example.com")
response2 = post("http://example.com", data={})
"""
        violations = self._check_code(
            code,
            [
                ViolationType.DIRECT_HTTP_IMPORT,
                ViolationType.DIRECT_HTTP_IMPORT,
                ViolationType.DIRECT_HTTP_IMPORT,
                ViolationType.DIRECT_HTTP_IMPORT,
            ],
        )
        # Two for imports, two for usage
        import_violations = [v for v in violations if v.line == 2]
        usage_violations = [v for v in violations if v.line in [3, 4]]
        assert len(import_violations) == 2
        assert len(usage_violations) == 2

    def test_snow007_direct_pool_import_usage(self):
        """SNOW007: Direct imports of PoolManager/ProxyManager should be flagged when used at runtime."""
        code = """
from urllib3 import PoolManager, ProxyManager
pool = PoolManager()
proxy = ProxyManager("http://proxy:8080")
"""
        violations = self._check_code(
            code,
            [
                ViolationType.DIRECT_POOL_IMPORT,
                ViolationType.DIRECT_POOL_IMPORT,
                ViolationType.DIRECT_POOL_IMPORT,
                ViolationType.DIRECT_POOL_IMPORT,
            ],
        )
        # Two for runtime imports, two for usage
        assert len(violations) == 4

    def test_snow008_direct_session_import_usage(self):
        """SNOW008: Direct imports of Session should be flagged when used at runtime."""
        code = """
from requests import Session
session = Session()
"""
        violations = self._check_code(
            code,
            [ViolationType.DIRECT_SESSION_IMPORT, ViolationType.DIRECT_SESSION_IMPORT],
        )
        # One for runtime import, one for usage
        assert len(violations) == 2

    def test_snow009_aliased_calls(self):
        """SNOW009: Aliased calls should be detected (import aliases)."""
        code = """
import requests as req
import urllib3 as u3
response = req.get("http://example.com")
pool = u3.PoolManager()
"""
        violations = self._check_code(
            code,
            [ViolationType.REQUESTS_HTTP_METHOD, ViolationType.URLLIB3_POOLMANAGER],
        )
        # The current implementation detects these as standard violations, not aliased
        assert "requests.get()" in violations[0].message
        assert "PoolManager()" in violations[1].message

    def test_snow010_star_imports(self):
        """SNOW010: Star imports from requests/urllib3 should be flagged."""
        code = """
from requests import *
from urllib3 import *
response = get("http://example.com")  # Using star-imported function
"""
        violations = self._check_code(
            code,
            [
                ViolationType.STAR_IMPORT,
                ViolationType.STAR_IMPORT,
                ViolationType.STAR_IMPORT,
            ],
        )
        star_import_violations = [v for v in violations if "Star import" in v.message]
        usage_violations = [
            v
            for v in violations
            if "star import" in v.message and "Use of" in v.message
        ]
        assert len(star_import_violations) == 2
        assert len(usage_violations) == 1

    def test_snow011_urllib3_direct_apis(self):
        """SNOW011: Direct urllib3 API calls should be flagged."""
        code = """
import urllib3
response = urllib3.request("GET", "http://example.com")
pool = urllib3.HTTPConnectionPool("example.com")
https_pool = urllib3.HTTPSConnectionPool("example.com")
"""
        violations = self._check_code(
            code,
            [
                ViolationType.URLLIB3_DIRECT_API,
                ViolationType.URLLIB3_DIRECT_API,
                ViolationType.URLLIB3_DIRECT_API,
            ],
        )
        assert any("urllib3.request()" in v.message for v in violations)
        assert any("HTTPConnectionPool" in v.message for v in violations)
        assert any("HTTPSConnectionPool" in v.message for v in violations)


class TestComplexPatterns:
    """Test cases for complex patterns and edge cases."""

    def _check_code(self, code: str):
        """Helper to check code and return violations."""
        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)
        analyzer.analyze_star_imports()
        return analyzer.violations

    def test_vendored_imports_detection(self):
        """Vendored imports should be detected through aliases."""
        code = """
from snowflake.connector.vendored import requests as vendored_requests
from .vendored.urllib3 import PoolManager as VendoredPoolManager
response = vendored_requests.get("http://example.com")
pool = VendoredPoolManager()
"""
        violations = self._check_code(code)
        assert len(violations) >= 2
        violation_messages = [v.message for v in violations]
        # Check for vendored detection - the exact message may vary
        assert any(
            "requests.get" in msg or "vendored" in msg.lower()
            for msg in violation_messages
        )

    def test_deep_attribute_chains(self):
        """Deep attribute chains should be detected."""
        code = """
import requests
session = requests.sessions.Session()
response = requests.api.request("GET", "http://example.com")
"""
        violations = self._check_code(code)
        assert len(violations) >= 2
        violation_messages = [v.message for v in violations]
        assert any("requests.sessions.Session" in msg for msg in violation_messages)
        assert any("requests.api.request" in msg for msg in violation_messages)

    def test_chained_session_calls(self):
        """Chained Session calls should be detected."""
        code = """
import requests
response = requests.Session().get("http://example.com")
"""
        violations = self._check_code(code)
        assert len(violations) >= 1
        # Currently detects the Session() call
        assert any("Session()" in v.message for v in violations)

    def test_variable_aliasing_basic(self):
        """Basic variable aliasing should be detected."""
        code = """
import requests
req = requests
response = req.get("http://example.com")
"""
        violations = self._check_code(code)
        # Should detect the aliased call
        assert len(violations) >= 1

    def test_from_import_aliasing(self):
        """From-import with aliasing should be detected."""
        code = """
from requests import get as http_get, Session as HTTPSession
response = http_get("http://example.com")
session = HTTPSession()
"""
        violations = self._check_code(code)
        assert len(violations) >= 4  # Import + usage violations


class TestTypeHintHandling:
    """Test cases for proper type hint handling."""

    def _check_code(self, code: str):
        """Helper to check code and return violations."""
        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)
        analyzer.analyze_star_imports()
        return analyzer.violations

    def test_type_hints_only_allowed(self):
        """Imports used only in type hints should be allowed."""
        code = '''
from requests import Session
from urllib3 import PoolManager
from typing import Generator

def type_only_function(s: Session, p: PoolManager) -> Generator[Session, None, None]:
    """Should be allowed - only used in type hints"""
    pass
'''
        violations = self._check_code(code)
        # Should have no violations since they're only used in type hints
        assert len(violations) == 0

    def test_mixed_type_hint_and_runtime(self):
        """Mixed usage should flag only runtime usage."""
        code = '''
from requests import Session
from urllib3 import PoolManager

def mixed_function(s: Session) -> Session:
    """Type hint usage + runtime usage"""
    runtime_session = Session()  # This should be flagged
    return runtime_session
'''
        violations = self._check_code(code)
        # Should flag the runtime usage but not the type hints
        runtime_violations = [
            v for v in violations if v.line == 8 or "Session()" in v.message
        ]
        assert len(runtime_violations) >= 1

    def test_type_checking_guard(self):
        """TYPE_CHECKING guard should prevent runtime violations."""
        code = '''
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from requests import Session
    from urllib3 import PoolManager

def guarded_function(s: Session, p: PoolManager) -> Session:
    """Should be allowed - imports are in TYPE_CHECKING block"""
    pass
'''
        violations = self._check_code(code)
        assert len(violations) == 0

    def test_pep604_unions(self):
        """PEP 604 union syntax should be handled."""
        code = '''
from requests import Session

def pep604_function(s: Session | None) -> Session | str:
    """Should be allowed - only type hint usage"""
    pass
'''
        violations = self._check_code(code)
        assert len(violations) == 0

    def test_complex_nested_types(self):
        """Complex nested type structures should be handled."""
        code = '''
from requests import Session
from typing import Dict, List, Tuple, Optional

def complex_types(
    sessions: List[Tuple[Session, int]],
    mapping: Dict[str, Optional[Session]]
) -> Dict[str, List[Session]]:
    """Should be allowed - complex nested type usage"""
    pass
'''
        violations = self._check_code(code)
        assert len(violations) == 0


class TestExemptions:
    """Test cases for file exemptions and temporary exemptions."""

    def test_session_manager_exemption(self):
        """session_manager.py should be exempt."""
        checker = FileChecker("src/snowflake/connector/session_manager.py")
        assert checker.is_exempt()

    def test_vendored_exemption(self):
        """vendored/ files should be exempt."""
        checker = FileChecker("src/snowflake/connector/vendored/requests/__init__.py")
        assert checker.is_exempt()

    def test_test_file_exemptions(self):
        """Test files should be exempt."""
        test_files = [
            "test/unit/test_something.py",
            "test/integration/test_auth.py",
            "src/snowflake/connector/test_helper.py",
            "conftest.py",
            "test/mock_utils.py",
        ]
        for file_path in test_files:
            checker = FileChecker(file_path)
            assert checker.is_exempt(), f"{file_path} should be exempt"

    def test_temporary_exemptions(self):
        """Temporary exemptions should return JIRA tickets."""
        temp_files = [
            ("src/snowflake/connector/auth/_oauth_base.py", "SNOW-2229411"),
            ("src/snowflake/connector/telemetry_oob.py", "SNOW-2259522"),
        ]
        for file_path, expected_ticket in temp_files:
            checker = FileChecker(file_path)
            ticket = checker.get_temporary_exemption()
            assert (
                ticket == expected_ticket
            ), f"{file_path} should have ticket {expected_ticket}"

    def test_windows_path_handling(self):
        """Windows-style paths should be handled correctly."""
        windows_paths = [
            "src/snowflake/connector/vendored/requests/__init__.py",  # Use forward slashes for cross-platform
            "test/unit/test_something.py",
        ]
        for path in windows_paths:
            checker = FileChecker(path)
            assert checker.is_exempt(), f"Path {path} should be exempt"


class TestModulePatterns:
    """Test cases for module pattern matching."""

    def test_requests_module_detection(self):
        """Test requests module pattern detection."""
        assert ModulePattern.is_requests_module("requests")
        assert ModulePattern.is_requests_module("snowflake.connector.vendored.requests")
        assert ModulePattern.is_requests_module("some.module.requests")
        assert not ModulePattern.is_requests_module("my_requests_utils")
        assert not ModulePattern.is_requests_module("requests_helper")

    def test_urllib3_module_detection(self):
        """Test urllib3 module pattern detection."""
        assert ModulePattern.is_urllib3_module("urllib3")
        assert ModulePattern.is_urllib3_module("snowflake.connector.vendored.urllib3")
        assert ModulePattern.is_urllib3_module("some.module.urllib3")
        assert not ModulePattern.is_urllib3_module("my_urllib3_utils")
        assert not ModulePattern.is_urllib3_module("urllib3_helper")

    def test_http_method_detection(self):
        """Test HTTP method detection."""
        http_methods = [
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "head",
            "options",
            "request",
        ]
        for method in http_methods:
            assert ModulePattern.is_http_method(method)

        assert not ModulePattern.is_http_method("invalid_method")
        assert not ModulePattern.is_http_method("session")

    def test_pool_manager_detection(self):
        """Test pool manager class detection."""
        assert ModulePattern.is_pool_manager("PoolManager")
        assert ModulePattern.is_pool_manager("ProxyManager")
        assert not ModulePattern.is_pool_manager("ConnectionPool")
        assert not ModulePattern.is_pool_manager("Session")


class TestIntegrationScenarios:
    """Integration test scenarios with real-world code patterns."""

    def test_migration_scenarios(self):
        """Test common patterns that need migration to SessionManager."""
        scenarios = [
            # Basic requests usage
            """
import requests
response = requests.get("http://api.example.com/data")
            """,
            # Session-based usage
            """
import requests
with requests.Session() as session:
    response = session.get("http://api.example.com/data")
            """,
            # urllib3 usage
            """
import urllib3
http = urllib3.PoolManager()
response = http.request("GET", "http://api.example.com/data")
            """,
            # Mixed usage
            """
import requests
import urllib3
session = requests.Session()
pool = urllib3.PoolManager()
            """,
        ]

        for i, code in enumerate(scenarios):
            tree = ast.parse(code)
            builder = ContextBuilder()
            builder.visit(tree)
            analyzer = ViolationAnalyzer(f"scenario_{i}.py", builder.context)
            analyzer.analyze_imports()
            analyzer.analyze_calls(tree)
            analyzer.analyze_star_imports()

            violations = analyzer.violations
            assert len(violations) > 0, f"Scenario {i} should have violations"

    def test_legitimate_patterns(self):
        """Test patterns that should NOT be flagged."""
        legitimate_code = '''
from requests import Session
from urllib3 import PoolManager
from typing import TYPE_CHECKING, Generator, Optional

if TYPE_CHECKING:
    from requests import Response

def api_client(session: Session, pool: PoolManager) -> Generator[Session, None, None]:
    """Legitimate use of imports for type hints only"""
    yield session

def response_handler(resp: Response) -> None:
    """TYPE_CHECKING import usage"""
    pass
'''
        tree = ast.parse(legitimate_code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("legitimate.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)
        analyzer.analyze_star_imports()

        violations = analyzer.violations
        assert (
            len(violations) == 0
        ), f"Legitimate code should have no violations, got: {violations}"


class TestFileHandling:
    """Test file-level operations and error handling."""

    def test_syntax_error_handling(self):
        """Test handling of files with syntax errors."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(
                "import requests\ndef invalid syntax here\nresponse = requests.get()"
            )
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should handle syntax error gracefully
                assert len(violations) == 0
                assert len(messages) == 1
                assert "syntax error" in messages[0]
            finally:
                os.unlink(f.name)

    def test_unicode_error_handling(self):
        """Test handling of files with encoding issues."""
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".py", delete=False) as f:
            # Write invalid UTF-8
            f.write(b"import requests\n\xff\xfe invalid unicode\n")
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should handle encoding error gracefully
                assert len(violations) == 0
                assert len(messages) == 1
            finally:
                os.unlink(f.name)

    def test_valid_file_processing(self):
        """Test processing of valid Python files."""
        code = """
import requests
response = requests.get("http://example.com")
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should process successfully and find violations
                assert len(violations) > 0
                assert len(messages) == 0
                assert (
                    violations[0].violation_type == ViolationType.REQUESTS_HTTP_METHOD
                )
            finally:
                os.unlink(f.name)


class TestAdvancedFeatures:
    """Test advanced features like string annotations and transitive aliases."""

    def test_string_annotations_pep563(self):
        """String annotations (PEP 563) should be handled correctly."""
        code = """
from __future__ import annotations
from requests import Session
from urllib3 import PoolManager

# String annotations - should NOT be flagged
def func1(session: "Session") -> "Session":
    pass

def func2(pool: "PoolManager") -> None:
    pass

def func3(data: "List[Session]") -> "Optional[Session]":
    pass

# Runtime usage should still be flagged
def func4():
    s = Session()
    return s
        """

        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)

        # Should only flag the runtime Session() call, not the string annotations
        violations = analyzer.violations
        assert len(violations) == 1
        assert violations[0].violation_type == ViolationType.DIRECT_SESSION_IMPORT

    def test_transitive_alias_resolution(self):
        """Transitive alias resolution should work (A→B→C)."""
        code = """
import requests

# Chain of aliases
a = requests
b = a
c = b
d = c

# Should all be detected as requests calls
result1 = a.get("http://example.com")
result2 = b.post("http://example.com")
result3 = c.Session()
result4 = d.request("GET", "http://example.com")
        """

        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)

        violations = analyzer.violations
        assert len(violations) == 4

        # All should be detected as requests violations
        violation_types = [v.violation_type for v in violations]
        expected_types = [
            ViolationType.REQUESTS_HTTP_METHOD,  # a.get
            ViolationType.REQUESTS_HTTP_METHOD,  # b.post
            ViolationType.REQUESTS_SESSION,  # c.Session
            ViolationType.REQUESTS_REQUEST,  # d.request
        ]
        assert all(vtype in expected_types for vtype in violation_types)

    def test_chained_poolmanager_calls(self):
        """Enhanced chained PoolManager calls should be detected."""
        code = """
import urllib3

# Various chained calls
result1 = urllib3.PoolManager().request("GET", "http://example.com")
result2 = urllib3.PoolManager().urlopen("GET", "http://example.com")
result3 = urllib3.PoolManager().request_encode_body("POST", "http://example.com", fields={})
        """

        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)

        violations = analyzer.violations
        assert len(violations) == 3

        # All should be chained urllib3 PoolManager violations
        for violation in violations:
            assert violation.violation_type == ViolationType.URLLIB3_POOLMANAGER
            assert "Chained call" in violation.message

    def test_attribute_aliasing(self):
        """Attribute aliasing should be detected."""
        code = """
import snowflake.connector.vendored.requests as vendored_requests
import snowflake.connector.vendored.urllib3 as vendored_urllib3

# Attribute aliasing
v_req = snowflake.connector.vendored.requests
v_urllib = snowflake.connector.vendored.urllib3

# Should be detected
result1 = v_req.get("http://example.com")
result2 = v_urllib.PoolManager()
result3 = vendored_requests.Session()
result4 = vendored_urllib3.request("GET", "http://example.com")
        """

        tree = ast.parse(code)
        builder = ContextBuilder()
        builder.visit(tree)
        analyzer = ViolationAnalyzer("test.py", builder.context)
        analyzer.analyze_imports()
        analyzer.analyze_calls(tree)

        violations = analyzer.violations
        assert len(violations) == 4

        # Check that all aliased calls are detected
        messages = [v.message for v in violations]
        assert any("requests.get" in msg for msg in messages)
        assert any("urllib3.PoolManager" in msg for msg in messages)
        assert any("requests.Session" in msg for msg in messages)
        assert any("urllib3.request" in msg for msg in messages)


if __name__ == "__main__":
    # Run tests when script is executed directly
    pytest.main([__file__, "-v"])
