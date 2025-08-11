#!/usr/bin/env python3
"""
Tests for the native HTTP checker run in pre-commit to enforce using SessionManager.
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


class TestEndToEndScenarios:
    """End-to-end tests using temporary files with complete code examples."""

    def test_real_world_migration_file(self):
        """Test a realistic file that needs migration to SessionManager."""
        code = '''
"""Module that demonstrates various HTTP patterns needing migration."""
import requests
import urllib3
from requests import Session, get as requests_get
from urllib3 import PoolManager
import json
import logging

logger = logging.getLogger(__name__)


class HTTPClient:
    def __init__(self):
        # These should be flagged
        self.session = requests.Session()
        self.pool = urllib3.PoolManager()

    def fetch_data(self, url: str):
        """Fetch data using various HTTP methods."""
        # Direct requests calls - should be flagged
        response1 = requests.get(url)
        response2 = requests.post(url, json={"test": "data"})

        # Session calls - should be flagged
        response3 = self.session.get(url)

        # urllib3 calls - should be flagged
        response4 = self.pool.request("GET", url)

        # Imported function calls - should be flagged
        response5 = requests_get(url)

        return [response1, response2, response3, response4, response5]

    def complex_patterns(self):
        """More complex patterns."""
        # Chained calls - should be flagged
        data1 = requests.Session().get("http://api.example.com").json()
        data2 = urllib3.PoolManager().request("POST", "http://api.example.com")

        # Variable aliasing - should be flagged
        req_lib = requests
        response = req_lib.get("http://example.com")

        return data1, data2, response


def standalone_function():
    """Standalone function with HTTP calls."""
    # These should all be flagged
    http = urllib3.PoolManager()
    session = Session()

    response1 = http.urlopen("GET", "http://example.com")
    response2 = session.post("http://example.com", data={})

    return response1, response2
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should find many violations in this realistic code
                assert (
                    len(violations) >= 12
                ), f"Expected many violations, got {len(violations)}"
                assert len(messages) == 0, "Should not have any error messages"

                # Check that different violation types are detected
                violation_types = {v.violation_type for v in violations}
                expected_types = {
                    ViolationType.REQUESTS_SESSION,
                    ViolationType.URLLIB3_POOLMANAGER,
                    ViolationType.REQUESTS_HTTP_METHOD,
                    ViolationType.DIRECT_HTTP_IMPORT,
                    ViolationType.DIRECT_SESSION_IMPORT,
                    ViolationType.DIRECT_POOL_IMPORT,
                }

                # Should detect multiple types of violations
                assert len(violation_types & expected_types) >= 4

            finally:
                os.unlink(f.name)

    def test_legitimate_production_code(self):
        """Test code that should NOT be flagged."""
        code = '''
"""Legitimate production code using SessionManager and type hints."""
from __future__ import annotations
from typing import Optional, List, Union
from requests import Session  # Used only for type hints
from urllib3 import PoolManager  # Used only for type hints
import json

from snowflake.connector.session_manager import SessionManager


class HTTPService:
    """Service using SessionManager correctly."""

    def __init__(self):
        self.session_manager = SessionManager()

    def get_data(self, url: str) -> Optional[dict]:
        """Fetch data using SessionManager."""
        # This should NOT be flagged - using SessionManager
        response = self.session_manager.request("GET", url)
        return response.json() if response.status_code == 200 else None

    def post_data(self, url: str, data: dict) -> bool:
        """Post data using SessionManager."""
        # This should NOT be flagged - using SessionManager
        session = self.session_manager.use_requests_session()
        response = session.post(url, json=data)
        return response.status_code == 201


def process_responses(responses: List[Session]) -> None:
    """Process responses - Session used only in type hint."""
    for response in responses:
        print(f"Processing response: {response}")


def create_pool_manager() -> PoolManager:
    """Return a pool manager - PoolManager used only in type hint."""
    # This should NOT be flagged - returning from SessionManager
    return SessionManager().get_pool_manager()


class APIClient:
    """API client with proper type annotations."""

    def __init__(self, session: Session | None = None):
        """Initialize with optional session parameter."""
        self.session_manager = SessionManager()
        self._session = session

    def configure(self, pool: Optional[PoolManager] = None) -> None:
        """Configure with optional pool parameter."""
        if pool:
            self.session_manager.configure_pool(pool)


# String annotations (PEP 563) - should NOT be flagged
def handle_session(s: "Session") -> "Optional[Session]":
    return s if s else None

def handle_pool(p: "PoolManager") -> "Union[PoolManager, None]":
    return p
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should find NO violations in legitimate code
                assert (
                    len(violations) == 0
                ), f"Expected no violations, got {[str(v) for v in violations]}"
                assert len(messages) == 0, "Should not have any error messages"

            finally:
                os.unlink(f.name)

    def test_complex_aliasing_chains(self):
        """Test complex aliasing patterns that should be detected."""
        code = '''
"""Complex aliasing patterns."""
import requests
import urllib3
import snowflake.connector.vendored.requests as vendored_req

# Multi-level aliasing
level1 = requests
level2 = level1
level3 = level2
final = level3

# Attribute aliasing
vendor_req = snowflake.connector.vendored.requests
vendor_urllib = snowflake.connector.vendored.urllib3

# Mixed patterns
def test_all_aliases():
    # Transitive aliases - should be flagged
    result1 = final.get("http://example.com")
    result2 = level2.Session()
    result3 = level1.request("POST", "http://example.com")

    # Attribute aliases - should be flagged
    result4 = vendor_req.get("http://example.com")
    result5 = vendor_urllib.PoolManager()

    # Import aliases - should be flagged
    result6 = vendored_req.Session()

    # Chained with aliases - should be flagged
    result7 = final.Session().post("http://example.com")
    result8 = vendor_urllib.PoolManager().request("GET", "http://example.com")

    return [result1, result2, result3, result4, result5, result6, result7, result8]
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should detect all aliased calls
                assert (
                    len(violations) >= 8
                ), f"Expected at least 8 violations, got {len(violations)}"
                assert len(messages) == 0, "Should not have any error messages"

                # Check that transitive and attribute aliasing are both detected
                violation_messages = [v.message for v in violations]
                assert any("requests.get" in msg for msg in violation_messages)
                assert any("requests.Session" in msg for msg in violation_messages)
                assert any("urllib3.PoolManager" in msg for msg in violation_messages)

            finally:
                os.unlink(f.name)

    def test_mixed_legitimate_and_violations(self):
        """Test file with both legitimate and violating patterns."""
        code = '''
"""Mixed legitimate and violating code."""
from __future__ import annotations
from typing import TYPE_CHECKING
from requests import Session, get
from urllib3 import PoolManager
import requests
import urllib3

if TYPE_CHECKING:
    from requests import RequestException
    from urllib3 import Retry

from snowflake.connector.session_manager import SessionManager


class MixedService:
    def __init__(self):
        self.session_manager = SessionManager()

        # VIOLATION: Direct session creation
        self.bad_session = requests.Session()

        # VIOLATION: Direct pool creation
        self.bad_pool = urllib3.PoolManager()

    def legitimate_method(self, session: Session) -> Session:
        """Type hints only - should NOT be flagged."""
        # LEGITIMATE: Using SessionManager
        response = self.session_manager.request("GET", "http://example.com")
        return session

    def violating_method(self):
        """Various violations."""
        # VIOLATION: Direct requests call
        response1 = requests.get("http://example.com")

        # VIOLATION: Imported function call
        response2 = get("http://example.com")

        # VIOLATION: Direct pool usage
        pool = PoolManager()
        response3 = pool.request("GET", "http://example.com")

        return response1, response2, response3

    def type_hint_method(self) -> Optional[Session]:
        """More type hints - should NOT be flagged."""
        return None

    def configure_pool(self, pool: PoolManager | None = None) -> None:
        """PEP 604 union in type hint - should NOT be flagged."""
        if pool:
            self.session_manager.configure(pool)


# String annotations - should NOT be flagged
def handle_request(req: "Session") -> "List[PoolManager]":
    return []

# TYPE_CHECKING imports - should NOT be flagged for runtime
def handle_exception(exc: RequestException) -> None:
    pass

def create_retry_policy() -> Retry:
    return None
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should find violations but not flag legitimate patterns
                assert (
                    len(violations) >= 5
                ), f"Expected violations, got {len(violations)}"
                assert len(messages) == 0, "Should not have any error messages"

                # Check violation types
                violation_types = [v.violation_type for v in violations]
                assert ViolationType.REQUESTS_SESSION in violation_types
                assert ViolationType.URLLIB3_POOLMANAGER in violation_types
                assert ViolationType.REQUESTS_HTTP_METHOD in violation_types
                assert ViolationType.DIRECT_HTTP_IMPORT in violation_types
                assert ViolationType.DIRECT_POOL_IMPORT in violation_types

            finally:
                os.unlink(f.name)

    def test_file_with_syntax_errors(self):
        """Test that files with syntax errors are handled gracefully."""
        code = '''
"""File with deliberate syntax errors."""
import requests
import urllib3

def broken_function(
    # Missing closing parenthesis and colon

# This should cause a syntax error
response = requests.get("http://example.com"
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should handle syntax errors gracefully
                assert (
                    len(violations) == 0
                ), "Should not find violations in syntactically invalid file"
                assert len(messages) == 1, "Should have exactly one error message"
                assert "syntax error" in messages[0].lower()

            finally:
                os.unlink(f.name)

    def test_large_realistic_file(self):
        """Test performance and correctness on a larger, realistic file."""
        code = '''
"""Large realistic file with many patterns."""
import asyncio
import json
import logging
import os
import sys
from typing import Dict, List, Optional, Union, Any
from concurrent.futures import ThreadPoolExecutor
import requests
import urllib3
from requests import Session, RequestException
from urllib3 import PoolManager, ProxyManager
from urllib3.exceptions import HTTPError

# This should NOT be flagged - legitimate import for type hints
from requests.models import Response

logger = logging.getLogger(__name__)


class HTTPService:
    """HTTP service with various patterns."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logger

        # VIOLATIONS: Direct instantiation
        self.session = requests.Session()
        self.pool = urllib3.PoolManager()
        self.proxy_pool = urllib3.ProxyManager("http://proxy:8080")

        # Aliasing that should be detected
        self.req_lib = requests
        self.urllib_lib = urllib3

    def fetch_data_sync(self, urls: List[str]) -> List[Optional[dict]]:
        """Synchronous data fetching with violations."""
        results = []

        for url in urls:
            try:
                # VIOLATIONS: Various HTTP calls
                response1 = requests.get(url, timeout=30)
                response2 = self.session.post(url, json={"test": True})
                response3 = self.pool.request("GET", url, retries=3)
                response4 = self.req_lib.get(url)  # Aliased call

                results.append(response1.json())
                results.append(response2.json())

            except (RequestException, HTTPError) as e:
                self.logger.error(f"HTTP error: {e}")
                results.append(None)

        return results

    async def fetch_data_async(self, urls: List[str]) -> List[dict]:
        """Async data fetching."""
        loop = asyncio.get_event_loop()

        async def fetch_one(url: str) -> Optional[dict]:
            # VIOLATION: requests in async context
            response = await loop.run_in_executor(
                None,
                lambda: requests.get(url)  # Should be flagged
            )
            return response.json() if response.status_code == 200 else None

        # VIOLATIONS: More async HTTP calls
        tasks = []
        for url in urls:
            # Chained calls in async context
            task = loop.run_in_executor(
                None,
                lambda u=url: urllib3.PoolManager().request("GET", u)
            )
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r.json() if hasattr(r, 'json') else {} for r in results]

    def process_with_threading(self, urls: List[str]) -> Dict[str, Any]:
        """Process URLs using threading."""
        def worker(url: str) -> dict:
            # VIOLATIONS: HTTP calls in threads
            session = Session()  # Direct import usage
            pool = PoolManager()  # Direct import usage

            response1 = session.get(url)
            response2 = pool.request("POST", url, body=b'{"data": "test"}')

            return {
                "url": url,
                "session_response": response1.json(),
                "pool_response": response2.data.decode()
            }

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker, url) for url in urls]
            results = [future.result() for future in futures]

        return {"results": results, "count": len(results)}

    def complex_chaining_patterns(self):
        """Complex chaining and aliasing patterns."""
        # VIOLATIONS: Various complex patterns

        # Multiple chained calls
        data1 = requests.Session().get("http://api.example.com").json()
        data2 = urllib3.PoolManager().urlopen("GET", "http://api.example.com").data
        data3 = urllib3.ProxyManager("http://proxy:8080").request_encode_body(
            "POST", "http://api.example.com", fields={"test": "data"}
        ).data

        # Transitive aliasing
        level1 = self.req_lib
        level2 = level1
        level3 = level2
        response = level3.get("http://example.com")  # Should trace back to requests

        # Attribute aliasing with complex paths
        vendor_requests = getattr(sys.modules.get('snowflake.connector.vendored'), 'requests', None)
        if vendor_requests:
            # This would be flagged if the getattr resolved to the vendored module
            response2 = vendor_requests.get("http://example.com")

        return data1, data2, data3, response, response2


def utility_functions():
    """Utility functions with various patterns."""

    def make_request(method: str, url: str, **kwargs) -> Response:
        """Make HTTP request - Response used in type hint only."""
        # VIOLATION: Direct requests usage
        return requests.request(method, url, **kwargs)

    def create_session_pool() -> tuple[Session, PoolManager]:
        """Create session and pool - types used in hint only."""
        # VIOLATIONS: Direct instantiation
        session = requests.Session()
        pool = urllib3.PoolManager()
        return session, pool

    def process_responses(responses: List[Response]) -> List[dict]:
        """Process responses - Response used in type hint only."""
        return [r.json() for r in responses if r.status_code == 200]


# VIOLATIONS: Module-level HTTP calls
CONFIG = {"base_url": "http://api.example.com"}
GLOBAL_SESSION = requests.Session()
GLOBAL_POOL = urllib3.PoolManager()

# Function with various violation patterns
def main():
    """Main function with violations."""
    service = HTTPService(CONFIG)

    urls = [
        "http://api.example.com/users",
        "http://api.example.com/posts",
        "http://api.example.com/comments"
    ]

    # VIOLATIONS: Direct calls
    health_check = requests.get(f"{CONFIG['base_url']}/health")
    if health_check.status_code != 200:
        # VIOLATION: Another direct call
        fallback = urllib3.PoolManager().request("GET", "http://fallback.example.com/health")

    # Various service methods that contain violations
    sync_results = service.fetch_data_sync(urls)
    async_results = asyncio.run(service.fetch_data_async(urls))
    threaded_results = service.process_with_threading(urls)

    return {
        "sync": sync_results,
        "async": async_results,
        "threaded": threaded_results,
        "health": health_check.json()
    }


if __name__ == "__main__":
    main()
        '''

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()

            try:
                checker = FileChecker(f.name)
                violations, messages = checker.check_file()

                # Should find exactly 20 violations in this large realistic file
                assert (
                    len(violations) == 20
                ), f"Expected exactly 20 violations in large file, got {len(violations)}"
                assert len(messages) == 0, "Should not have any error messages"

                # Should detect many different types of violations
                violation_types = {v.violation_type for v in violations}
                expected_types = {
                    ViolationType.REQUESTS_SESSION,
                    ViolationType.URLLIB3_POOLMANAGER,
                    ViolationType.REQUESTS_HTTP_METHOD,
                    ViolationType.REQUESTS_REQUEST,
                    ViolationType.DIRECT_HTTP_IMPORT,
                    ViolationType.DIRECT_SESSION_IMPORT,
                    ViolationType.DIRECT_POOL_IMPORT,
                }

                # Should detect most violation types in this comprehensive example
                assert len(violation_types & expected_types) >= 6

                # Should detect violations across different patterns
                violation_messages = [v.message for v in violations]
                assert any("Chained call" in msg for msg in violation_messages)
                assert any("Direct use" in msg for msg in violation_messages)
                assert any("aliased" in msg for msg in violation_messages)

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
