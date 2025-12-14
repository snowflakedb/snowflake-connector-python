#!/usr/bin/env python3
"""
Lean, comprehensive tests for the native HTTP checker.

Goals:
- One minimal snippet per violation type (order-independent checks).
- A few compact "real-life" integration scenarios.
- Clear separation of: violations, aliasing/vendored, type hints, exemptions, file handling.
"""
import ast
import sys
from collections import Counter
from pathlib import Path

import pytest

# Make checker importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "ci" / "pre-commit"))

from check_no_native_http import (
    ContextBuilder,
    FileChecker,
    ViolationAnalyzer,
    ViolationType,
)

# ---------- Helpers ----------


def analyze(code: str, filename: str = "test.py"):
    tree = ast.parse(code)
    builder = ContextBuilder()
    builder.visit(tree)
    analyzer = ViolationAnalyzer(filename, builder.context)
    analyzer.analyze_imports()
    analyzer.analyze_calls(tree)
    analyzer.analyze_star_imports()
    return analyzer.violations


def assert_types(violations, expected_types):
    """Order-independent type assertion with counts."""
    got = Counter(v.violation_type for v in violations)
    want = Counter(expected_types)
    assert got == want, f"Expected {want}, got {got}\nViolations:\n" + "\n".join(
        str(v) for v in violations
    )


# ---------- Per-violation unit tests (minimal snippets) ----------


@pytest.mark.parametrize(
    "code,expected",
    [
        # SNOW001 requests.request()
        (
            """import requests
requests.request("GET", "http://x")
""",
            [ViolationType.REQUESTS_REQUEST],
        ),
        # SNOW002 requests.Session()
        (
            """import requests
requests.Session()
""",
            [ViolationType.REQUESTS_SESSION],
        ),
        # SNOW003 urllib3.PoolManager / ProxyManager
        (
            """import urllib3
urllib3.PoolManager()
urllib3.ProxyManager("http://p:8080")
""",
            [ViolationType.URLLIB3_POOLMANAGER, ViolationType.URLLIB3_POOLMANAGER],
        ),
        # SNOW004 requests.get/post/...
        (
            """import requests
requests.get("http://x")
requests.post("http://x")
""",
            [ViolationType.REQUESTS_HTTP_METHOD, ViolationType.REQUESTS_HTTP_METHOD],
        ),
        # SNOW006 direct import of HTTP methods + usage
        (
            """from requests import get, post
get("http://x")
post("http://x")
""",
            [
                ViolationType.DIRECT_HTTP_IMPORT,
                ViolationType.DIRECT_HTTP_IMPORT,  # import line flags both
                ViolationType.DIRECT_HTTP_IMPORT,
                ViolationType.DIRECT_HTTP_IMPORT,  # usage flags both
            ],
        ),
        # SNOW007 direct PoolManager import + usage
        (
            """from urllib3 import PoolManager
PoolManager()
""",
            [ViolationType.DIRECT_POOL_IMPORT, ViolationType.DIRECT_POOL_IMPORT],
        ),
        # SNOW008 direct Session import + usage
        (
            """from requests import Session
Session()
""",
            [ViolationType.DIRECT_SESSION_IMPORT, ViolationType.DIRECT_SESSION_IMPORT],
        ),
        # SNOW010 star import + usage
        (
            """from requests import *
get("http://x")
""",
            [ViolationType.STAR_IMPORT, ViolationType.STAR_IMPORT],
        ),
        # SNOW011 urllib3 direct APIs
        (
            """import urllib3
urllib3.request("GET", "http://x")
urllib3.HTTPConnectionPool("x")
urllib3.HTTPSConnectionPool("x")
""",
            [
                ViolationType.URLLIB3_DIRECT_API,
                ViolationType.URLLIB3_DIRECT_API,
                ViolationType.URLLIB3_DIRECT_API,
            ],
        ),
        # SNOW012 aiohttp.ClientSession()
        (
            """import aiohttp
aiohttp.ClientSession()
""",
            [ViolationType.AIOHTTP_CLIENT_SESSION],
        ),
        # SNOW013 aiohttp.request()
        (
            """import aiohttp
aiohttp.request("GET", "http://x")
""",
            [ViolationType.AIOHTTP_REQUEST],
        ),
        # SNOW014 direct import of ClientSession + usage
        (
            """from aiohttp import ClientSession
ClientSession()
""",
            [ViolationType.DIRECT_AIOHTTP_IMPORT, ViolationType.AIOHTTP_CLIENT_SESSION],
        ),
        # SNOW010 star import from aiohttp
        (
            """from aiohttp import *
ClientSession()
""",
            [ViolationType.STAR_IMPORT],
        ),
    ],
)
def test_minimal_violation_snippets(code, expected):
    violations = analyze(code)
    assert_types(violations, expected)


# ---------- Aliasing, vendored, deep chains, and chained calls ----------


def test_aliasing_and_chained_calls():
    code = """
import requests, urllib3, aiohttp
req = requests
req.get("http://x")
requests.Session().post("http://x")
urllib3.PoolManager().request("GET", "http://x")
urllib3.PoolManager().urlopen("GET", "http://x")
aiohttp.ClientSession().get("http://x")
"""
    v = analyze(code)
    # Expect: requests.get, Session().post (Session), PoolManager().request, PoolManager().urlopen, ClientSession().get
    expected = [
        ViolationType.REQUESTS_HTTP_METHOD,
        ViolationType.REQUESTS_SESSION,
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.AIOHTTP_CLIENT_SESSION,
    ]
    assert_types(v, expected)


def test_vendored_and_deep_attribute_chains():
    code = """
from snowflake.connector.vendored import requests as vreq
import requests, urllib3

vreq.get("http://x")
requests.api.request("GET", "http://x")
requests.sessions.Session()
"""
    v = analyze(code)
    # vreq.get -> REQUESTS_HTTP_METHOD
    # requests.api.request -> REQUESTS_REQUEST
    # requests.sessions.Session -> REQUESTS_SESSION
    expected = [
        ViolationType.REQUESTS_HTTP_METHOD,  # vreq.get(...)
        ViolationType.REQUESTS_HTTP_METHOD,  # requests.api.request(...)
        ViolationType.REQUESTS_SESSION,  # requests.sessions.Session()
    ]
    assert_types(v, expected)


def test_chained_poolmanager_variants():
    code = """
import urllib3
urllib3.PoolManager().request("GET", "http://x")
urllib3.PoolManager().urlopen("GET", "http://x")
urllib3.PoolManager().request_encode_body("POST", "http://x", fields={})
"""
    v = analyze(code)
    expected = [
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.URLLIB3_POOLMANAGER,
    ]
    assert_types(v, expected)


def test_chained_aiohttp_clientsession_variants():
    code = """
import aiohttp
aiohttp.ClientSession().get("http://x")
aiohttp.ClientSession().post("http://x")
aiohttp.ClientSession().request("GET", "http://x")
"""
    v = analyze(code)
    expected = [
        ViolationType.AIOHTTP_CLIENT_SESSION,
        ViolationType.AIOHTTP_CLIENT_SESSION,
        ViolationType.AIOHTTP_CLIENT_SESSION,
    ]
    assert_types(v, expected)


def test_aiohttp_aliasing():
    code = """
import aiohttp
aioh = aiohttp
aioh.ClientSession()
"""
    v = analyze(code)
    expected = [ViolationType.AIOHTTP_CLIENT_SESSION]
    assert_types(v, expected)


from textwrap import dedent


def test_attribute_aliasing_on_self_filechecker(tmp_path):
    """
    File-level: self.req_lib = requests; self.req_lib.get(...) should be flagged.
    """
    code = dedent(
        """
    import requests

    class Foo:
        def __init__(self):
            self.req_lib = requests

        def do(self):
            return self.req_lib.get("http://x")
    """
    )
    p = tmp_path / "attr_alias_self.py"
    p.write_text(code, encoding="utf-8")

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert messages == []
    types = [v.violation_type for v in violations]
    assert types == [ViolationType.REQUESTS_HTTP_METHOD]


def test_chained_proxymanager_variants_filechecker(tmp_path):
    """
    File-level: ProxyManager chained calls (request, urlopen, request_encode_body).
    Note: instance calls (pm.request(...)) are not inferred by the checker.
    """
    code = (
        "import urllib3\n"
        "a = urllib3.ProxyManager('http://p:8080').request('GET', 'http://x')\n"
        "b = urllib3.ProxyManager('http://p:8080').urlopen('GET', 'http://x')\n"
        "c = urllib3.ProxyManager('http://p:8080').request_encode_body('POST', 'http://x')\n"
    )
    p = tmp_path / "proxy_variants.py"
    p.write_text(code, encoding="utf-8")

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert messages == []
    types = [v.violation_type for v in violations]
    assert types == [
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.URLLIB3_POOLMANAGER,
    ]


# ---------- Type-hints and TYPE_CHECKING handling ----------


def test_type_hints_only_allowed():
    code = """
from requests import Session
from urllib3 import PoolManager
from aiohttp import ClientSession
from typing import Generator

def f(s: Session, p: PoolManager, c: ClientSession) -> Generator[Session, None, None]:
    pass
"""
    assert analyze(code) == []


def test_type_hints_mixed_runtime_flags_runtime_only():
    code = """
from requests import Session
def f(s: Session) -> Session:
    x = Session()  # runtime
    return x
"""
    v = analyze(code)
    expected = [ViolationType.DIRECT_SESSION_IMPORT]
    assert_types(v, expected)


def test_type_checking_guard_allows_imports():
    code = """
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from requests import Session
    from urllib3 import PoolManager
    from aiohttp import ClientSession

def g(s: 'Session', p: 'PoolManager', c: 'ClientSession'):
    pass
"""
    assert analyze(code) == []


def test_pep604_and_string_annotations():
    code = """
from requests import Session
from aiohttp import ClientSession
def f(a: Session | None) -> Session | str: pass
def g(x: "Session") -> "Session | None": pass
def h(c: ClientSession | None) -> "ClientSession": pass
"""
    assert analyze(code) == []


# ---------- Exemptions & temporary exemptions ----------


@pytest.mark.parametrize(
    "path,expected",
    [
        ("src/snowflake/connector/session_manager.py", True),
        ("src/snowflake/connector/aio/_session_manager.py", True),
        ("src/snowflake/connector/vendored/requests/__init__.py", True),
        ("test/unit/test_something.py", True),
        ("conftest.py", True),
        ("src/snowflake/connector/regular_module.py", False),
    ],
)
def test_exemptions(path, expected):
    assert FileChecker(path).is_exempt() is expected


@pytest.mark.parametrize(
    "path,ticket",
    [
        ("src/snowflake/connector/auth/_oauth_base.py", "SNOW-2229411"),
        ("src/snowflake/connector/telemetry_oob.py", "SNOW-2259522"),
    ],
)
def test_temporary_exemptions(path, ticket):
    assert FileChecker(path).get_temporary_exemption() == ticket


# ---------- File handling ----------


def test_syntax_error_handling_tempfile(tmp_path):
    p = tmp_path / "broken.py"
    p.write_text(
        "import requests\ndef invalid syntax here\nresponse = requests.get()",
        encoding="utf-8",
    )

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert violations == []
    assert len(messages) == 1
    assert "syntax error" in messages[0].lower()


def test_unicode_error_handling_tempfile(tmp_path):
    p = tmp_path / "bad.py"
    p.write_bytes(b"import requests\n\xff\xfe invalid unicode\n")

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert violations == []
    assert len(messages) == 1


def test_valid_file_processing_tempfile(tmp_path):
    p = tmp_path / "ok.py"
    p.write_text(
        'import requests\nresponse = requests.get("http://example.com")\n',
        encoding="utf-8",
    )

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert violations
    assert messages == []


# ---------- Compact integration scenarios ----------


def test_integration_class_definition():
    code = """
import requests, urllib3, aiohttp
from requests import Session, get as rget
from urllib3 import PoolManager
from aiohttp import ClientSession

class C:
    def __init__(self):
        self.s = requests.Session()
        self.p = urllib3.PoolManager()
        self.c = aiohttp.ClientSession()  # AIOHTTP_CLIENT_SESSION

    def run(self, url):
        a = requests.get(url)
        b = self.s.post(url)
        c = self.p.request("GET", url)
        d = rget(url)
        e = PoolManager().request("GET", url)
        f = ClientSession()  # AIOHTTP_CLIENT_SESSION
        return a,b,c,d,e,f
"""
    v = analyze(code, filename="mix.py")
    # Expect a mix of types, not exact counts
    vt = {x.violation_type for x in v}
    # Check that we have at least these violation types
    assert {
        ViolationType.REQUESTS_SESSION,
        ViolationType.URLLIB3_POOLMANAGER,
        ViolationType.REQUESTS_HTTP_METHOD,
        ViolationType.DIRECT_HTTP_IMPORT,
        ViolationType.DIRECT_POOL_IMPORT,
        ViolationType.AIOHTTP_CLIENT_SESSION,
        ViolationType.DIRECT_AIOHTTP_IMPORT,
    } <= vt


def test_integration_multiple_functions():
    code = """
from __future__ import annotations
from typing import Optional, List
from requests import Session  # type hints only
from urllib3 import PoolManager  # type hints only
from snowflake.connector.session_manager import SessionManager

class Svc:
    def __init__(self):
        self.m = SessionManager()

    def get(self, url: str) -> Optional[dict]:
        r = self.m.request("GET", url)
        return r.json() if r.status_code == 200 else None

def process(xs: List[Session]) -> None:
    pass

def provide() -> PoolManager:
    # hypothetically returned by SessionManager in prod code
    return None
"""
    assert analyze(code) == []


def test_e2e_mixed_small_filechecker(tmp_path):
    """
    End-to-end small realistic file:
      - legit type-hint-only imports
      - violations: requests.get, requests.Session, ProxyManager.request
      - attribute aliasing: self.req_lib.get
    """
    code = """
from typing import TYPE_CHECKING, Optional
from requests import Session  # type-hint only
from urllib3 import PoolManager  # type-hint only
import requests, urllib3

if TYPE_CHECKING:
    from requests import Response

class Svc:
    def __init__(self):
        self.req_lib = requests  # attribute alias

    def ok(self, s: Session, p: PoolManager) -> Optional[Session]:
        return None

    def bad(self, url: str):
        x = requests.get(url)                        # REQUESTS_HTTP_METHOD
        s = requests.Session()                       # REQUESTS_SESSION
        pm = urllib3.ProxyManager("http://p:8080")
        y = pm.request("GET", url)                   # URLLIB3_POOLMANAGER
        z = self.req_lib.get(url)                    # REQUESTS_HTTP_METHOD (alias)
        return x, s, y, z
"""
    p = tmp_path / "e2e_mixed_small.py"
    p.write_text(code, encoding="utf-8")

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert messages == []
    types = [v.violation_type for v in violations]

    # Expect exactly four violations, one of each kind listed below
    expected = [
        ViolationType.REQUESTS_HTTP_METHOD,  # requests.get
        ViolationType.REQUESTS_SESSION,  # requests.Session
        ViolationType.URLLIB3_POOLMANAGER,  # ProxyManager.request
        ViolationType.REQUESTS_HTTP_METHOD,  # self.req_lib.get (alias)
    ]
    assert types == expected


def test_aiohttp_integration(tmp_path):
    """
    End-to-end aiohttp test:
      - legit type-hint-only imports (ClientSession, TCPConnector allowed in TYPE_CHECKING)
      - violations: aiohttp.ClientSession(), aiohttp.ClientSession().get()
    """
    code = """
from typing import TYPE_CHECKING, Optional
from aiohttp import ClientSession  # type-hint only
import aiohttp

if TYPE_CHECKING:
    from aiohttp import TCPConnector  # allowed - config object like HTTPAdapter

class AsyncSvc:
    def ok(self, c: ClientSession) -> Optional[ClientSession]:
        return None

    async def bad(self, url: str):
        async with aiohttp.ClientSession() as session:  # AIOHTTP_CLIENT_SESSION
            x = await session.get(url)
        y = await aiohttp.ClientSession().get(url)     # AIOHTTP_CLIENT_SESSION (chained)
        return x, y
"""
    p = tmp_path / "aiohttp_integration.py"
    p.write_text(code, encoding="utf-8")

    checker = FileChecker(str(p))
    violations, messages = checker.check_file()

    assert messages == []
    types = [v.violation_type for v in violations]

    # Expect exactly two violations
    expected = [
        ViolationType.AIOHTTP_CLIENT_SESSION,  # aiohttp.ClientSession()
        ViolationType.AIOHTTP_CLIENT_SESSION,  # aiohttp.ClientSession().get (chained)
    ]
    assert types == expected
