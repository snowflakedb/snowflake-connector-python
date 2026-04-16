# ADR: Python 3.14t CI failures — snowflakedb/snowflake-connector-python — 2026-04-13

## Goal

All Python 3.14 and 3.14t Test jobs on PR #2832 pass without mitmproxy-related
test errors.

## Context

- Repo: snowflakedb/snowflake-connector-python
- PR / branch: #2832 / agent/add-python-314-support-task-31085da0
- Target jobs: Test manylinux_x86_64-3.14-aws, Test manylinux_x86_64-3.14t-aws,
  Test macosx_x86_64-3.14-azure, Test macosx_x86_64-3.14t-azure,
  Test win_amd64-3.14-gcp, Test win_amd64-3.14t-gcp
- Runners: ubuntu-latest, macos-latest, windows-latest

## Current failure

- Category: Dependency / test fixture — mitmproxy not available on Python 3.14+
- Error: `Failed to start mitmproxy: mitmproxy (mitmdump) is not installed`
  then `FileNotFoundError: [Errno 2] No such file or directory: 'mitmdump'`
- Run: from CI run on 2026-03-27 (pre-merge-with-main push)

## Observations

[2026-04-13] [pre-merge run] — All 6 failing Test jobs fail identically on 2 tests:
  `test/integ/test_proxies.py::test_put_with_https_proxy` and
  `test/integ/test_proxies.py::test_put_with_https_proxy_and_no_proxy_regression`.
  Source: gh run view log-failed output, all 6 jobs

[2026-04-13] [pre-merge run] — setup.cfg correctly excludes mitmproxy for 3.14+:
  `mitmproxy>=12.0.0; python_version >= '3.12' and python_version < '3.14'`
  Source: setup.cfg line 96

[2026-04-13] [pre-merge run] — test_proxies.py has a skipif for `sys.version_info < (3, 12)`
  but NO skipif for `sys.version_info >= (3, 14)` where mitmproxy is excluded.
  Source: test/integ/test_proxies.py line 28-31

[2026-04-13] [pre-merge run] — All other test suites pass on both 3.14 and 3.14t:
  extras, unit-parallel, pandas-parallel, sso all green.
  Source: gh run view summary

[2026-04-13] [pre-merge run] — 3.14t shows GIL warnings ("GIL has been enabled to load
  module 'snowflake.connector.nanoarrow_arrow_iterator'") but these are warnings only,
  not failures.
  Source: 3.14t job logs

## Hypotheses

[H1] [current] — The test_proxies.py tests need a version upper-bound skip to match
  the dependency exclusion in setup.cfg. The existing `skipif(sys.version_info < (3, 12))`
  skips old Python but doesn't skip 3.14+ where mitmproxy is intentionally absent.
  Rests on: all 5 observations above.

## Iterations

### Iteration 1 — Fixture-level dynamic skip

**Motivation**: mitmproxy test fixture fails on Python 3.14+ because mitmdump is not installed.

**Observation**: `FileNotFoundError: [Errno 2] No such file or directory: 'mitmdump'`
in `mitm_fixtures.py` fixture setup, causing `pytest.fail()` on 2 tests.

**Hypothesis**: Adding a `shutil.which("mitmdump")` guard at the fixture entry point
will skip all mitmproxy-dependent tests when the binary is absent, without affecting
Python versions where mitmproxy IS installed (3.12–3.13).

**Fit**: Best explanation — the error is unambiguously "binary not found", and the
dependency is intentionally excluded in setup.cfg. All 3 ADR reviewers agreed on
root cause; orchestrator ranked fixture-level dynamic skip as Solution 1.

**Falsification**: If CI still shows mitmproxy errors after this change, H1 is disproved.
If tests on 3.12/3.13 start being skipped, the shutil.which check is broken.

**Change**:
- File: `test/test_utils/cross_module_fixtures/mitm_fixtures.py`
- Change: Added `import shutil` and `pytest.skip()` guard before `MitmClient()` init

**Commit**: pending

**Observations afterwards**: pending CI run

**Conclusion**: pending

**Next step**: If green → done. If same error → Solution 2 (hybrid fixture + decorator).

## Confirmed conclusions

<!-- To be filled after CI evidence -->

## Deferred items

- GIL re-enable warnings on 3.14t for nanoarrow_arrow_iterator (cosmetic, not a failure)
- Windows 3.14t subprocess handle cleanup errors during test teardown (cosmetic)
