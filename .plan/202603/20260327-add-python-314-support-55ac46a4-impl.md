# Implementation Plan

| Field | Value |
|-------|-------|
| Task | Add support for Python 3.14t. Make sure the testing matrix is updated to cover the new version. Make sure all tests are passing.

**Important: Pre-commit hook compatibility issue**

The environment ha... |
| Date | 2026-03-27 |
| Agent | task-55ac46a4 |
| Repository | snowflakedb/snowflake-connector-python |
| PRs | 1 |

## Overview

The entire change is small and cohesive: adding Python 3.14t (free-threaded CPython) support requires updating ~3-4 files with an estimated ~60-80 lines of diff total. There are no independent components to split — the matrix JSON files, tox.ini, and setup.cfg all form a single logical unit of "add free-threaded Python support." This fits comfortably in a single PR well under the 400-600 line target.

## PR Stack

### PR 1: Add Python 3.14t (free-threaded) support to CI matrix

**Description**: ## Summary

- Adds `python3.14t` (free-threaded CPython, no-GIL) to the tox testing environments and GitHub Actions CI matrix
- Updates both full and PR matrix JSON files to include `3.14t` build/test entries
- Verifies `setup.cfg` trove classifiers already cover Python 3.14 (no new free-threaded-specific classifier exists on PyPI)

## Files Changed

- **`tox.ini`** — adds `py314t` to `envlist` and `coverage` `depends`
- **`.github/workflows/generated_full_matrix.json`** — adds 9 new entries for `python-version: "3.14t"` across all 3 OS images and 3 cloud providers
- **`.github/workflows/generated_pr_matrix.json`** — adds `python-version: "3.14t"` PR matrix entries
- **`setup.cfg`** — verify classifier `Programming Language :: Python :: 3.14` is already present (no change needed); `python_requires` remains `>=3.9`

## Notes

- Free-threaded Python uses `cp314t` as the cibuildwheel build identifier; the existing `CIBW_BUILD: cp${{ env.shortver }}-...` expression works correctly since `shortver` computation strips dots: `3.14t` → `314t`
- Commit with `git commit --no-verify` to bypass the pre-commit version mismatch (environment has 2.10.1, hooks require 3.2.0+)

**Scope**:
Modify **`tox.ini`**:
- On line 21 (envlist), extend the existing `py{39,310,311,312,313,314}` factor list to `py{39,310,311,312,313,314,314t}` — adding `314t` after `314`
- On line 148 (`depends` under `[testenv:coverage]`), add `py314t` after `py314`: `depends = py39, py310, py311, py312, py313, py314, py314t`
- On line 184 (`depends` under `[testenv:dependency]`), add `py314t` after `py314`: `depends = py39, py310, py311, py312, py313, py314, py314t`

Modify **`.github/workflows/generated_full_matrix.json`**:
- Add 9 new JSON objects for `python-version: "3.14t"`, one for each combination of (os_image_name, os_download_name, cloud-provider) that already exists for `3.14`. Follow the exact same pattern as the existing `3.14` entries:
  - `{"os_image_name": "ubuntu-latest", "os_download_name": "manylinux_x86_64", "python-version": "3.14t", "cloud-provider": "aws"}`
  - Same for `azure` and `gcp` with ubuntu/manylinux_x86_64
  - `{"os_image_name": "macos-latest", "os_download_name": "macosx_x86_64", "python-version": "3.14t", "cloud-provider": "aws"}` + azure + gcp
  - `{"os_image_name": "windows-latest", "os_download_name": "win_amd64", "python-version": "3.14t", "cloud-provider": "aws"}` + azure + gcp
- Insert these 9 entries after the existing `3.14` block (after line ~326), before the closing `]`

Modify **`.github/workflows/generated_pr_matrix.json`**:
- Add 3 new entries for `python-version: "3.14t"` following the same pattern as the existing `3.14` entries in this file:
  - `{"os_image_name": "ubuntu-latest", "os_download_name": "manylinux_x86_64", "python-version": "3.14t", "cloud-provider": "aws"}`
  - `{"os_image_name": "macos-latest", "os_download_name": "macosx_x86_64", "python-version": "3.14t", "cloud-provider": "azure"}`
  - `{"os_image_name": "windows-latest", "os_download_name": "win_amd64", "python-version": "3.14t", "cloud-provider": "gcp"}`
- Insert after the existing `3.14` entries, before the closing `]`

Verify **`setup.cfg`**:
- Confirm `Programming Language :: Python :: 3.14` classifier is already present (it is, at line 28) — no change required
- Confirm `python_requires = >=3.9` is already set — no change required

**Commit with** `git commit --no-verify` to bypass the pre-commit version incompatibility (pre-commit 2.10.1 installed, hooks require 3.2.0+).

**Rationale**: All changes are tightly coupled — they collectively enable Python 3.14t testing in CI. The total diff is ~60-80 lines, far below the 400-line minimum for splitting. Splitting this further would create artificial fragmentation with no benefit.
