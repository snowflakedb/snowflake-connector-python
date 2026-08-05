"""Validate conda run requirements match pyproject.toml dependencies.

Compares project.dependencies in pyproject.toml against meta.yaml run
requirements. Optional extras (e.g. boto3) are intentionally excluded.

Exit behavior:
- If there is no diff: exit 0 with no output.
- If there is a diff: print the diff and exit 1.
"""

import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import yaml

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef]


def repo_root() -> Path:
    """Return repository root based on this file location."""
    return Path(__file__).resolve().parents[2]


def normalize_name(name: str) -> str:
    """Normalize a dependency name to a canonical form.

    Replaces underscores with hyphens and lowercases the name.

    Args:
      name: Raw package name.

    Returns:
      Normalized package name.
    """
    return name.strip().lower().replace("_", "-")


def split_requirement(req: str) -> Tuple[str, str]:
    """Split a requirement into name and version specifier.

    Drops PEP 508 markers (after ';') and conda selectors (after '#').

    Args:
      req: A single requirement line.

    Returns:
      Tuple of (normalized_name, normalized_spec). Spec contains no spaces.
    """
    # Drop markers and selectors
    req = req.split(";", 1)[0]
    req = req.split("#", 1)[0]
    req = req.strip()
    if not req:
        return "", ""

    # Find first comparator
    m = re.search(r"(<=|>=|==|!=|~=|<|>|=)", req)
    if m:
        name = req[: m.start()].strip()
        spec = req[m.start() :].strip()
    else:
        # No version specified
        parts = req.split()
        name = parts[0] if parts else ""
        spec = ""

    # Normalize
    spec = re.sub(r"\s*,\s*", ",", spec)
    spec = re.sub(r"\s+", "", spec)
    return normalize_name(name), spec


def _load_pyproject(pyproject_path: Path) -> dict:
    """Load and return the parsed pyproject.toml mapping."""
    with pyproject_path.open("rb") as f:
        return tomllib.load(f)


def _deps_from_requirement_list(raw_deps: Iterable[str]) -> List[str]:
    """Normalize a list of requirement strings from pyproject.toml."""
    deps: List[str] = []
    for item in raw_deps:
        if not isinstance(item, str):
            continue
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        name, spec = split_requirement(item)
        if name and name != "python":
            deps.append(f"{name} {spec}".strip())
    return deps


def get_setup_install_requires(pyproject_path: Path) -> List[str]:
    """Extract normalized project.dependencies entries from pyproject.toml.

    Args:
      pyproject_path: Path to pyproject.toml.

    Returns:
      List of strings in the form "<name> <spec>" where spec may be empty.
    """
    data = _load_pyproject(pyproject_path)
    project = data.get("project") or {}
    raw_deps = project.get("dependencies")
    if raw_deps is None:
        raise RuntimeError(f"Missing project.dependencies in {pyproject_path}")
    if not isinstance(raw_deps, list):
        raise RuntimeError(
            f"project.dependencies in {pyproject_path} must be a list; "
            f"got {type(raw_deps).__name__}"
        )
    return _deps_from_requirement_list(raw_deps)


def get_meta_run_requirements(meta_path: Path) -> List[str]:
    """Extract normalized run requirements from meta.yaml.

    Args:
      meta_path: Path to meta.yaml.

    Returns:
      List of strings in the form "<name> <spec>" where spec may be empty.
    """
    text = meta_path.read_text(encoding="utf-8")
    cleaned_lines: List[str] = []
    for line in text.splitlines():
        if "{%" in line or "%}" in line:
            continue
        if "{{" in line and "}}" in line:
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)

    try:
        data = yaml.safe_load(cleaned) or {}
    except Exception as exc:
        raise RuntimeError(f"Failed to parse YAML for {meta_path}") from exc

    reqs = data.get("requirements", {}) or {}
    run_items = reqs.get("run", []) or []

    deps: List[str] = []
    for idx, it in enumerate(run_items):
        if not isinstance(it, str):
            raise TypeError(
                f"requirements.run entry at index {idx} in {meta_path} "
                f"must be a string; got {type(it).__name__}: {it!r}"
            )
        name, spec = split_requirement(it)
        if name and name != "python":
            deps.append(f"{name} {spec}".strip())
    return deps


def get_setup_extra_requires(pyproject_path: Path, extra: str) -> List[str]:
    """Extract normalized requirements for a given optional dependency.

    Args:
      pyproject_path: Path to pyproject.toml.
      extra: The optional-dependencies key to extract (e.g., "boto3").

    Returns:
      List of strings in the form "<name> <spec>".
    """
    data = _load_pyproject(pyproject_path)
    project = data.get("project") or {}
    optional = project.get("optional-dependencies") or {}
    key = extra.strip().lower()
    if key not in optional:
        raise RuntimeError(
            f"Missing optional-dependency '{key}' under "
            f"[project.optional-dependencies] in {pyproject_path}"
        )
    raw_deps = optional[key]
    if not isinstance(raw_deps, list):
        raise RuntimeError(
            f"project.optional-dependencies.{key} in {pyproject_path} "
            f"must be a list; got {type(raw_deps).__name__}"
        )
    return _deps_from_requirement_list(raw_deps)


def compare_deps(setup_deps: Iterable[str], meta_deps: Iterable[str]) -> str:
    """Compare two dependency lists and return a human-readable diff.

    Args:
      setup_deps: Normalized dependencies from pyproject.toml.
      meta_deps: Normalized dependencies from meta.yaml.

    Returns:
      Empty string if equal, otherwise a multi-line diff description.
    """

    def to_map(items: Iterable[str]) -> Dict[str, str]:
        mapping: Dict[str, str] = {}
        for it in items:
            parts = it.split(" ", 1)
            name = parts[0]
            spec = parts[1] if len(parts) > 1 else ""
            mapping[name] = spec
        return mapping

    s_map = to_map(setup_deps)
    m_map = to_map(meta_deps)

    s_names = set(s_map)
    m_names = set(m_map)
    missing = sorted(s_names - m_names)
    extra = sorted(m_names - s_names)

    mismatches: List[Tuple[str, str, str]] = []
    for name in sorted(s_names & m_names):
        if s_map.get(name, "") != m_map.get(name, ""):
            mismatches.append((name, s_map.get(name, ""), m_map.get(name, "")))

    if not (missing or extra or mismatches):
        return ""

    lines: List[str] = []
    if missing:
        lines.append("Missing in meta.yaml run:")
        for n in missing:
            lines.append(f"  - {n} ({s_map[n] or 'no spec'})")
    if extra:
        lines.append("Extra in meta.yaml run:")
        for n in extra:
            lines.append(f"  - {n} ({m_map[n] or 'no spec'})")
    if mismatches:
        lines.append("Version spec mismatches:")
        for n, s, m in mismatches:
            lines.append(f"  - {n}: pyproject.toml='{s}' vs meta.yaml='{m}'")
    return "\n".join(lines)


def main() -> int:
    root = repo_root()
    pyproject_path = root / "pyproject.toml"
    # Make sure to update ci/anaconda/recipe/meta.yaml accordingly when there is dependency set update.
    expected_deps = get_setup_install_requires(pyproject_path)
    meta_deps = get_meta_run_requirements(
        root / "ci" / "anaconda" / "recipe" / "meta.yaml"
    )
    diff = compare_deps(expected_deps, meta_deps)
    if not diff:
        return 0
    print(diff)
    return 1


if __name__ == "__main__":
    sys.exit(main())
