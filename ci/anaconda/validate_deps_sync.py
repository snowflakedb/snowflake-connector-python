"""Validate conda run requirements match setup.cfg install_requires.

Note that it assumes default requirements to be install_requires + boto. If that assumption is no longer true,
this script needs to be updated accordingly.

Exit behavior:
- If there is no diff: exit 0 with no output.
- If there is a diff: print the diff and exit 1.
"""

import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


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


def get_setup_install_requires(cfg_path: Path) -> List[str]:
    """Extract normalized install_requires entries from setup.cfg.

    Args:
      cfg_path: Path to setup.cfg.

    Returns:
      List of strings in the form "<name> <spec>" where spec may be empty.
    """
    lines = cfg_path.read_text(encoding="utf-8").splitlines()
    in_options = False
    in_install = False
    deps: List[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[options]"):
            in_options = True
            in_install = False
            continue
        if in_options and stripped.startswith("[") and "]" in stripped:
            # Left [options]
            in_options = False
            in_install = False
        if in_options and stripped.startswith("install_requires"):
            in_install = True
            continue
        if in_install:
            # Stop when dedented (not an indented list item)
            if not re.match(r"\s{4,}\S", line):
                in_install = False
                continue
            item = stripped
            if not item or item.startswith("#"):
                continue
            name, spec = split_requirement(item)
            if name and name != "python":
                deps.append(f"{name} {spec}".strip())
    return deps


def get_meta_run_requirements(meta_path: Path) -> List[str]:
    """Extract normalized run requirements from meta.yaml.

    Args:
      meta_path: Path to meta.yaml.

    Returns:
      List of strings in the form "<name> <spec>" where spec may be empty.
    """
    lines = meta_path.read_text(encoding="utf-8").splitlines()
    in_requirements = False
    in_run = False
    base_indent = None
    run_indent = None
    deps: List[str] = []

    for line in lines:
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if stripped.startswith("requirements:"):
            in_requirements = True
            base_indent = indent
            in_run = False
            continue
        if in_requirements and stripped and indent <= (base_indent or 0):
            in_requirements = False
            in_run = False
        if in_requirements and stripped.startswith("run:"):
            in_run = True
            run_indent = indent
            continue
        if in_run:
            if stripped and indent <= (run_indent or 0):
                in_run = False
                continue
            if re.match(r"-\s+", stripped):
                item = stripped[1:].strip()
                name, spec = split_requirement(item)
                if name and name != "python":
                    deps.append(f"{name} {spec}".strip())
    return deps


def get_setup_extra_requires(cfg_path: Path, extra: str) -> List[str]:
    """Extract normalized requirements for a given extra from setup.cfg.

    Args:
      cfg_path: Path to setup.cfg.
      extra: The extras_require key to extract (e.g., "boto").

    Returns:
      List of strings in the form "<name> <spec>".
    """
    lines = cfg_path.read_text(encoding="utf-8").splitlines()
    in_extras = False
    in_target = False
    deps: List[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[options.extras_require]"):
            in_extras = True
            in_target = False
            continue
        if in_extras and stripped.startswith("[") and "]" in stripped:
            # Left extras_require section
            break
        if (
            in_extras
            and not in_target
            and re.match(rf"^{re.escape(extra)}\s*=\s*$", stripped)
        ):
            in_target = True
            continue
        if in_extras and in_target:
            # Stop when dedented (not an indented list item)
            if not re.match(r"\s{4,}\S", line):
                in_target = False
                continue
            item = stripped
            if not item or item.startswith("#"):
                continue
            name, spec = split_requirement(item)
            if name and name != "python":
                deps.append(f"{name} {spec}".strip())
    return deps


def compare_deps(setup_deps: Iterable[str], meta_deps: Iterable[str]) -> str:
    """Compare two dependency lists and return a human-readable diff.

    Args:
      setup_deps: Normalized dependencies from setup.cfg.
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
            lines.append(f"  - {n}: setup.cfg='{s}' vs meta.yaml='{m}'")
    return "\n".join(lines)


def main() -> int:
    root = repo_root()
    setup_cfg_path = root / "setup.cfg"
    setup_deps = get_setup_install_requires(setup_cfg_path)
    boto_deps = get_setup_extra_requires(setup_cfg_path, "boto")
    # Make sure to update ci/anaconda/recipe/meta.yaml accordingly when there is dependency set update.
    expected_deps = setup_deps + boto_deps
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
