#!/usr/bin/env python3
"""Validate that JSON files contain no duplicate object keys.

Python's json.load silently keeps the last value when an object contains
duplicate keys. That bug class lost 4 framework overrides in v2.22.0 and
was caught only by downstream cross-validation (commit 8634df0). This
script uses object_pairs_hook to reject duplicates at parse time.

Usage:
    python scripts/Validate-NoDuplicateKeys.py [paths...]

If no paths are given, validates every JSON file under data/.

Exit codes:
    0 — all files clean
    1 — at least one duplicate key or parse error
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable


class DuplicateKeyError(ValueError):
    """Raised when a JSON object contains duplicate keys."""

    def __init__(self, file: Path, key: str, detail: str = "") -> None:
        self.file = file
        self.key = key
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(
            f"{file}: duplicate key '{key}'{suffix}. "
            "json.load silently keeps the last value — fix by merging the two entries."
        )


def _strict_pairs_hook(file: Path):
    """Return an object_pairs_hook bound to the file path for error context."""

    def hook(pairs: list[tuple[str, object]]) -> dict:
        seen: dict[str, object] = {}
        for k, v in pairs:
            if k in seen:
                raise DuplicateKeyError(file, k)
            seen[k] = v
        return seen

    return hook


def validate_file(path: Path) -> list[str]:
    """Validate one JSON file. Return list of error messages (empty when clean)."""
    try:
        with path.open(encoding="utf-8") as fh:
            json.load(fh, object_pairs_hook=_strict_pairs_hook(path))
        return []
    except DuplicateKeyError as e:
        return [str(e)]
    except json.JSONDecodeError as e:
        return [f"{path}: JSON parse error at line {e.lineno} col {e.colno}: {e.msg}"]


def discover(paths: list[str]) -> list[Path]:
    """Expand CLI args into a sorted, deduplicated list of JSON files."""
    if not paths:
        repo_root = Path(__file__).resolve().parent.parent
        return sorted((repo_root / "data").rglob("*.json"))

    out: list[Path] = []
    for p in paths:
        path = Path(p)
        if path.is_dir():
            out.extend(path.rglob("*.json"))
        elif path.is_file():
            out.append(path)
        else:
            out.extend(Path().glob(p))
    # Dedupe while preserving sort order
    return sorted(set(out))


def main(argv: list[str]) -> int:
    files = discover(argv)
    if not files:
        print("::error::No JSON files found to validate", file=sys.stderr)
        return 1

    all_errors: list[tuple[Path, str]] = []
    for f in files:
        errors = validate_file(f)
        if errors:
            for msg in errors:
                # GitHub Actions error annotation
                print(f"::error file={f}::{msg}", file=sys.stderr)
            all_errors.extend((f, msg) for msg in errors)
        else:
            print(f"  OK: {f}")

    if all_errors:
        print(
            f"\nValidation FAILED: {len(all_errors)} issue(s) across "
            f"{len({f for f, _ in all_errors})} file(s) "
            f"(scanned {len(files)} total)",
            file=sys.stderr,
        )
        return 1

    print(f"\nAll {len(files)} JSON file(s) pass duplicate-key validation")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
