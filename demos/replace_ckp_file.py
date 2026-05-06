#!/usr/bin/env python3
"""Find and replace .ckp files within a chosen directory.

This script is intentionally conservative:
- It only searches under a user-provided root directory.
- It defaults to dry-run mode.
- It creates a backup before replacing a file.
- It refuses to replace multiple matches unless --all is provided.
- It can infer likely targets from local context when --auto is used.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from difflib import SequenceMatcher


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find .ckp files under a directory and replace them with another file."
    )
    parser.add_argument(
        "--search-root",
        required=True,
        help="Directory to search inside.",
    )
    parser.add_argument(
        "--replacement",
        required=True,
        help="Path to the .ckp file that should replace the matched file(s).",
    )
    parser.add_argument(
        "--name",
        help="Optional exact filename to match, for example 'Project (Modified) (1).ckp'.",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Infer likely target .ckp file(s) from local context under the search root.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Replace every matching .ckp file instead of requiring a single match.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Perform the replacement. Without this flag, the script only reports matches.",
    )
    return parser.parse_args()


def find_matches(search_root: Path, name: str | None) -> list[Path]:
    pattern = name if name else "*.ckp"
    return sorted(path for path in search_root.rglob(pattern) if path.is_file())


def normalize_name(name: str) -> str:
    lowered = name.lower().removesuffix(".ckp")
    cleaned = []
    skip = False
    for char in lowered:
        if char == "(":
            skip = True
        elif char == ")":
            skip = False
        elif not skip and char.isalnum():
            cleaned.append(char)
    return "".join(cleaned)


def infer_matches(search_root: Path, replacement: Path) -> list[Path]:
    replacement_name = replacement.name
    replacement_norm = normalize_name(replacement_name)
    candidates = [
        path
        for path in search_root.rglob("*.ckp")
        if path.is_file() and path.resolve() != replacement.resolve()
    ]
    if not candidates:
        return []

    exact_stem = replacement.stem
    if " (" in exact_stem:
        base_stem = exact_stem.split(" (", 1)[0] + replacement.suffix
        exact_name_matches = [path for path in candidates if path.name == base_stem]
        if exact_name_matches:
            return sorted(exact_name_matches)

    normalized_matches = [path for path in candidates if normalize_name(path.name) == replacement_norm]
    if normalized_matches:
        return sorted(normalized_matches)

    ranked = sorted(
        candidates,
        key=lambda path: SequenceMatcher(None, path.name.lower(), replacement_name.lower()).ratio(),
        reverse=True,
    )
    if not ranked:
        return []
    best_score = SequenceMatcher(None, ranked[0].name.lower(), replacement_name.lower()).ratio()
    if best_score < 0.60:
        return []
    return [path for path in ranked if SequenceMatcher(None, path.name.lower(), replacement_name.lower()).ratio() == best_score]


def backup_path_for(target: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return target.with_suffix(target.suffix + f".bak.{timestamp}")


def main() -> int:
    args = parse_args()

    search_root = Path(args.search_root).expanduser().resolve()
    replacement = Path(args.replacement).expanduser().resolve()

    if not search_root.exists() or not search_root.is_dir():
        print(f"Search root is not a directory: {search_root}", file=sys.stderr)
        return 1

    if not replacement.exists() or not replacement.is_file():
        print(f"Replacement file does not exist: {replacement}", file=sys.stderr)
        return 1

    if replacement.suffix.lower() != ".ckp":
        print(f"Replacement file must be a .ckp file: {replacement}", file=sys.stderr)
        return 1

    if args.auto:
        matches = infer_matches(search_root, replacement)
    else:
        matches = find_matches(search_root, args.name)
    if not matches:
        print(f"No matching .ckp files found under {search_root}")
        return 1

    print("Matched files:")
    for match in matches:
        print(f"- {match}")

    if len(matches) > 1 and not args.all:
        print(
            "\nMultiple matches found. Re-run with --name to narrow the search or --all to replace every match."
        )
        return 1

    if not args.apply:
        print("\nDry run only. Re-run with --apply to perform the replacement.")
        return 0

    for target in matches:
        backup = backup_path_for(target)
        shutil.copy2(target, backup)
        shutil.copy2(replacement, target)
        print(f"Backed up {target} -> {backup}")
        print(f"Replaced {target} with {replacement}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
