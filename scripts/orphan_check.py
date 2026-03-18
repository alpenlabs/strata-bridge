#!/usr/bin/env python3

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Sequence


REPO_ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_PATHS = {
    Path(".vscode/settings.json"),
}
COMMENT_PREFIXES = ("///", "//!", "//", "#", "*")
RUST_DOC_PREFIXES = {"///", "//!"}
JIRA_LINK_PREFIX = "https://atlassian.alpenlabs.net/browse/STR-"
SUPPORTED_SLUGS = ("TODO", "FIXME", "NOTE", "HACK", "PERF")
SUPPORTED_FORMATS = ("jira-link", "assignee")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check comment formats for selected slugs.",
    )
    parser.add_argument(
        "--format",
        required=True,
        choices=SUPPORTED_FORMATS,
        help="Format rule to enforce.",
    )
    parser.add_argument(
        "--slugs",
        required=True,
        nargs="+",
        choices=SUPPORTED_SLUGS,
        help="Comment slugs to check.",
    )
    parser.add_argument(
        "--allow-rust-docstrings",
        nargs="*",
        default=[],
        choices=SUPPORTED_SLUGS,
        help="Slugs exempt from checks in Rust doc comments (`///`, `//!`).",
    )
    return parser.parse_args()


def iter_tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    return [Path(path.decode("utf-8")) for path in result.stdout.split(b"\0") if path]


def parse_comment(line: str) -> tuple[str, str] | None:
    stripped = line.lstrip()

    for prefix in COMMENT_PREFIXES:
        if stripped.startswith(prefix):
            return prefix, stripped[len(prefix) :].strip()

    return None


def matching_slug(remainder: str, slugs: Sequence[str]) -> str | None:
    for slug in slugs:
        if remainder.startswith(slug):
            return slug
    return None


def find_candidates(
    path: Path,
    slugs: Sequence[str],
) -> list[tuple[int, str, str, str]]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    candidates: list[tuple[int, str, str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        parsed = parse_comment(line)
        if parsed is None:
            continue

        prefix, remainder = parsed
        slug = matching_slug(remainder, slugs)
        if slug is None:
            continue

        candidates.append((line_number, prefix, remainder, line.strip()))

    return candidates


def is_valid_jira_link(remainder: str, slug: str) -> bool:
    expected_prefix = f"{slug}: <{JIRA_LINK_PREFIX}"
    if not remainder.startswith(expected_prefix):
        return False

    suffix = remainder[len(expected_prefix) :]
    if not suffix.endswith(">"):
        return False

    ticket = suffix[:-1]
    return ticket.isdigit()


def is_valid_assignee_format(remainder: str, slug: str) -> bool:
    expected_prefix = f"{slug}: ("
    if not remainder.startswith(expected_prefix):
        return False

    assignee_and_description = remainder[len(expected_prefix) :]
    assignee, separator, description = assignee_and_description.partition(")")
    if separator == "":
        return False

    if not assignee or any(ch.isspace() for ch in assignee):
        return False

    if not description.startswith(" "):
        return False

    return bool(description.strip())


def is_valid_format(
    prefix: str,
    remainder: str,
    slug: str,
    format_name: str,
    rust_docstring_exemptions: set[str],
) -> bool:
    if prefix in RUST_DOC_PREFIXES and slug in rust_docstring_exemptions:
        return True

    if format_name == "jira-link":
        return is_valid_jira_link(remainder, slug)
    if format_name == "assignee":
        return is_valid_assignee_format(remainder, slug)

    raise ValueError(f"unsupported format: {format_name}")


def format_label(format_name: str) -> str:
    if format_name == "jira-link":
        return "Jira-link"
    if format_name == "assignee":
        return "assignee"
    raise ValueError(f"unsupported format: {format_name}")


def example_formats(format_name: str, slugs: Sequence[str]) -> list[str]:
    if format_name == "jira-link":
        return [f"// {slug}: <{JIRA_LINK_PREFIX}1234>" for slug in slugs]
    if format_name == "assignee":
        return [f"// {slug}: (github_id) Description" for slug in slugs]
    raise ValueError(f"unsupported format: {format_name}")


def main() -> int:
    args = parse_args()
    slugs = tuple(args.slugs)
    rust_docstring_exemptions = set(args.allow_rust_docstrings)
    failures: list[tuple[Path, int, str]] = []

    for relative_path in iter_tracked_files():
        if relative_path in EXCLUDED_PATHS:
            continue

        path = REPO_ROOT / relative_path
        for line_number, prefix, remainder, original_line in find_candidates(
            path, slugs
        ):
            slug = matching_slug(remainder, slugs)
            assert slug is not None

            if is_valid_format(
                prefix,
                remainder,
                slug,
                args.format,
                rust_docstring_exemptions,
            ):
                continue

            failures.append((relative_path, line_number, original_line))

    joined_slugs = "/".join(slugs)
    label = format_label(args.format)

    if not failures:
        print(f"All {joined_slugs} comments use the expected {label} format.")
        return 0

    print(f"Found {joined_slugs} comments without the expected {label} format:\n")
    for path, line_number, line in failures:
        print(f"{path}:{line_number}: {line}")

    print("\nExpected format:")
    for example in example_formats(args.format, slugs):
        print(f"  {example}")

    if args.format == "jira-link":
        print("Optional summary lines may follow on the next comment line.")

    if rust_docstring_exemptions:
        exempted = ", ".join(sorted(rust_docstring_exemptions))
        print(f"Rust doc comments (`///`, `//!`) are exempt for: {exempted}.")

    return 1


if __name__ == "__main__":
    sys.exit(main())
