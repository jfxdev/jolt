#!/usr/bin/env python3
"""Allocate immutable YYYY-MM-DD[.N] release tags from locally fetched refs."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path


def versions_for_day(tags: list[str], day: str) -> list[tuple[int, str]]:
    pattern = re.compile(rf"^{re.escape(day)}(?:\.(\d+))?$")
    return [
        (int(match.group(1) or 0), tag)
        for tag in tags
        if (match := pattern.fullmatch(tag))
    ]


def allocate_version(tags: list[str], day: str, commit_tags: list[str]) -> str:
    dated_commit_tags = versions_for_day(commit_tags, day)
    if dated_commit_tags:
        return max(dated_commit_tags)[1]
    existing = versions_for_day(tags, day)
    if not existing:
        return day
    return f"{day}.{max(number for number, _ in existing) + 1}"


def git_lines(repository: Path, *args: str) -> list[str]:
    output = subprocess.check_output(["git", "-C", str(repository), *args], text=True)
    return [line for line in output.splitlines() if line]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    allocate = subparsers.add_parser("allocate")
    allocate.add_argument("--day", required=True)
    allocate.add_argument("--sha", required=True)
    allocate.add_argument("--repository", type=Path, default=Path("."))
    args = parser.parse_args()

    tags = git_lines(args.repository, "tag", "--list")
    commit_tags = git_lines(args.repository, "tag", "--points-at", args.sha)
    print(allocate_version(tags, args.day, commit_tags))


if __name__ == "__main__":
    main()
