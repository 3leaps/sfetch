#!/usr/bin/env python3
"""Regression checks for draft-preserving release action steps."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
ACTION_RE = re.compile(r"^(\s*)uses:\s*softprops/action-gh-release@\S+\s*(?:#.*)?$")


def action_blocks(text: str) -> list[tuple[int, int, int]]:
    """Return start, end, and child indentation for each release action step."""
    lines = text.splitlines()
    blocks: list[tuple[int, int, int]] = []
    for uses_index, line in enumerate(lines):
        match = ACTION_RE.match(line)
        if not match:
            continue
        uses_indent = len(match.group(1))
        step_indent = uses_indent - 2
        start = uses_index
        while start >= 0 and not re.match(rf"^ {{{step_indent}}}-\s+", lines[start]):
            start -= 1
        if start < 0:
            raise ValueError(
                f"release action at line {uses_index + 1} has no step boundary"
            )
        end = uses_index + 1
        while end < len(lines) and not re.match(
            rf"^ {{{step_indent}}}-\s+", lines[end]
        ):
            end += 1
        blocks.append((start, end, uses_indent + 2))
    return blocks


def validate(text: str) -> tuple[bool, str]:
    lines = text.splitlines()
    try:
        blocks = action_blocks(text)
    except ValueError as error:
        return False, str(error)
    if not blocks:
        return False, "release workflow has no softprops/action-gh-release steps"

    failures: list[str] = []
    for start, end, child_indent in blocks:
        drafts = [
            line.strip()
            for line in lines[start:end]
            if re.match(rf"^ {{{child_indent}}}draft:\s*", line)
        ]
        if drafts != ["draft: true"]:
            failures.append(
                f"release action step at line {start + 1} requires exactly one literal draft: true"
            )
    if failures:
        return False, "; ".join(failures)
    return True, f"{len(blocks)} release-writing action steps preserve draft state"


def mutate_last_action(text: str, replacement: str | None) -> str:
    lines = text.splitlines()
    blocks = action_blocks(text)
    if not blocks:
        raise ValueError("cannot mutate workflow without a release action")
    start, end, child_indent = blocks[-1]
    draft_indexes = [
        index
        for index in range(start, end)
        if re.match(rf"^ {{{child_indent}}}draft:\s*", lines[index])
    ]
    if len(draft_indexes) != 1:
        raise ValueError("last release action must contain exactly one draft setting")
    index = draft_indexes[0]
    if replacement is None:
        del lines[index]
    else:
        lines[index] = " " * child_indent + replacement
    return "\n".join(lines) + "\n"


workflow = WORKFLOW.read_text(encoding="utf-8")
valid, message = validate(workflow)
if not valid:
    raise SystemExit(f"FAIL: fixed workflow rejected: {message}")
print(f"PASS: {message}")

for label, replacement in (("missing draft", None), ("draft false", "draft: false")):
    fixture = mutate_last_action(workflow, replacement)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")
