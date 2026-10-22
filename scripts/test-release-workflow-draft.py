#!/usr/bin/env python3
"""Regression checks for the read-only tag workflow.

Replaces the previous draft-preservation check (every softprops/action-gh-release
step must set draft: true). The tag workflow is now artifacts-only: it must not
create a GitHub Release, must not request contents: write, and must not use
action-gh-release. Publication stays on the maintainer machine (release-upload
is a draft; release-publish byte-verifies, then promotes).
"""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
WRITE_PERM_RE = re.compile(r"^\s*([a-z-]+):\s*write\b", re.MULTILINE)
WRITE_ALL_RE = re.compile(r"^\s*permissions:\s*write-all\b", re.MULTILINE)
CONTENTS_READ_RE = re.compile(
    r"^permissions:\s*\n\s+contents:\s*read\b", re.MULTILINE
)
BANNED = (
    "action-gh-release",
    "gh release ",
    "contents: write",
    "GITHUB_TOKEN: ${{ secrets",
)


def validate(text: str) -> tuple[bool, str]:
    failures: list[str] = []
    if WRITE_ALL_RE.search(text):
        failures.append("write-all permissions granted")
    for match in WRITE_PERM_RE.finditer(text):
        failures.append(f"write permission granted: {match.group(1)}")
    if not CONTENTS_READ_RE.search(text):
        failures.append("workflow-level permissions must be contents: read")
    for banned in BANNED:
        if banned in text:
            failures.append(f"release-creating construct present: {banned!r}")
    if "upload-artifact" not in text:
        failures.append("tag workflow must upload artifacts (no GitHub Release)")
    if failures:
        return False, "; ".join(failures)
    return True, "tag workflow is read-only and never creates a release"


def mutate_insert_action(text: str) -> str:
    """Fixture: sneak a release-writing action back in."""
    return text.replace(
        "uses: actions/upload-artifact@",
        "uses: softprops/action-gh-release@deadbeef\n"
        "        with:\n"
        "          draft: true\n"
        "      - uses: actions/upload-artifact@",
        1,
    )


def mutate_contents_write(text: str) -> str:
    return text.replace("contents: read", "contents: write", 1)


workflow = WORKFLOW.read_text(encoding="utf-8")
valid, message = validate(workflow)
if not valid:
    raise SystemExit(f"FAIL: fixed workflow rejected: {message}")
print(f"PASS: {message}")

for label, mutator in (
    ("action-gh-release restored", mutate_insert_action),
    ("contents write", mutate_contents_write),
):
    fixture = mutator(workflow)
    valid, _ = validate(fixture)
    if valid:
        raise SystemExit(f"FAIL: validator accepted fixture with {label}")
    print(f"PASS: validator rejects {label}")
