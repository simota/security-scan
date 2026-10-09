#!/usr/bin/env python3
"""Fail when a document cites a repository file that does not exist.

    python3 scripts/ci/check_doc_refs.py

Checks backticked `reference/...`, `scripts/...` and `templates/...` paths
(resolved against the skill), backticked repository paths such as
`skills/security-scan/...`, `docs/...`, `examples/...` and `tests/...`, and
relative Markdown links, in every tracked Markdown document.
"""
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "skills" / "security-scan"
DOCS = sorted({*REPO.glob("*.md"), *REPO.glob("docs/*.md"), *SKILL.glob("*.md"),
               *SKILL.glob("reference/*.md"), *SKILL.glob("templates/*.md")})
SKILL_REF = re.compile(r"`((?:reference|scripts|templates)/[A-Za-z][A-Za-z0-9._/-]*)`")
REPO_REF = re.compile(r"`((?:skills/security-scan|docs|examples|tests|scripts/ci)/[A-Za-z0-9._/-]*[A-Za-z0-9_-])`")
LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?\)")


def problems():
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        rel = doc.relative_to(REPO)
        for ref in sorted(set(SKILL_REF.findall(text))):
            # A bare scripts/ci/... path is a repository path, not a skill path.
            base = REPO if ref.startswith("scripts/ci/") else SKILL
            if not (base / ref.rstrip("/")).exists():
                yield f"{rel} cites {ref}, which does not exist"
        for ref in sorted(set(REPO_REF.findall(text))):
            if "*" not in ref and not (REPO / ref).exists():
                yield f"{rel} cites {ref}, which does not exist"
        for target in sorted(set(LINK.findall(text))):
            if re.match(r"[a-z][a-z0-9+.-]*:", target) or "{{" in target:
                continue  # External URL or a template placeholder.
            if not (doc.parent / target).exists():
                yield f"{rel} links to {target}, which does not exist"


def main():
    found = list(problems())
    for line in found:
        print("MISS " + line, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
