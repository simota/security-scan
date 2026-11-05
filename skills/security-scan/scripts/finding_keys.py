"""Run-independent identity for findings, shared by compare.py and export.py.

`F-NNN` and `D-NNN` IDs are assigned per run in severity order, so the same
weakness carries different IDs in two assessments. These helpers describe a
finding by what it is (part, file, weakness class, title) instead, which lets a
later run be compared with an earlier one and lets external trackers (SARIF
consumers, spreadsheets) follow a finding across rescans.
Standard library only; never imports the renderer.
"""
import hashlib
import re
import unicodedata

from report_schema import EXCLUDED, LOC_RE

_WORD = re.compile(r"[^\W_]+", re.UNICODE)
# CJK text has no spaces: compare it as overlapping character pairs instead.
_CJK = re.compile(r"[぀-ヿ㐀-鿿가-힯]")


def part(finding):
    """`deps` for scanner-owned dependency findings (D-*), `code` for everything else."""
    return "deps" if str(finding["id"]).startswith("D-") else "code"


def included(finding):
    """Ruled-out findings (FalsePositive, NotApplicable) stay visible but are not counted."""
    return finding.get("validation", {}).get("verdict", "Unverified") not in EXCLUDED


def location(finding):
    """(path, start, end) from `path:line[-end]`; (location, None, None) when it is not one."""
    raw = str(finding.get("location", "")).strip()
    match = LOC_RE.match(raw)
    if not match:
        return raw.replace("\\", "/"), None, None
    path = match.group("path").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    return path, start, max(start, end)


def normalized_title(text):
    text = unicodedata.normalize("NFKC", str(text or "")).casefold()
    return " ".join(_WORD.findall(text))


def title_tokens(text):
    text = normalized_title(text)
    tokens = set(text.split())
    compact = "".join(ch for ch in text if _CJK.match(ch))
    tokens.update(compact[i:i + 2] for i in range(len(compact) - 1))
    return tokens


def title_similarity(a, b):
    """Jaccard similarity of title tokens, 0.0-1.0."""
    left, right = title_tokens(a), title_tokens(b)
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def rule_id(finding):
    """The weakness class: the CWE when recorded, otherwise the perspective (category)."""
    if finding.get("cwe"):
        return finding["cwe"]
    slug = re.sub(r"[^a-z0-9]+", "-", normalized_title(finding.get("category", ""))).strip("-")
    return "security-scan/" + (slug or "uncategorized")


def fingerprint(finding):
    """A stable digest that ignores the run's ID and line drift.

    Dependency findings are keyed by package and advisory (or by scanner
    title and file for supply-chain checks); code findings by file, weakness
    class and title. Two runs that describe one weakness with different
    words get different fingerprints: compare.py matches those by similarity.
    """
    path = location(finding)[0]
    if part(finding) == "deps":
        advisories = sorted(str(a) for a in finding.get("advisory_ids") or [] if isinstance(a, str))
        if finding.get("package") and advisories:
            basis = ["deps", str(finding.get("package")), *advisories]
        else:
            basis = ["deps", path, normalized_title(finding.get("title"))]
    else:
        basis = ["code", path, rule_id(finding), normalized_title(finding.get("title"))]
    return hashlib.sha256("\x1f".join(basis).encode("utf-8")).hexdigest()[:32]
