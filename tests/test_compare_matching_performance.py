"""compare.match(): indexed candidate pairs give the all-pairs result with bounded work."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "skills/security-scan/scripts"))

import compare  # noqa: E402


def code(fid, title, location, **extra):
    return {"id": fid, "title": title, "location": location, "category": "Injection", **extra}


def deps(fid, title, location, **extra):
    return {"id": fid, "title": title, "location": location, "category": "Dependencies and platform", **extra}


def all_pairs(baseline, current):
    """The previous matching: score every pair, greedy by descending score."""
    candidates = sorted((-s, a["id"], b["id"], i, j)
                        for i, a in enumerate(baseline) for j, b in enumerate(current)
                        for s in (compare.score(a, b),) if s >= compare.MATCH_THRESHOLD)
    used_a, used_b, pairs = set(), set(), []
    for neg, _, _, i, j in candidates:
        if i not in used_a and j not in used_b:
            used_a.add(i)
            used_b.add(j)
            pairs.append((i, j, -neg))
    return pairs


MANY = " ".join("w%d" % k for k in range(2000))


BASELINE = [
    code("F-001", "SQL injection in login", "app/auth.py:10", cwe="CWE-89"),
    code("F-002", "Stored XSS in profile", "app/views.py:40"),
    code("F-003", "ＳＱＬ Injection in search", "app/search.py:5"),
    code("F-004", MANY, "a.py:1", cwe="CWE-89"),
    code("F-005", " ".join("w%d" % k for k in range(998)), "b.py:1"),
    code("F-006", "認証回避の不備", "app/auth.py:90"),
    code("F-007", "", "c.py:3"),
    deps("D-001", "Vulnerable lodash", "package-lock.json:3", package="lodash", advisory_ids=["GHSA-1"]),
    deps("D-002", "Vulnerable react", "package-lock.json:9", package="react", advisory_ids=[]),
    deps("D-003", "Unpinned action", ".github/workflows/ci.yml:4"),
    deps("D-004", "Install script", "package.json:2", package=""),
]
CURRENT = [
    code("F-010", "sql injection in login", "app/auth.py:12", cwe="CWE-89"),  # line drift, case
    code("F-011", "Stored XSS in profile", "app/other.py:40"),  # same words, another file
    code("F-012", "SQL Injection in search", "./app/search.py:6"),  # NFKC, ./ prefix
    code("F-013", MANY.replace("w7 ", "zz "), "z.py:1", cwe="CWE-89"),  # 1999 of 2001 tokens shared (Jaccard 0.9990)
    code("F-014", " ".join("w%d" % k for k in range(997)) + " zz", "y.py:1"),  # small sets differ
    code("F-015", "認証回避の不備がある", "app/auth.py:91"),
    code("F-016", "", "c.py:3"),
    deps("D-010", "Vulnerable lodash (new title)", "package-lock.json:30", package="lodash", advisory_ids=["GHSA-1", "GHSA-2"]),
    deps("D-011", "Vulnerable react", "package-lock.json:9", package="react"),
    deps("D-012", "Unpinned action", ".github/workflows/ci.yml:7"),
    deps("D-013", "Install script", "package.json:2"),
]


class IndexedMatchingTests(unittest.TestCase):
    def assert_same_as_all_pairs(self, baseline, current):
        expected = all_pairs(baseline, current)
        self.assertEqual(compare.match(copy.deepcopy(baseline), copy.deepcopy(current)), expected)
        return expected

    def test_index_finds_every_matching_pair(self):
        pairs = self.assert_same_as_all_pairs(BASELINE, CURRENT)
        matched = {(BASELINE[i]["id"], CURRENT[j]["id"]) for i, j, _ in pairs}
        # Different files with the same words, NFKC titles and very long titles still match.
        for pair in (("F-002", "F-011"), ("F-003", "F-012"), ("F-004", "F-013"), ("D-001", "D-010")):
            self.assertIn(pair, matched)
        self.assertNotIn(("F-005", "F-014"), matched)

    def test_reversed_and_duplicated_inputs_match_all_pairs(self):
        self.assert_same_as_all_pairs(CURRENT, BASELINE)
        self.assert_same_as_all_pairs(BASELINE + CURRENT, CURRENT + BASELINE[::-1])
        self.assert_same_as_all_pairs([], CURRENT)
        self.assert_same_as_all_pairs(BASELINE, [])

    def test_unvalidated_extension_values_fall_back_to_every_pair(self):
        odd = copy.deepcopy(BASELINE)
        odd[7]["package"] = ["lodash"]
        self.assertEqual(compare.match(odd, CURRENT), all_pairs(odd, CURRENT))
        bad = copy.deepcopy(BASELINE)
        bad[8]["advisory_ids"] = [["GHSA-1"]]
        with self.assertRaises(TypeError):
            all_pairs(bad, CURRENT)
        with self.assertRaises(TypeError):
            compare.match(bad, CURRENT)

    def test_unrelated_findings_are_not_scored_pairwise(self):
        baseline = [code("F-%04d" % n, "issue %d" % n, "src/m%d.py:1" % n) for n in range(300)]
        current = [code("F-%04d" % n, "issue %d" % n, "src/m%d.py:2" % n) for n in range(300)]
        calls = []
        original = compare._score

        def counted(a, b):
            calls.append(1)
            return original(a, b)

        with patch.object(compare, "_score", counted):
            pairs = compare.match(baseline, current)
        self.assertEqual(len(pairs), 300)
        # Each finding shares a file and title only with its own counterpart.
        self.assertLessEqual(len(calls), 300)


if __name__ == "__main__":
    unittest.main()
