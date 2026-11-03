"""Renumbering partitions records without pairwise dictionary comparisons."""
import copy
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import findings  # noqa: E402


class ComparedFinding(dict):
    comparisons = 0

    def __eq__(self, other):
        type(self).comparisons += 1
        return super().__eq__(other)


def record(number, *, excluded=False, **fields):
    return {"id": "F-%03d" % number, "severity": "Low", "location": "app.py:%d" % number,
            "validation": {"verdict": "FalsePositive" if excluded else "Unverified"}, **fields}


class RenumberPartitionTests(unittest.TestCase):
    def test_none_half_and_all_excluded_keep_numbering_through_999_findings(self):
        for count in (0, 1, 10, 99, 999):
            for mode in ("none", "half", "all"):
                with self.subTest(count=count, mode=mode):
                    excluded = {number for number in range(1, count + 1)
                                if mode == "all" or mode == "half" and number % 2 == 0}
                    source = [record(number, excluded=number in excluded, location="app.py:%d" % (count + 1 - number))
                              for number in range(1, count + 1)]
                    before = copy.deepcopy(source)
                    # All severities tie: included records follow numeric source
                    # lines, then excluded records follow their original IDs.
                    order = [number for number in range(count, 0, -1) if number not in excluded] + sorted(excluded)
                    expected = {"F-%03d" % old: "F-%03d" % new for new, old in enumerate(order, 1)}
                    actual = findings.renumber_map(source)
                    self.assertEqual(actual, expected)
                    self.assertEqual(list(actual), list(expected))
                    self.assertEqual(source, before)

    def test_severity_location_ties_and_dependency_records_keep_the_contract(self):
        source = [record(1, severity="Low", location="a.py:1"),
                  record(2, severity="High", location="z.py:9"),
                  record(3, severity="High", location="a.py:10-12"),
                  record(4, severity="High", location="a.py:2"),
                  record(5, severity="High", location="a.py:2"),
                  record(6, excluded=True, severity="High", location="a.py:1"),
                  record(7, validation={"verdict": "NotApplicable"}, severity="High", location="a.py:1"),
                  {"id": "D-001", "validation": "uninterpreted by code renumbering"}]
        expected_order = [4, 5, 3, 2, 1, 6, 7]
        self.assertEqual(findings.renumber_map(source),
                         {"F-%03d" % old: "F-%03d" % new for new, old in enumerate(expected_order, 1)})

    def test_equal_and_aliased_dictionaries_keep_existing_duplicate_id_behavior(self):
        included, excluded = record(1), record(2, excluded=True)
        source = [excluded, included, copy.deepcopy(included), included, copy.deepcopy(excluded)]
        before = copy.deepcopy(source)
        # The public helper keeps repeated records; the CLI's schema validator
        # separately refuses duplicate IDs. Last mapping values still win here.
        self.assertEqual(findings.renumber_map(source), {"F-001": "F-003", "F-002": "F-005"})
        self.assertEqual(source, before)
        self.assertIs(source[1], source[3])

    def test_partition_does_not_compare_finding_dictionaries(self):
        source = [ComparedFinding(record(number, excluded=number % 2 == 0)) for number in range(1, 1000)]
        ComparedFinding.comparisons = 0
        result = findings.renumber_map(source)
        self.assertEqual(len(result), 999)
        self.assertEqual(ComparedFinding.comparisons, 0)

    def test_id_validation_still_precedes_partition_and_sort_errors(self):
        with self.assertRaises(KeyError) as error:
            findings.renumber_map([record(1, validation=42), {}])
        self.assertEqual(error.exception.args, ("id",))
        with self.assertRaises(AttributeError) as error:
            findings.renumber_map([record(1, severity="Unknown"), record(2, validation=42)])
        self.assertEqual(str(error.exception), "'int' object has no attribute 'get'")
        with self.assertRaises(KeyError) as error:
            findings.renumber_map([record(1, severity="Unknown"), record(2)])
        self.assertEqual(error.exception.args, ("Unknown",))

    def test_excluded_records_still_do_not_require_sort_fields(self):
        self.assertEqual(findings.renumber_map([
            {"id": "F-002", "validation": {"verdict": "NotApplicable"}},
            {"id": "F-001", "validation": {"verdict": "FalsePositive"}},
        ]), {"F-001": "F-001", "F-002": "F-002"})


if __name__ == "__main__":
    unittest.main()
