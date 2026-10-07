"""Step <-> trace consistency between reference/perspectives.md and reference/coverage-trace.md.

Each hunt step's Catalog cell lists exactly the ASVS sections, API Security Top 10 risks and
CWE Top 25 entries whose trace rows cite that step; other CWEs in the cell are closer children.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/security-scan"
STEP_ROW = re.compile(r"^\| ([A-Z]{2}\d) \|.*\| ([^|]+) \|$")
PERSPECTIVES = ("Actor and tenant", "Role and privilege", "Identity and session", "Input handling",
                "Data exposure", "Business rules", "Files and content", "Availability",
                "Configuration and deployment", "Secrets", "Dependencies and platform",
                "Build and delivery", "Integrations", "Client side", "Privacy")


def catalog_cells():
    text = (SKILL / "reference/perspectives.md").read_text(encoding="utf-8")
    cells = {}
    for line in text.splitlines():
        match = STEP_ROW.match(line)
        if match and "·" in match.group(2):
            parts = [part.strip() for part in match.group(2).split("·")]
            cells[match.group(1)] = [set(re.findall(pattern, part)) for pattern, part in
                                     zip((r"CWE-\d+", r"V\d+\.\d+", r"API\d+"), parts)]
    return cells


def expand(steps):
    out = set()
    for start, end in re.findall(r"\b([A-Z]{2}\d)(?:–([A-Z]{2}\d))?\b", steps):
        if end:
            out |= {start[:2] + str(n) for n in range(int(start[2]), int(end[2]) + 1)}
        else:
            out.add(start)
    return out


def trace_rows():
    """Yield (catalog index, key, perspectives cell, steps cell) for every trace row."""
    text = (SKILL / "reference/coverage-trace.md").read_text(encoding="utf-8")
    for line in text.splitlines():
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if re.match(r"^V\d+\.\d+$", cols[0]):
            yield 1, cols[0], cols[2], cols[3]
        elif cols[0].startswith("API") and ":2023" in cols[0]:
            yield 2, cols[0].split(":")[0], cols[1], cols[2]
        elif cols[0].isdigit() and len(cols) == 7:
            yield 0, cols[1].split()[0], cols[2], cols[3]


class CatalogTraceTests(unittest.TestCase):
    def test_step_catalog_matches_trace_rows(self):
        cells = catalog_cells()
        self.assertGreater(len(cells), 45)
        cited = {step: [set(), set(), set()] for step in cells}
        top25 = set()
        for index, key, _, steps in trace_rows():
            if index == 0:
                top25.add(key)
            for step in expand(steps):
                self.assertIn(step, cited, f"{key} cites unknown step {step}")
                cited[step][index].add(key)
        for step, (cwe, asvs, api) in cells.items():
            with self.subTest(step=step):
                self.assertEqual(cwe & top25, cited[step][0])
                self.assertEqual(asvs, cited[step][1])
                self.assertEqual(api, cited[step][2])

    def test_trace_names_only_the_fifteen_perspectives(self):
        for _, key, perspectives, _ in trace_rows():
            with self.subTest(row=key):
                for name in perspectives.split(";"):
                    self.assertIn(name.strip(), PERSPECTIVES)

    def test_trace_covers_every_catalog_row(self):
        counts = [0, 0, 0]
        for index, *_ in trace_rows():
            counts[index] += 1
        self.assertEqual(counts[0], 25)
        self.assertEqual(counts[2], 10)
        self.assertGreaterEqual(counts[1], 70)


if __name__ == "__main__":
    unittest.main()
