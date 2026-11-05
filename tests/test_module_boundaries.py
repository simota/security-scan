"""Dependency direction between the skill's scripts.

render.py is the presentation layer. Record tools (merge, capture, audits, the
runner) validate and redact through report_schema.py and secret_redaction.py,
and only ever start render.py as a program, so a change to the report's look
cannot change how a record is checked. Import cycles are refused outright.
"""
import ast
from pathlib import Path
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills" / "security-scan" / "scripts"
PRESENTATION = {"render"}
# Contract modules sit below every tool: they may not reach up to presentation or the PDF kit.
CONTRACT = {"report_schema", "secret_redaction", "url_redaction"}


def local_imports(path, deferred=True):
    """Sibling modules imported by one script: module level only, or also inside functions."""
    local = {p.stem for p in SCRIPTS.glob("*.py")} | {"scan_report_kit"}
    tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
    nodes = ast.walk(tree) if deferred else tree.body
    found = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module]
        else:
            continue
        found.update(name.split(".")[0] for name in names if name.split(".")[0] in local)
    return found


def cycles(graph):
    """Every elementary cycle, each as a sorted tuple of its modules."""
    found = set()

    def walk(start, node, trail):
        for dep in graph.get(node, ()):
            if dep == start:
                found.add(tuple(sorted(trail)))
            elif dep not in trail and dep > start:
                walk(start, dep, trail + [dep])

    for name in graph:
        walk(name, name, [name])
    return found


# Function-level imports that close a loop on purpose, each taken only on a
# controller or CLI path, never while a module loads: report_schema validates
# workflow journals and the workflow controller validates the whole report before
# it writes; three_pass derives workflow states that the controller reads back;
# the controller's `bundle` command runs reproduction, which reuses its checks;
# verification reads fresh provenance and evidence_integrity's CLI validates
# through verification. A new loop must be added here deliberately.
KNOWN_DEFERRED_CYCLES = {
    ("evidence_integrity", "verification"),
    ("report_schema", "three_pass", "verification_workflow"),
    ("report_schema", "verification_workflow"),
    ("reproduction", "verification_workflow"),
    ("three_pass", "verification_workflow"),
}


class ModuleBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.graph = {p.stem: local_imports(p) for p in sorted(SCRIPTS.glob("*.py"))}

    def test_only_presentation_imports_the_renderer(self):
        offenders = sorted(name for name, deps in self.graph.items()
                           if name not in PRESENTATION and deps & PRESENTATION)
        self.assertEqual(offenders, [], "record tools must use report_schema/secret_redaction, not render")

    def test_contract_modules_stay_below_presentation(self):
        for name in sorted(CONTRACT):
            with self.subTest(module=name):
                self.assertIn(name, self.graph)
                self.assertFalse(self.graph[name] & (PRESENTATION | {"scan_report_kit"}), self.graph[name])

    def test_no_import_cycles_at_load_time(self):
        graph = {p.stem: local_imports(p, deferred=False) for p in SCRIPTS.glob("*.py")}
        self.assertEqual(cycles(graph), set())

    def test_deferred_cycles_are_only_the_known_ones(self):
        self.assertEqual(cycles(self.graph), KNOWN_DEFERRED_CYCLES)

    def test_renderer_keeps_its_schema_and_redaction_names(self):
        """Callers that import render for the contract keep working: the names are the same objects."""
        import importlib.util
        import sys
        from unittest.mock import patch

        def load(stem):
            spec = importlib.util.spec_from_file_location(stem, SCRIPTS / f"{stem}.py")
            module = importlib.util.module_from_spec(spec)
            with patch.object(sys, "path", [str(SCRIPTS)] + sys.path):
                spec.loader.exec_module(module)
            return module

        render = load("render")
        schema, redaction = sys.modules["report_schema"], sys.modules["secret_redaction"]
        for name in ("SchemaError", "load", "validate_data", "json_depth", "MAX_JSON_DEPTH", "EXCLUDED",
                     "SEVERITIES", "CONFIDENCES", "STATUSES", "VERDICTS", "LOC_RE", "http_url"):
            self.assertIs(getattr(render, name), getattr(schema, name), name)
        for name in ("redact", "mask_multiline", "secret_in_source", "sensitive_path", "TOKEN_RE", "JWT_RE"):
            self.assertIs(getattr(render, name), getattr(redaction, name), name)


if __name__ == "__main__":
    unittest.main()
