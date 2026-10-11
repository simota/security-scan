"""Skill documents give commands that resolve from the installed skill directory."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "ci" / "check_doc_refs.py"
spec = importlib.util.spec_from_file_location("check_doc_refs", SCRIPT)
check_doc_refs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check_doc_refs)


def problems(text):
    return list(check_doc_refs.skill_command_problems("reference/x.md", text))


class SkillCommandTests(unittest.TestCase):
    def test_repository_root_command_without_lead_in_is_reported(self):
        text = ("Use the CLI for each finding:\n\n```sh\n"
                "python3 skills/security-scan/scripts/verification_workflow.py status findings.json\n```\n")
        found = problems(text)
        self.assertEqual(len(found), 1, found)
        self.assertIn("reference/x.md:4 runs a repository-root path", found[0])

    def test_tmp_output_is_reported_even_in_a_source_repository_demo(self):
        text = ("Run from the source repository's root:\n\n```sh\n"
                "python3 skills/security-scan/scripts/render.py f.json --out /tmp/report\n```\n")
        found = problems(text)
        self.assertEqual(len(found), 1, found)
        self.assertIn("writes under /tmp/", found[0])

    def test_skill_relative_and_labelled_demo_commands_pass(self):
        text = ("From this skill's directory:\n\n```sh\n"
                "python3 scripts/render.py <out>/findings.json --out <out> --repo <repo>\n```\n\n"
                "Run it from the security-scan source repository's root:\n\n```sh\n"
                'work=$(mktemp -d "${TMPDIR:-/tmp}/demo.XXXXXX")\n'
                "python3 skills/security-scan/scripts/reproduction.py verify \"$work/bundle\"\n```\n")
        self.assertEqual(problems(text), [])

    def test_prose_outside_fences_is_not_a_command(self):
        self.assertEqual(problems("The tests live under `skills/security-scan/` and /tmp/ is a path.\n"), [])

    def test_repository_documents_pass(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
