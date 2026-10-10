"""Round-7 final review regressions: advisory ids in reference links, run block scalars beside
`env:`, linear flow mappings and env references, URL userinfo over-redaction, F-* order wording,
new-branch names in `git checkout -b`, and comments in checkout `ref:` values."""
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills/security-scan/scripts"
sys.path.insert(0, str(SCRIPTS))
import contract_check  # noqa: E402
import deps_scan  # noqa: E402
import render  # noqa: E402
import url_redaction  # noqa: E402

SHA = "0" * 40
PRT = "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    steps:\n"
CHECKOUT = "      - uses: actions/checkout@" + SHA + "\n        with:\n"


class ReferenceLinkTests(unittest.TestCase):
    def test_advisory_ids_in_queries_are_kept(self):
        for url in ("https://www.cve.org/CVERecord?id=CVE-2021-44228",
                    "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                    "https://osv.dev/list?q=PYSEC-2023-117",
                    "https://github.com/advisories?query=GHSA-jfh8-c2jp-5v3q",
                    "https://security-tracker.debian.org/tracker/?id=DSA-5555-1"):
            with self.subTest(url=url):
                self.assertEqual(render.public_href(url), url)

    def test_credential_parameters_are_still_dropped(self):
        self.assertEqual(render.public_href("https://h.invalid/x?id=CVE-2021-1&token=Zx9QmW4tR7uY2pL8"),
                         "https://h.invalid/x?id=CVE-2021-1")
        self.assertEqual(render.public_href("https://h.invalid/x?page=2&v=Zx9QmW4tR7uY2pL8"),
                         "https://h.invalid/x?page=2")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="security-scan-round7-")).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def high(self, body, name="w.yml"):
        path = self.tmp / ".github/workflows" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return [f["location"] for f in deps_scan.scan(self.tmp, False)["findings"] if f["severity"] == "High"]

    def timed(self, body):
        started = time.monotonic()
        self.high(body)
        self.assertLess(time.monotonic() - started, 2.0)

    def test_run_block_scalar_ends_before_sibling_env(self):
        self.assertTrue(self.high(PRT + "      - run: |\n          git fetch origin \"$REF\" && git checkout FETCH_HEAD\n"
                                  "        env:\n          REF: ${{ github.head_ref }}\n"))
        # The same text inside the script body is not an env definition.
        self.assertFalse(self.high(PRT + "      - run: |\n          git fetch origin \"$REF\" && git checkout FETCH_HEAD\n"
                                   "          REF: ${{ github.head_ref }}\n"))

    def test_unterminated_flow_mapping_is_linear(self):
        self.timed("on: push\njobs:\n  b:\n    runs-on: x\n    steps:\n      - uses: ./x\n        with: {"
                   + "a" * 200000 + "\n")
        self.assertEqual(deps_scan.flow_pairs('{ ref: "x", path: y, with: ${{ a, b }} } # ref: z'),
                         {"ref": '"x"', "path": "y", "with": "${{ a, b }}"})

    def test_long_env_value_referenced_many_times_is_parsed_once(self):
        self.timed("on: push\nenv:\n  X: \"" + "${{ github.sha }}" * 5000 + "\"\njobs:\n  b:\n    runs-on: x\n"
                   "    steps:\n" + "      - run: echo ${{ env.X }}\n" * 3000)

    def test_new_branch_names_are_not_checked_out(self):
        self.assertFalse(self.high(PRT + "      - uses: actions/checkout@" + SHA + "\n"
                                   "      - run: git checkout -b backport-${{ github.event.number }} origin/release\n"))
        self.assertFalse(self.high("on:\n  issue_comment:\n    types: [created]\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                                   "      - run: git checkout -b backport-${{ github.event.issue.number }} origin/release\n"))
        self.assertFalse(self.high(PRT + "      - run: git switch -c \"backport-$N\" origin/release\n"
                                   "        env:\n          N: ${{ github.event.number }}\n"))
        self.assertFalse(self.high(PRT + "      - run: git checkout -b ${{ github.head_ref }}\n"))
        for run in ("git fetch origin pull/${{ github.event.number }}/head && git checkout FETCH_HEAD",
                    "gh pr checkout ${{ github.event.number }}", "git checkout -b pr ${{ github.head_ref }}"):
            with self.subTest(run=run):
                self.assertTrue(self.high(PRT + "      - run: " + run + "\n"))
        self.assertTrue(self.high(PRT + "      - run: git fetch origin \"refs/pull/$N/merge\" && git checkout FETCH_HEAD\n"
                                  "        env:\n          N: ${{ github.event.number }}\n"))

    def test_comments_in_checkout_ref_are_ignored(self):
        self.assertFalse(self.high(PRT + CHECKOUT + "          ref: main # not ${{ github.head_ref }}\n"))
        self.assertFalse(self.high(PRT + CHECKOUT + "          ref: main\n            # was ${{ github.head_ref }}\n"))
        self.assertTrue(self.high(PRT + CHECKOUT + "          ref: ${{ github.head_ref }} # the PR\n"))
        self.assertTrue(self.high(PRT + CHECKOUT + "          ref: \"x #${{ github.head_ref }}\"\n"))


class UrlUserinfoTests(unittest.TestCase):
    ORDINARY = ("http://localhost:5173/@vite/client", "https://unpkg.com/react@18.3.1/umd/x.js",
                "https://api.example.com:8443/users/alice@example.com/profile",
                '<a href="https://twitter.com">@acme</a>', "x = a //b@c",
                '<link rel="stylesheet" href="https://unpkg.com/sakura.css@1.3.1/css/sakura.css">',
                "self.selenium.find_element(By.XPATH, '//input[@value=\"Log in\"]').click()",
                ".get('//todo@txt')", "https://pkg.go.dev/net@v0.17.0")
    LEAKS = ("postgres://app:5432/SuperSecret@db/app", "https://svc:2024/Qx9+abc=@db.internal/x",
             "https://user:/s3cr3t@host/x", "redis://default:1234#Abcd@cache:6379",
             "redis://default:1234#Abcd@10.0.0.5:6379", 'url = "https://user:p"ssw0rd@host/x"',
             'u = "//user:pw-secret@host/path"', "next=https%3A%2F%2Fuser%3Apw-secret%40host%2Fx")

    def test_ordinary_at_signs_are_kept(self):
        for text in self.ORDINARY:
            with self.subTest(text=text):
                self.assertFalse(url_redaction.has_url_credentials(text))
                self.assertEqual(url_redaction.redact_urls(text), text)
                self.assertFalse(render.secret_in_source("src/app.py", text))

    def test_hidden_userinfo_is_still_found(self):
        for text in self.LEAKS:
            with self.subTest(text=text):
                self.assertTrue(url_redaction.has_url_credentials(text))
                self.assertTrue(render.secret_in_source("src/app.py", text))


class OrderWordingTests(unittest.TestCase):
    def test_message_and_skill_name_the_line_tie_break(self):
        rank = contract_check.SEVERITY_RANK["High"]
        self.assertEqual(contract_check.order_key({"severity": "High", "location": "a.py:9-12"}), (rank, "a.py", 9))
        source = (SCRIPTS / "contract_check.py").read_text(encoding="utf-8")
        self.assertIn("severity order (High first), then path and line", source)
        self.assertIn("severity order (then path and line;", (SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
