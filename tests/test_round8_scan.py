"""Round 8 regressions: PR-number taint, caller inputs, shell variables, linear parsing, URL userinfo."""
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills/security-scan/scripts"))
import deps_scan  # noqa: E402
from url_redaction import has_url_credentials, redact_urls  # noqa: E402

SHA = "0" * 40
W = ".github/workflows/"
PRT = "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n"
COMMENT = "on: issue_comment\njobs:\n  j:\n    runs-on: x\n"
CHECKOUT = "      - uses: actions/checkout@" + SHA + "\n        with:\n"
CALLER = PRT.replace("    runs-on: x\n", "    uses: ./.github/workflows/b.yml\n    with:\n"
                     "      ref: ${{ github.event.pull_request.head.sha }}\n")
CALLEE = "on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\njobs:\n  b:\n    runs-on: x\n"
STEP_CALLER = PRT + "    steps:\n      - uses: ./.github/actions/co\n        with:\n          sha: ${{ github.event.pull_request.head.sha }}\n"
COMPOSITE = "name: co\ninputs:\n  sha:\n    required: true\nruns:\n  using: composite\n  steps:\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def high(self, files):
        for name, body in ({W + "a.yml": files} if isinstance(files, str) else files).items():
            path = self.tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(body, encoding="utf-8")
        return [f["location"] for f in deps_scan.scan(self.tmp, False)["findings"] if f["severity"] == "High"]

    def timed(self, files):
        started = time.monotonic()
        self.high(files)
        self.assertLess(time.monotonic() - started, 2.0)


class PullNumberTaintTests(Base):
    def test_pr_number_in_env_reaches_a_pull_ref(self):
        for body in (PRT + "    env:\n      PR: ${{ github.event.pull_request.number }}\n    steps:\n"
                     + CHECKOUT + "          ref: refs/pull/${{ env.PR }}/merge\n",
                     COMMENT + "    env:\n      PR: ${{ github.event.issue.number }}\n    steps:\n"
                     + CHECKOUT + "          ref: refs/pull/${{ env.PR }}/head\n",
                     COMMENT + "    steps:\n      - run: echo \"PR=${{ github.event.issue.number }}\" >> $GITHUB_ENV\n"
                     + CHECKOUT + "          ref: refs/pull/${{ env.PR }}/head\n",
                     PRT + "    steps:\n      - run: |\n"
                     "          git fetch origin '+refs/pull/*/head:refs/remotes/origin/pr/*'\n"
                     "          git checkout origin/pr/${{ github.event.number }}\n"):
            with self.subTest(body=body):
                self.assertTrue(self.high(body))

    def test_pr_number_outside_a_ref_is_not_the_head(self):
        for body in (COMMENT + "    steps:\n      - run: git checkout -b backport-${{ github.event.issue.number }} origin/release\n",
                     PRT + "    steps:\n      - run: echo \"PR=${{ github.event.number }}\" >> $GITHUB_ENV\n"
                     "      - run: git checkout -b \"backport-$PR\" origin/release\n",
                     PRT + "    env:\n      PR: ${{ github.event.number }}\n    steps:\n"
                     + CHECKOUT + "          ref: release-${{ env.PR }}\n"):
            with self.subTest(body=body):
                self.assertFalse(self.high(body))


class CallerInputTests(Base):
    def test_head_passed_as_input_reaches_callee_run_and_env(self):
        for files in ({W + "a.yml": CALLER, W + "b.yml": CALLEE + "    steps:\n"
                       "      - run: git fetch origin ${{ inputs.ref }} && git checkout FETCH_HEAD\n"},
                      {W + "a.yml": CALLER, W + "b.yml": CALLEE + "    env:\n      REF: ${{ inputs.ref }}\n    steps:\n"
                       + CHECKOUT + "          ref: ${{ env.REF }}\n"},
                      {W + "a.yml": STEP_CALLER, ".github/actions/co/action.yml": COMPOSITE
                       + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"},
                      {W + "a.yml": STEP_CALLER, ".github/actions/co/action.yml": COMPOSITE
                       + "    - run: git checkout \"$SHA\"\n      shell: bash\n      env:\n        SHA: ${{ inputs.sha }}\n"}):
            with self.subTest(files=files):
                self.assertTrue(any("b.yml" in x or "action.yml" in x for x in self.high(files)))

    def test_unprivileged_caller_input_is_not_flagged(self):
        self.assertFalse(self.high({W + "a.yml": CALLER.replace("pull_request_target", "push"),
                                    W + "b.yml": CALLEE + "    steps:\n      - run: git checkout ${{ inputs.ref }}\n"}))


class RunStepTests(Base):
    def test_shell_variables_continuations_quoted_and_flow_env_and_brackets(self):
        for steps in ("      - run: |\n          SHA=${{ github.event.pull_request.head.sha }}\n          git checkout \"$SHA\"\n",
                      "      - run: |\n          export REF=\"${{ github.head_ref }}\"\n          git fetch origin \"$REF\"\n"
                      "          git checkout FETCH_HEAD\n",
                      "      - run: |\n          git fetch origin \\\n            pull/${{ github.event.number }}/head:pr\n"
                      "          git checkout pr\n",
                      "      - run: git fetch origin \"$SHA\" && git checkout FETCH_HEAD\n        env:\n"
                      "          \"SHA\": ${{ github.event.pull_request.head.sha }}\n",
                      "      - run: git fetch origin \"$SHA\" && git checkout FETCH_HEAD\n"
                      "        env: { SHA: \"${{ github.event.pull_request.head.sha }}\" }\n",
                      "      - run: |\n          git fetch origin +refs/pull/${{ github.event.number }}/head:refs/remotes/origin/pr-head\n"
                      "          git checkout origin/pr-head\n",
                      CHECKOUT + "          ref: ${{ github.event['pull_request']['head']['sha'] }}\n",
                      "      - run: git checkout ${{ github['head_ref'] }}\n"):
            with self.subTest(steps=steps):
                self.assertTrue(self.high(PRT + "    steps:\n" + steps))

    def test_safe_shell_values_are_not_flagged(self):
        self.assertFalse(self.high(PRT + "    steps:\n      - run: |\n          SHA=main\n          git checkout \"$SHA\"\n"))

    def test_boolean_function_result_is_not_injection(self):
        def medium(run):
            self.high(PRT + "    steps:\n      - run: " + run + "\n")
            return [f for f in deps_scan.scan(self.tmp, False)["findings"] if f["title"].startswith("untrusted event")]
        self.assertFalse(medium("echo ${{ contains(github.event.pull_request.title, 'WIP') }}"))
        self.assertTrue(medium("echo ${{ contains(github.event.pull_request.title, 'x') && github.event.pull_request.title }}"))


class LinearParsingTests(Base):
    def test_multi_line_flow_with_is_linear(self):
        self.timed(PRT + "    steps:\n      - uses: actions/checkout@v4\n        with: {\n" + "          a: [,\n" * 20000)

    def test_repeated_local_uses_resolve_once(self):
        (self.tmp / "x").mkdir()
        (self.tmp / "x/action.yml").write_text("runs:\n  using: composite\n  steps: []\n", encoding="utf-8")
        self.timed("on: pull_request_target\njobs:\n  b:\n    steps:\n" + "      - uses: ./x\n" * 12000)


class UrlUserinfoTests(unittest.TestCase):
    def test_service_url_passwords_with_delimiters_are_redacted(self):
        for text, secret in (("postgres://app.svc:1234/PW/SECRET@h.com/x", "SECRET"),
                             ("postgres://app.svc:1234/PWSECRET?a(@h.com", "PWSECRET"),
                             ('https://user:p\\"ss@host', "ss@host")):
            with self.subTest(text=text):
                self.assertTrue(has_url_credentials(text))
                self.assertEqual(redact_urls(text), "[redacted URL]")
                self.assertNotIn(secret, redact_urls(text))

    def test_service_paths_and_nested_urls_are_kept(self):
        for text in ("http://my-service:8080/v1/accounts/john@example.com", "http://web:3000/images/icon@2x.png",
                     "http://minio:9000/bucket/file@2x.png", "https://web.archive.org/web/2020/https://example.com/"):
            with self.subTest(text=text):
                self.assertFalse(has_url_credentials(text))
                self.assertEqual(redact_urls(text), text)
        self.assertEqual(redact_urls("https://example.com/redirect?to=https://other.com/"), "https://example.com/redirect")
        for text in ("postgres://app:5432/Secret@db", "https://svc:2024/Qx9+abc=@db.internal/x",
                     "redis://default:1234#Abcd@cache:6379"):
            with self.subTest(text=text):
                self.assertTrue(has_url_credentials(text))
                self.assertEqual(redact_urls(text), "[redacted URL]")


if __name__ == "__main__":
    unittest.main()
