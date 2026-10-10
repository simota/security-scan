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


class CodexRound8Tests(Base):
    def test_taint_flows_through_a_chain_of_local_callers(self):
        middle = CALLEE + "    steps:\n      - uses: ./.github/actions/co\n        with:\n          sha: ${{ inputs.ref }}\n"
        files = {W + "a.yml": CALLER, W + "b.yml": middle, ".github/actions/co/action.yml": COMPOSITE
                 + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"}
        self.assertTrue(any("action.yml" in x for x in self.high(files)))

    def test_reassigned_shell_variable_is_no_longer_tainted(self):
        run = PRT + "    steps:\n      - run: |\n          SHA=${{ github.event.pull_request.head.sha }}\n"
        self.assertFalse(self.high(run + "          SHA=main\n          git checkout \"$SHA\"\n"))
        self.assertTrue(self.high(run + "          git checkout \"$SHA\"\n          SHA=main\n"))

    def test_shell_assignment_shadows_inherited_env(self):
        step = ("      - run: |\n          SHA=main\n          git checkout \"$SHA\"\n"
                "        env:\n          SHA: ${{ github.event.pull_request.head.sha }}\n")
        self.assertFalse(self.high(PRT + "    steps:\n" + step))

    def test_assignment_and_checkout_on_one_row(self):
        for step in ('      - run: SHA=${{ github.event.pull_request.head.sha }}; git checkout "$SHA"\n',
                     '      - run: |\n          SHA=${{ github.event.pull_request.head.sha }} && git checkout "$SHA"\n'):
            with self.subTest(step=step):
                self.assertTrue(self.high(PRT + "    steps:\n" + step))
        self.assertTrue(self.high(PRT + "    steps:\n      - run: git checkout ${{ github.head_ref || 'main' }}\n"))


class ServiceUrlPathTests(unittest.TestCase):
    def test_at_sign_in_a_service_url_path_is_kept(self):
        for url in ("ftp://files.example.com/pub/icon@2x.png", "sftp://files.example.com/home/alice@example.com",
                    "postgres://db.example.com/analytics/v@2"):
            with self.subTest(url=url):
                self.assertFalse(has_url_credentials(url))
        self.assertTrue(has_url_credentials("postgres://app:1234/PW/SECRET@h.com/x"))


class UrlUserinfoTests(unittest.TestCase):
    def test_service_url_passwords_with_delimiters_are_redacted(self):
        # A dotted name with a numeric port is host:port (see CodexRound8bScanTests), so these
        # passwords-with-delimiters use a single-label user name.
        for text, secret in (("postgres://app:1234/PW/SECRET@h.com/x", "SECRET"),
                             ("postgres://app:1234/PWSECRET?a(@h.com", "PWSECRET"),
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


class CodexRound8bScanTests(Base):
    def test_pr_number_in_a_branch_name_with_pull_is_not_the_head(self):
        for value in ("feature/pull/${{ github.event.number }}/docs", "docs/pr/${{ github.event.number }}"):
            with self.subTest(value=value):
                self.assertFalse(self.high(PRT + "    steps:\n" + CHECKOUT + "          ref: " + value + "\n"))
                self.assertFalse(self.high(PRT + "    steps:\n      - run: git checkout " + value + "\n"))
        self.assertTrue(self.high(PRT + "    steps:\n" + CHECKOUT + "          ref: refs/pull/${{ github.event.number }}/head\n"))

    def test_conditional_shell_assignment_does_not_clear_taint(self):
        head = "          SHA=${{ github.event.pull_request.head.sha }}\n"
        for script in (head + '          false && SHA=main; git checkout "$SHA"\n',
                       head + '          true || SHA=main\n          git checkout "$SHA"\n',
                       head + '          if [ -z "$X" ]; then SHA=main; fi\n          git checkout "$SHA"\n',
                       head + '          if [ -z "$X" ]; then\n            SHA=main\n          fi\n          git checkout "$SHA"\n',
                       head + '          for b in a; do\n            SHA=main\n          done\n          git checkout "$SHA"\n',
                       '          if [ -n "$X" ]; then SHA=${{ github.head_ref }}; fi\n          git checkout "$SHA"\n'):
            with self.subTest(script=script):
                self.assertTrue(self.high(PRT + "    steps:\n      - run: |\n" + script))
        # After the block closes, an unconditional assignment still replaces the value.
        self.assertFalse(self.high(PRT + "    steps:\n      - run: |\n" + head
                                   + '          if [ -z "$X" ]; then echo; fi\n          SHA=main\n          git checkout "$SHA"\n'))

    def test_service_url_with_host_port_and_at_in_path_is_kept(self):
        for url in ("postgres://db.example.com:5432/analytics@2024", "sftp://files.example.com:22/home/alice@example.com",
                    "postgres://localhost:5432/db/v@2", "mysql://10.0.0.5:3306/a/b@c"):
            with self.subTest(url=url):
                self.assertFalse(has_url_credentials(url))
                self.assertEqual(redact_urls(url), url)
        for url in ("postgres://app:5432/Secret@db/app", "redis://default:1234#Abcd@10.0.0.5:6379",
                    "postgres://u:pw@db.example.com:5432/x@y"):
            with self.subTest(url=url):
                self.assertTrue(has_url_credentials(url))


class CodexRound8cScanTests(Base):
    def test_every_leading_shell_assignment_is_read(self):
        head = "${{ github.event.pull_request.head.sha }}"
        for row in ('SAFE=main SHA=' + head + '; git checkout "$SHA"', 'export A=1 SHA=' + head + '; git checkout "$SHA"',
                    'SAFE="a b" SHA="' + head + '" && git checkout "$SHA"', 'declare -x A=1 SHA=' + head + '\n          git checkout "$SHA"'):
            with self.subTest(row=row):
                self.assertTrue(self.high(PRT + "    steps:\n      - run: |\n          " + row + "\n"))
        # A later unconditional assignment still replaces the value; a prefix `A=x cmd` only raises it.
        self.assertFalse(self.high(PRT + "    steps:\n      - run: |\n          SHA=" + head + "\n"
                                   "          A=1 SHA=main\n          git checkout \"$SHA\"\n"))
        self.assertTrue(self.high(PRT + "    steps:\n      - run: |\n          SHA=" + head + "\n"
                                  "          SHA=main env\n          git checkout \"$SHA\"\n"))
        started = time.monotonic()
        deps_scan.shell_assignments("A=" + "\"$(${{ x " * 20000)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_caller_env_passed_to_a_local_callee_is_tainted(self):
        env = "env:\n  SHA: ${{ github.event.pull_request.head.sha }}\n"
        callee_run = "    steps:\n      - run: git checkout ${{ inputs.ref }}\n"
        step = "        with:\n          sha: ${{ env.SHA }}\n"
        for files in ({W + "a.yml": env + CALLER.replace("${{ github.event.pull_request.head.sha }}", "${{ env.SHA }}"),
                       W + "b.yml": CALLEE + callee_run},
                      {W + "a.yml": PRT + "    env:\n      SHA: ${{ github.event.pull_request.head.sha }}\n    steps:\n"
                       "      - uses: ./.github/actions/co\n" + step,
                       ".github/actions/co/action.yml": COMPOSITE + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"},
                      {W + "a.yml": PRT + "    steps:\n      - uses: ./.github/actions/co\n        env:\n"
                       "          SHA: ${{ github.head_ref }}\n" + step,
                       ".github/actions/co/action.yml": COMPOSITE + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"}):
            with self.subTest(files=files):
                self.assertTrue(self.high(files))
                shutil.rmtree(self.tmp)
                self.tmp.mkdir()
        self.assertFalse(self.high({W + "a.yml": PRT + "    env:\n      SHA: main\n    steps:\n"
                                    "      - uses: ./.github/actions/co\n" + step,
                                    ".github/actions/co/action.yml": COMPOSITE + "    - run: git checkout ${{ inputs.sha }}\n"}))
        self.timed("on: pull_request_target\njobs:\n" + "".join(
            "  j%d:\n    env:\n      A: x\n    steps:\n      - uses: ./x\n        with:\n          a: ${{ env.A }}\n" % i
            for i in range(2500)))


class CodexRound8dScanTests(Base):
    def test_assignment_in_an_uncalled_function_does_not_clear_taint(self):
        head = "          SHA=${{ github.event.pull_request.head.sha }}\n"
        for body in ("f() { SHA=main; }\n", "function f {\n            SHA=main\n          }\n",
                     "function f() {\n            if true; then echo; fi\n            SHA=main\n          }\n",
                     "f () {\n            { echo; }\n            SHA=main\n          }\n"):
            with self.subTest(body=body):
                self.assertTrue(self.high(PRT + "    steps:\n      - run: |\n" + head + "          " + body
                                          + '          git checkout "$SHA"\n'))
        # After the function's closing brace an assignment runs again.
        self.assertFalse(self.high(PRT + "    steps:\n      - run: |\n" + head + "          f() { echo; }\n"
                                   '          SHA=main\n          git checkout "$SHA"\n'))
        started = time.monotonic()
        deps_scan.FUNCTION_HEADER.match("function " + "a" * 200000)
        deps_scan.FUNCTION_HEADER.match("a" * 200000 + " (" + " " * 200000)
        self.assertLess(time.monotonic() - started, 1.0)

    def test_forwarded_inputs_keep_each_callers_privilege(self):
        middle = CALLEE + "    steps:\n      - uses: ./.github/actions/co\n        with:\n          sha: ${{ inputs.ref }}\n"
        action = COMPOSITE + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"
        unprivileged = CALLER.replace("on: pull_request_target", "on: pull_request")
        safe = CALLER.replace("${{ github.event.pull_request.head.sha }}", "main")
        files = {W + "a.yml": safe, W + "c.yml": unprivileged, W + "b.yml": middle, ".github/actions/co/action.yml": action}
        self.assertFalse(any("action.yml" in x for x in self.high(files)))
        shutil.rmtree(self.tmp)
        self.tmp.mkdir()
        files[W + "a.yml"] = CALLER
        self.assertTrue(any("action.yml" in x for x in self.high(files)))


class CodexRound8eScanTests(Base):
    HEAD = "${{ github.event.pull_request.head.sha }}"
    ACTION = COMPOSITE + "    - run: git checkout ${{ inputs.sha }}\n      shell: bash\n"

    def fresh(self):
        shutil.rmtree(self.tmp)
        self.tmp.mkdir()

    def not_run(self):
        return [x["reason"] for x in deps_scan.scan(self.tmp, False)["not_run"]]

    def test_subshell_pipeline_and_background_assignments_do_not_clear_taint(self):
        head = "          SHA=" + self.HEAD + "\n"
        for line in ("{ SHA=main; } &", "{ SHA=main; } | cat", "{\n            SHA=main\n          } &",
                     "SHA=main | cat", "SHA=main &", "echo x | SHA=main", "( SHA=main )", "(cd x; SHA=main)",
                     "(\n            SHA=main\n          )"):
            with self.subTest(line=line):
                self.assertTrue(self.high(PRT + "    steps:\n      - run: |\n" + head + "          " + line
                                          + '\n          git checkout "$SHA"\n'))
        for line in ("{ SHA=main; }", "{ echo; } | cat; SHA=main", "echo x | cat; SHA=main",
                     "git log 2>&1 >/dev/null; SHA=main", "(cd x); SHA=main", "X=$(git rev-parse HEAD); SHA=main"):
            with self.subTest(line=line):
                self.assertFalse(self.high(PRT + "    steps:\n      - run: |\n" + head + "          " + line
                                           + '\n          git checkout "$SHA"\n'))
        started = time.monotonic()
        for text in ("|" * 200000, "&" * 200000, "<|>&" * 50000, "run: |" + " " * 200000 + "x"):
            deps_scan.SHELL_SEP.split(text)
            deps_scan.RUN_KEY.sub("", text)
        self.assertLess(time.monotonic() - started, 1.0)
        self.timed(PRT + "    steps:\n      - run: |\n          " + "{ " * 20000 + "x" + "; } |" * 20000 + "\n")

    def test_chained_env_aliases_resolve(self):
        for env in ("    env:\n      SHA: %s\n      REF: ${{ env.SHA }}\n" % self.HEAD,
                    "    env: { SHA: %s, REF: ${{ env.SHA }} }\n" % self.HEAD):
            with self.subTest(env=env):
                self.assertTrue(self.high(PRT + env + "    steps:\n" + CHECKOUT + "          ref: ${{ env.REF }}\n"))
                self.fresh()
                self.assertTrue(self.high({W + "a.yml": PRT + env + "    steps:\n      - uses: ./.github/actions/co\n"
                                           "        with:\n          sha: ${{ env.REF }}\n",
                                           ".github/actions/co/action.yml": self.ACTION}))
                self.fresh()
        workflow = "env:\n  SHA: %s\n" % self.HEAD
        self.assertTrue(self.high(workflow + PRT + "    env:\n      REF: ${{ env.SHA }}\n    steps:\n"
                                  + CHECKOUT + "          ref: ${{ env.REF }}\n"))
        self.fresh()
        cycle = "    env:\n      A: ${{ env.B }}\n      B: ${{ env.A }}\n"
        self.assertFalse(self.high({W + "a.yml": PRT + cycle + "    steps:\n" + CHECKOUT + "          ref: ${{ env.A }}\n"
                                    "      - uses: ./.github/actions/co\n        with:\n          sha: ${{ env.A }}\n",
                                    ".github/actions/co/action.yml": self.ACTION}))

    def test_a_long_local_call_chain_reaches_the_last_callee(self):
        files = {W + "a.yml": PRT + "    steps:\n      - uses: ./.github/actions/c1\n        with:\n"
                 "          sha: %s\n" % self.HEAD, ".github/actions/c10/action.yml": self.ACTION}
        for i in range(1, 10):
            files[".github/actions/c%d/action.yml" % i] = (COMPOSITE + "    - uses: ./.github/actions/c%d\n"
                                                           "      with:\n        sha: ${{ inputs.sha }}\n" % (i + 1))
        self.assertTrue(any("c10/action.yml" in x for x in self.high(files)))

    def test_too_many_call_paths_are_not_merged_but_reported(self):
        step = "    steps:\n      - uses: ./.github/actions/m\n        with:\n          sha: %s\n"
        files = {W + "w%02d.yml" % i: PRT + step % ("main-%d" % i) for i in range(70)}
        files[W + "pr.yml"] = PRT.replace("pull_request_target", "pull_request") + step % self.HEAD
        files[".github/actions/m/action.yml"] = (COMPOSITE + "    - uses: ./.github/actions/x\n"
                                                 "      with:\n        sha: ${{ inputs.sha }}\n")
        files[".github/actions/x/action.yml"] = self.ACTION
        self.assertFalse(any("x/action.yml" in x for x in self.high(files)))
        self.assertTrue(any("x/action.yml: too many local call paths" in x for x in self.not_run()))


if __name__ == "__main__":
    unittest.main()
