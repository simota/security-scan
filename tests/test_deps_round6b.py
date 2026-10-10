"""Round-6 (deps) regressions: pwn-request and injection coverage, crashes, quadratic paths, false positives."""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load_script(name):
    path = Path(__file__).resolve().parents[1] / "skills/security-scan/scripts" / (name + ".py")
    spec = importlib.util.spec_from_file_location("round6b_" + name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


HEAD_SHA = "${{ github.event.pull_request.head.sha }}"
PRT = "on: pull_request_target\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
CHECKOUT = "      - uses: actions/checkout@v4\n"


class DepsRound6bTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deps = load_script("deps_scan")

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="security-scan-deps-r6b-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode("utf-8"))
        return path

    def scan(self):
        return self.deps.scan(self.root, False)

    def titles(self, needle=""):
        return [f["location"] + " " + f["title"] for f in self.scan()["findings"] if needle in f["title"]]

    def reasons(self):
        return [n["reason"] for n in self.scan()["not_run"]]

    def workflow(self, body, name="w.yml"):
        return self.write(".github/workflows/" + name, body)

    def assertPwn(self, body, line=None, name="w.yml"):
        self.workflow(body, name)
        hits = [t for t in self.titles("checks out the pull request's code") if t.startswith(f".github/workflows/{name}:")]
        self.assertEqual(len(hits), 1, hits)
        if line is not None:
            self.assertTrue(hits[0].startswith(f".github/workflows/{name}:{line} "), hits)
        return hits[0]

    def timed(self, limit=2.0):
        start = time.perf_counter()
        result = self.scan()
        self.assertLess(time.perf_counter() - start, limit)
        return result

    # ---- A1: issue_comment is privileged; refs/pull/<issue number> is the PR head ----

    def test_issue_comment_checkout_of_pull_ref(self):
        hit = self.assertPwn("on:\n  issue_comment:\n    types: [created]\njobs:\n  t:\n    runs-on: x\n    steps:\n"
                             + CHECKOUT + "        with:\n          ref: refs/pull/${{ github.event.issue.number }}/head\n"
                             "      - run: npm ci && npm test\n", 10)
        self.assertIn("issue_comment workflow checks out", hit)

    def test_issue_comment_gh_pr_checkout(self):
        self.assertPwn("on: issue_comment\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: gh pr checkout "
                       "${{ github.event.issue.number }}\n", 6)

    def test_issue_comment_git_fetch_of_issue_number(self):
        self.assertPwn("on: issue_comment\njobs:\n  t:\n    runs-on: x\n    steps:\n      - run: |\n"
                       "          git fetch origin pull/${{ github.event.issue.number }}/head\n"
                       "          git checkout FETCH_HEAD\n", 8)

    # ---- A2: checkout `with:` forms ----

    def test_checkout_ref_forms(self):
        cases = {
            "format": "        with:\n          ref: ${{ format('refs/pull/{0}/merge', github.event.pull_request.number) }}\n",
            "paren": "        with:\n          ref: ${{ (github.event.pull_request.head.sha) }}\n",
            "flow": '        with: { ref: "' + HEAD_SHA + '" }\n',
            "flow_bare": "        with: {fetch-depth: 0, ref: " + HEAD_SHA + "}\n",
            "flow_multiline": "        with: {\n          ref: " + HEAD_SHA + "\n        }\n",
            "quoted_key": '        with:\n          "ref": ' + HEAD_SHA + "\n",
            "block": "        with:\n          ref: >-\n            " + HEAD_SHA + "\n",
            "plain_next_line": "        with:\n          ref:\n            " + HEAD_SHA + "\n",
            "head_commit": "        with:\n          ref: ${{ github.event.workflow_run.head_commit.id }}\n",
        }
        for name, step in cases.items():
            with self.subTest(name):
                self.assertPwn(PRT + CHECKOUT + step + "      - run: make\n", name=name + ".yml")

    # ---- A3: clones and decoded double-quoted run scalars ----

    def test_run_step_clones_of_the_head(self):
        cases = {
            "git_clone": "      - run: git clone https://github.com/${{ github.event.pull_request.head.repo.full_name }} pr\n",
            "git_clone_branch": '      - run: git clone --branch "${{ github.head_ref }}" https://github.com/x/y pr\n',
            "gh_repo_clone": "      - run: gh repo clone ${{ github.event.pull_request.head.repo.full_name }}\n",
            "dq_newline": '      - run: "git fetch origin pull/${{ github.event.pull_request.number }}/head:pr\\ngit checkout pr"\n',
            "two_git_one_segment": '      - run: "git fetch origin ' + HEAD_SHA + '\\n  git switch --detach FETCH_HEAD"\n',
        }
        for name, step in cases.items():
            with self.subTest(name):
                self.assertPwn(PRT + step, 6, name=name + ".yml")

    def test_git_commands_reads_every_git_in_a_segment(self):
        self.assertEqual(self.deps.git_commands("git fetch a git checkout b"),
                         [("fetch", ["a"]), ("checkout", ["b"])])
        self.assertEqual(self.deps.git_commands("git -C x -c a=b --no-pager switch y"), [("switch", ["y"])])

    # ---- A4: indirection through $GITHUB_ENV, $GITHUB_OUTPUT, inputs and other sources ----

    def test_github_env_and_output_carry_the_head(self):
        self.assertPwn(PRT + '      - run: echo "SHA=' + HEAD_SHA + '" >> $GITHUB_ENV\n' + CHECKOUT
                       + "        with:\n          ref: ${{ env.SHA }}\n", 9, name="env.yml")
        self.assertPwn(PRT + '      - id: pr\n        run: echo "sha=' + HEAD_SHA + '" >> "$GITHUB_OUTPUT"\n' + CHECKOUT
                       + "        with:\n          ref: ${{ steps.pr.outputs.sha }}\n", 10, name="out.yml")
        self.assertPwn(PRT + '      - run: echo "SHA=' + HEAD_SHA + '" >> $GITHUB_ENV\n'
                       "      - run: git checkout $SHA\n", 7, name="shell.yml")

    def test_unresolved_checkout_sources_are_incomplete(self):
        self.workflow(PRT + "      - id: pr\n        uses: actions/github-script@v7\n" + CHECKOUT
                      + "        with:\n          ref: ${{ steps.pr.outputs.sha }}\n" + CHECKOUT
                      + "        with:\n          ref: ${{ needs.prep.outputs.sha }}\n" + CHECKOUT
                      + "        with:\n          ref: ${{ env.UNSET }}\n")
        self.assertEqual(self.titles("checks out"), [])
        reasons = self.reasons()
        for kind in ("a step output", "a job output", "an environment variable"):
            self.assertIn(f".github/workflows/w.yml: checkout ref from {kind} requires manual review", reasons)

    def test_safe_env_checkout_is_not_incomplete(self):
        self.workflow(PRT.replace("    steps:", "    env:\n      BASE: main\n    steps:") + CHECKOUT
                      + "        with:\n          ref: ${{ env.BASE }}\n")
        self.assertFalse([r for r in self.reasons() if "checkout ref" in r])

    def test_reusable_workflow_and_composite_inputs_from_privileged_callers(self):
        self.workflow("on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n"
                      "    with:\n      ref: " + HEAD_SHA + "\n", "caller.yml")
        self.workflow("on:\n  workflow_call:\n    inputs:\n      ref:\n        type: string\njobs:\n  b:\n"
                      "    runs-on: x\n    steps:\n" + CHECKOUT + "        with:\n          ref: ${{ inputs.ref }}\n"
                      "      - run: npm ci\n", "build.yml")
        self.write(".github/actions/co/action.yml", "runs:\n  using: composite\n  steps:\n"
                   "    - uses: actions/checkout@v4\n      with:\n        ref: ${{ inputs.ref }}\n")
        self.workflow(PRT + "      - uses: ./.github/actions/co\n        with: {ref: " + HEAD_SHA + "}\n", "step.yml")
        hits = self.titles("checks out the pull request's code")
        self.assertIn(".github/workflows/build.yml:12 pull_request_target workflow checks out the pull request's code", hits)
        self.assertIn(".github/actions/co/action.yml:6 pull_request_target workflow checks out the pull request's code", hits)

    def test_callee_input_from_safe_caller_is_clean(self):
        self.workflow("on: pull_request_target\njobs:\n  call:\n    uses: ./.github/workflows/build.yml\n"
                      "    with:\n      ref: main\n", "caller.yml")
        self.workflow("on: workflow_call\njobs:\n  b:\n    runs-on: x\n    steps:\n" + CHECKOUT
                      + "        with:\n          ref: ${{ inputs.ref }}\n", "build.yml")
        self.assertEqual(self.titles("checks out"), [])

    # ---- A5: BOM and indentationless trigger lists ----

    def test_bom_and_indentationless_trigger_list(self):
        step = CHECKOUT + "        with:\n          ref: " + HEAD_SHA + "\n"
        self.assertPwn("\ufeff" + PRT + step, 8, name="bom.yml")
        self.assertPwn(PRT.replace("on: pull_request_target", "on:\n- push\n- pull_request_target") + step, 10,
                       name="list.yml")

    # ---- A6: injection through env maps, composite inputs and display_title ----

    def test_env_context_indirection_is_injection(self):
        self.workflow("on: issues\njobs:\n  b:\n    runs-on: x\n    env:\n      TITLE: ${{ github.event.issue.title }}\n"
                      "    steps:\n      - run: echo \"${{ env.TITLE }}\"\n      - run: echo \"${{ env.SAFE }}\"\n"
                      "        env:\n          SAFE: fixed\n          TITLE: x\n")
        self.assertEqual(self.titles("untrusted event text"),
                         [".github/workflows/w.yml:8 untrusted event text interpolated into a workflow"])

    def test_step_env_shadows_tainted_job_env(self):
        self.workflow("on: issues\njobs:\n  b:\n    runs-on: x\n    env:\n      TITLE: ${{ github.event.issue.title }}\n"
                      "    steps:\n      - run: echo \"${{ env.TITLE }}\"\n        env:\n          TITLE: fixed\n")
        self.assertEqual(self.titles("untrusted event text"), [])

    def test_composite_input_fed_untrusted_text(self):
        self.write("action.yml", 'inputs:\n  title: {}\n  flag:\n    type: boolean\nruns:\n  using: composite\n  steps:\n'
                   '    - run: echo "${{ inputs.title }}" "${{ inputs.other }}"\n      shell: bash\n')
        self.workflow("on: issues\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: ./\n        with:\n"
                      "          title: ${{ github.event.issue.title }}\n          other: fixed\n")
        self.assertEqual(self.titles("untrusted event text"), ["action.yml:8 untrusted event text interpolated into a workflow"])

    def test_boolean_reusable_input_is_not_text(self):
        self.workflow("on: pull_request\njobs:\n  call:\n    uses: ./.github/workflows/c.yml\n    with:\n"
                      "      all: ${{ contains(github.event.pull_request.labels.*.name, 'x') }}\n", "caller.yml")
        self.workflow("on:\n  workflow_call:\n    inputs:\n      all:\n        type: boolean\njobs:\n  b:\n    runs-on: x\n"
                      "    steps:\n      - run: echo ${{ inputs.all }}\n", "c.yml")
        self.assertEqual(self.titles("untrusted event text"), [])

    def test_display_title_is_untrusted(self):
        self.workflow("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n"
                      "      - run: echo \"${{ github.event.workflow_run.display_title }}\"\n")
        self.assertEqual(len(self.titles("untrusted event text")), 1)

    # ---- A7: self-hosted forms, artifact downloads, secrets: inherit by job ----

    def test_self_hosted_block_list_and_labels(self):
        for name, runs_on in (("list", "    runs-on:\n      - self-hosted\n      - linux\n"),
                              ("labels", "    runs-on:\n      group: g\n      labels: [self-hosted]\n")):
            with self.subTest(name):
                self.workflow("on: pull_request_target\njobs:\n  a:\n" + runs_on + "    steps:\n      - run: echo\n",
                              name + ".yml")
                self.assertEqual(self.titles("self-hosted"),
                                 [f".github/workflows/{name}.yml:4 pull_request_target job runs on a self-hosted runner"])
                os.unlink(self.root / ".github/workflows" / (name + ".yml"))

    def test_workflow_run_artifact_downloads_by_cli_and_script(self):
        on = "on:\n  workflow_run:\n    workflows: [ci]\n    types: [completed]\njobs:\n  a:\n    runs-on: x\n    steps:\n"
        self.workflow(on + "      - run: gh run download ${{ github.event.workflow_run.id }} -n pr\n", "cli.yml")
        self.workflow(on + "      - uses: actions/github-script@v7\n        with:\n          script: |\n"
                      "            await github.rest.actions.downloadArtifact({artifact_id: 1, archive_format: 'zip'})\n",
                      "script.yml")
        self.assertEqual(sorted(self.titles("downloads artifacts")), [
            ".github/workflows/cli.yml:9 workflow_run workflow downloads artifacts from the triggering run",
            ".github/workflows/script.yml:9 workflow_run workflow downloads artifacts from the triggering run"])

    def test_secrets_inherit_is_matched_per_job(self):
        ext = "org/r/.github/workflows/x.yml@" + "0" * 40
        self.workflow("on: push\njobs:\n  a:\n    secrets: inherit\n    uses: " + ext + "\n    with:\n"
                      + "".join(f"      k{i}: {i}\n" for i in range(9)) + "  b:\n    uses: " + ext + "\n"
                      "  c:\n    uses: ./.github/workflows/local.yml\n    secrets: inherit\n")
        self.assertEqual(self.titles("every secret"),
                         [".github/workflows/w.yml:5 every secret is passed to external reusable workflow " + ext])

    # ---- B: crashes ----

    def test_nul_in_npm_local_spec(self):
        self.write("package.json", '{"dependencies":{"a":"./x\\u0000y","b":"file:x\\u0000y"}}')
        self.write("package-lock.json", "{}")
        self.scan()  # must not raise ValueError from os.path.realpath

    def test_deep_json_in_npm_audit_inputs(self):
        deep = "[" * 100000 + "]" * 100000
        c = self.deps.Collector(self.root)
        lock = self.write("package-lock.json", deep)
        self.deps.audit_npm(c, self.root, lock)
        self.assertIn("could not validate single-project audit input", str(c.not_run))
        os.unlink(lock)
        lock = self.write("package-lock.json", '{"lockfileVersion":3,"packages":{}}')
        self.write("package.json", deep)
        c = self.deps.Collector(self.root)
        self.deps.audit_npm(c, self.root, lock)
        self.assertIn("could not validate single-project audit input", str(c.not_run))

    def test_deep_json_in_composer_audit_input(self):
        lock = self.write("composer.lock", "[" * 100000 + "]" * 100000)
        c = self.deps.Collector(self.root)
        self.assertIsNone(self.deps.isolated_composer_audit(c, self.root, lock, "composer"))
        self.assertIn("could not prepare isolated audit input", str(c.not_run))

    def test_run_decodes_invalid_utf8_output(self):
        code, out, _ = self.deps.run([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'ok\\xff')"], self.root)
        self.assertEqual((code, out), (0, "ok\ufffd"))

    def test_into_rejects_malformed_findings_shapes(self):
        for name, data in (("null", '{"findings": null}'), ("strings", '{"findings": ["x"]}'),
                           ("limitations", '{"findings": [], "limitations": null}'),
                           ("validation", '{"findings": [{"id": "D-001", "validation": "x"}]}'),
                           ("deep", '{"findings": ' + "[" * 100000 + "]" * 100000 + "}")):
            with self.subTest(name):
                report, repo = self.write("findings.json", data), self.root / "repo"
                repo.mkdir(exist_ok=True)
                with patch.object(sys, "stderr", io.StringIO()):
                    code = self.deps.main([str(repo), "--into", str(report)])
                self.assertEqual(code, 0 if name == "validation" else 2)

    # ---- C: quadratic inputs (reviewer sizes) ----

    def test_gradle_unterminated_escaped_strings_are_linear(self):
        self.write("build.gradle", "repositories {\n'" + "\\'" * 250000 + "\n\"" + '\\"' * 250000 + "\n")
        self.timed()

    def test_many_env_names_and_steps_are_linear(self):
        k = 2000
        self.workflow("on: pull_request_target\nenv:\n" + "".join(f"  E{i}: ${{{{ github.head_ref }}}}\n" for i in range(k))
                      + "jobs:\n  b:\n    steps:\n" + "".join(f"      - run: echo\n        env:\n          E{i}: x\n"
                                                         for i in range(k)))
        self.timed()

    def test_git_option_run_is_linear(self):
        start = time.perf_counter()
        self.deps.git_commands("git " + "-x " * 200000)
        self.assertLess(time.perf_counter() - start, 1.0)
        self.workflow(PRT.replace("    runs-on: ubuntu-latest\n", "") + "      - run: |\n          git "
                      + "-x " * 66666 + "\n")
        self.timed()

    def test_many_head_checkouts_with_later_steps_are_linear(self):
        self.workflow(PRT + "".join(CHECKOUT + "        with:\n          ref: " + HEAD_SHA + f"\n      - run: echo {i}\n"
                                    for i in range(2000)))
        result = self.timed()
        self.assertEqual(len([f for f in result["findings"] if f["severity"] == "High"]), 2000)

    def test_nested_sequence_items_are_linear(self):
        self.workflow("on: pull_request_target\njobs:\n  b:\n    steps:\n"
                      + "".join("  " * i + "- run: x\n" for i in range(2000)))
        self.timed()

    def test_nuget_many_adds_are_linear(self):
        self.write("nuget.config", "<packageSources>\n" + "<add key='a'/>\n" * 66666 + "</packageSources>")
        result = self.timed()
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["location"], "nuget.config:3")

    def test_pnpm_resolution_without_closing_brace_is_linear(self):
        self.write("pnpm-lock.yaml", "resolution: {integrity: x\n" * 200000 + "type: git\n")
        self.timed()

    # ---- D: false positives ----

    def test_npmrc_quoted_env_reference_is_not_literal(self):
        self.write(".npmrc", '//registry.npmjs.org/:_authToken="${NPM_TOKEN}"\n//x/:_authToken=\'${T}\'\n')
        self.assertEqual(self.titles("literal"), [])
        self.write(".npmrc", '//registry.npmjs.org/:_authToken="abc"\n')
        self.assertEqual(len(self.titles("literal")), 1)

    def test_curl_piped_to_checksum_tools_is_not_a_shell(self):
        self.write("Dockerfile", "FROM alpine:3.19\nRUN curl -fsSL https://x/t.sha256 | sha256sum -c\n"
                   "RUN curl -fsSL https://x/t | shasum -a 256\n")
        self.assertEqual(self.titles("piped into a shell"), [])
        self.write("Dockerfile", "FROM alpine:3.19\nRUN curl -fsSL https://x/i | sh -s\n")
        self.assertEqual(len(self.titles("piped into a shell")), 1)

    def test_uses_text_inside_block_scalars_is_not_a_step(self):
        self.workflow("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: |\n          cat > g.yml <<EOF\n"
                      "          uses: foo/bar@v1\n          EOF\n      - uses: real/act@v1\n")
        self.assertEqual(self.titles("mutable tag"),
                         [".github/workflows/w.yml:10 action real/act@v1 is pinned to a mutable tag, not a commit SHA"])

    def test_only_files_directly_in_github_workflows_are_workflows(self):
        body = "on: pull_request_target\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: a/b@v1\n"
        self.write(".github/workflows-archive/old.yml", body)
        self.write(".github/workflows/sub/old.yml", body)
        self.write("vendored/.github/workflows/w.yml", body)
        self.assertEqual(self.titles(), [
            "vendored/.github/workflows/w.yml:1 workflow triggers on pull_request_target",
            "vendored/.github/workflows/w.yml:6 action a/b@v1 is pinned to a mutable tag, not a commit SHA"])

    # ---- E: workspace discovery reasons and BOMs ----

    def test_cargo_workspace_reason_without_tomllib(self):
        self.write("Cargo.toml", '[workspace]\nmembers = ["a"]\n')
        self.write("a/Cargo.toml", '[package]\nname = "a"\n[dependencies]\nx = "1"\n')
        with patch.dict(sys.modules, {"tomllib": None}):
            reasons = self.reasons()
        self.assertIn("a/Cargo.toml: Cargo workspace discovery requires Python 3.11+", reasons)

    def test_bom_in_workspace_package_json(self):
        self.write("package.json", '\ufeff{"workspaces": ["sub"]}')
        self.write("package-lock.json", '{"lockfileVersion": 3, "packages": {}}')
        self.write("sub/package.json", '\ufeff{"dependencies": {"a": "1.0.0"}}')
        result = self.scan()
        self.assertEqual([f["title"] for f in result["findings"] if "lockfile" in f["title"]], [])
        self.assertFalse([n for n in result["not_run"] if n["tool"] == "workspace discovery"])


    def test_run_step_format_expression_is_one_argument(self):
        self.assertPwn(PRT + "      - run: |\n          git fetch origin ${{ format('pull/{0}/head', "
                       "github.event.pull_request.number) }}:pr && git checkout pr\n")

if __name__ == "__main__":
    unittest.main()
