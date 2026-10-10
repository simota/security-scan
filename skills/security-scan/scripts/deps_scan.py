#!/usr/bin/env python3
"""Inventory dependencies and flag supply-chain and known-vulnerability risks.

    python3 deps_scan.py REPO [--audit [--strict]] [--out deps.json] [--into findings.json]

Static checks (always, no network; nothing in the repository is executed):
  - manifests that declare dependencies without a lockfile (npm/Yarn, block-style
    pnpm and Cargo workspace membership resolved), unpinned or floating versions
  - dependencies fetched from git / URLs / paths outside the checkout, lockfiles
    resolving from git, local paths or non-default hosts
  - package sources over plaintext http:// or git://, disabled TLS checks,
    extra indexes and unmapped NuGet sources (dependency confusion), literal
    registry/upload credentials, install-time scripts
  - CI workflows and actions: actions not pinned to a commit SHA, unpinned
    container images, pull_request_target / workflow_run risks (PR head checkout,
    including from run steps and followed through local reusable workflows and
    composite actions, artifact downloads, self-hosted runners), write-all
    permissions, inherited secrets, untrusted event text inside run steps
  - Dockerfile and compose base images without a pinned tag or digest
Inputs that cannot be analysed safely (escaped YAML, unsupported workspace
syntax, links, files over 64 MiB, pruned build/vendor directories holding
manifests) are listed under "not_run", never treated as clean.

--audit additionally runs whichever audit tools are installed
(osv-scanner, composer audit, npm audit, pip-audit) in isolated configurations
and converts their results into findings. Cargo is OSV-only; other unsupported
audits are recorded as incomplete. These need network access to vulnerability
databases; a tool that is missing or fails is listed under "not_run", never
silently skipped. Without --audit, "not_run" names how many pinned packages were
not matched against advisories. --strict exits 3 when anything was not run.

Output: {"inventory": [...], "findings": [...], "not_run": [...]} with findings
in the findings.json shape. --into replaces the D-* findings of an existing
findings.json (keeping prior manual reviews as history) and records not_run
entries as limitations. Standard library only.
"""
import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
# Sibling modules must import under python3 -I / PYTHONSAFEPATH as well.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from url_redaction import redact_urls
from findings import MergeConflict, write_report  # The shared findings.json writer.

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build",
             "target", "__pycache__", ".next", ".nuxt", "bower_components", ".tox"}
# Pruned silently: these never hold first-party manifests.
QUIET_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "bower_components", ".tox"}
MAX_READ = 64 << 20
_OVERSIZED = set()

LOCKS = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb", "npm-shrinkwrap.json"],
    "composer.json": ["composer.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"],
    "Pipfile": ["Pipfile.lock"],
}
ECOSYSTEM = {"package.json": "npm", "composer.json": "composer", "Gemfile": "bundler", "go.mod": "go",
             "Cargo.toml": "cargo", "pyproject.toml": "python", "setup.py": "python",
             "setup.cfg": "python", "Pipfile": "python",
             "requirements.txt": "python", "pom.xml": "maven", "build.gradle": "gradle",
             "build.gradle.kts": "gradle"}

def is_requirements(p, suffixes=("txt", "in")):
    """requirements*.txt, dev-requirements.txt / test_requirements.in, and files under requirements/."""
    p = Path(p)
    ext = p.suffix[1:]
    prose = re.match(r"(readme|license|licence|notice|notes|changelog|authors)\b", p.stem, re.I)
    return ext in suffixes and (re.match(r"^requirements", p.name) is not None
                                or re.search(r"[-_.]requirements$", p.stem) is not None
                                or p.parent.name == "requirements" and not prose)


CAT_DEP = "Dependencies and platform"
CAT_BUILD = "Build and delivery"


def printable(text):
    """Escape control/format characters so a location or title stays one line."""
    return "".join(ch if ch.isprintable() else ascii(ch)[1:-1] for ch in str(text))


def safe_output(value):
    """Sanitize all string fields, including inventory, references and history."""
    if isinstance(value, str):
        # Undecodable file names arrive as surrogate escapes; keep them visible
        # as \udcXX text so the output is always valid UTF-8 JSON.
        return redact_urls(value.encode("utf-8", "backslashreplace").decode("utf-8"))
    if isinstance(value, list):
        return [safe_output(v) for v in value]
    if isinstance(value, dict):
        return {safe_output(k): safe_output(v) for k, v in value.items()}
    return value


def safe_file(path, root=None):
    """Accept regular files only; optionally enforce the checkout boundary.

    Symlinks (including in-checkout links) are deliberately not scan inputs.
    Callers must use an unchanged checkout; this is not a filesystem sandbox.
    """
    path = Path(path)
    try:
        if root is not None:
            root = Path(root).resolve()
            path = Path(os.path.abspath(path))
            parts = path.relative_to(root).parts
            current = root
            for part in parts:
                current /= part
                if current.is_symlink():
                    return False
            path.resolve(strict=True).relative_to(root)
        return not path.is_symlink() and path.is_file()
    except (OSError, ValueError, RuntimeError):
        return False


def audit_input(c, root, path, companions=()):
    """Recheck file operands and optional project config before a subprocess."""
    paths = [Path(path)] + [Path(path).parent / name for name in companions
                            if os.path.lexists(Path(path).parent / name)]
    if all(safe_file(p, root) and p.stat().st_size <= MAX_READ for p in paths):
        return True
    c.not_run.append({"tool": "audit input", "reason": f"{c.rel(path)}: unsafe or missing input/config file"})
    return False


class Collector:
    def __init__(self, root):
        self.root = root
        self.findings = []
        self.inventory = []
        self.not_run = []

    def rel(self, p):
        return os.path.relpath(p, self.root)

    def add(self, severity, title, path, line=None, impact="", fix="", confidence="Confirmed", category=CAT_DEP):
        loc = printable(self.rel(path)) + (f":{line}" if line else "")
        self.findings.append({
            "id": f"D-{len(self.findings) + 1:03d}", "title": redact_urls(printable(title)), "severity": severity,
            "confidence": confidence, "category": category, "location": loc, "actor": "",
            "request": "", "impact": redact_urls(impact), "fix": redact_urls(fix), "status": "Open"})


def walk(root, not_run=None):
    root = Path(root).resolve()

    def skipped(path):
        name = Path(path).name
        try:  # An in-checkout link to a non-input is scanned on its own path.
            inside = Path(path).is_symlink() and Path(path).resolve(strict=True).is_relative_to(root)
        except (OSError, RuntimeError):
            inside = False
        if inside and not scan_input(name):
            return
        if not_run is not None:
            not_run.append({"tool": "file scan", "reason": f"{os.path.relpath(path, root)}: "
                            "skipped symlink, non-regular or unreadable path"})

    for d, dirs, files in os.walk(root, onerror=lambda e: skipped(e.filename or root)):
        dirs.sort()
        files.sort()
        kept = []
        for name in dirs:
            if name in SKIP_DIRS or name.startswith(".cache"):
                if not_run is not None and name not in QUIET_SKIP_DIRS:
                    try:
                        known = sorted(x for x in os.listdir(Path(d) / name) if dependency_file(x))
                    except OSError:
                        known = []
                    if known:
                        not_run.append({"tool": "file scan", "reason": f"{os.path.relpath(Path(d) / name, root)}: "
                                        f"skipped directory contains {known[0]}; scan it separately if first-party"})
                continue
            path = Path(d) / name
            if path.is_symlink():
                skipped(path)
            else:
                kept.append(name)
        dirs[:] = kept
        for name in files:
            path = Path(d) / name
            try:  # Ancestors were already lstat-checked by this walk.
                regular = stat.S_ISREG(os.lstat(path).st_mode)
            except OSError:
                regular = False
            if regular:
                yield path
            else:
                skipped(path)


_LINE_INDEX = {}
_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"  # str.splitlines() separators
_QUOTED = re.compile('(?="([^"' + _BREAKS + ']*)")')


def _line_index(text):
    """Per text: line end offsets and the first offset of every quote-free "X" substring."""
    hit = _LINE_INDEX.get(id(text))
    if hit is None or hit[0] is not text:
        import itertools
        ends = list(itertools.accumulate(len(l) for l in text.splitlines(True)))
        first = {}
        for m in _QUOTED.finditer(text):  # zero-width: every quote, overlaps included
            first.setdefault(m[1], m.start())
        _LINE_INDEX.clear()
        hit = _LINE_INDEX[id(text)] = (text, ends, first)
    return hit


def line_of(text, needle):
    import bisect
    _, ends, first = _line_index(text)
    if not ends:
        return None
    inner = needle[1:-1]
    if len(needle) >= 2 and needle[0] == needle[-1] == '"' and not any(ch in inner for ch in '"' + _BREAKS):
        pos = first.get(inner, -1)
    elif any(ch in needle for ch in _BREAKS):
        return None
    else:
        pos = text.find(needle)
    return None if pos < 0 else bisect.bisect_right(ends, pos) + 1


def read(p):
    if not safe_file(p):
        return ""
    try:
        if os.stat(p).st_size > MAX_READ:
            _OVERSIZED.add(Path(p))
            return ""
        text = p.read_text(encoding="utf-8", errors="replace")
        return text[1:] if text.startswith("\ufeff") else text  # A UTF-8 BOM is not content.
    except OSError:
        return ""


def incomplete(c, tool, path, reason):
    item = {"tool": tool, "reason": f"{c.rel(path)}: {reason}"}
    if item not in c.not_run:
        c.not_run.append(item)


def workspace_pattern(relative, pattern):
    """Match path segments, not fnmatch's slash-crossing '*'."""
    import fnmatch
    from functools import lru_cache
    if (not isinstance(pattern, str) or not pattern or pattern.startswith("/")
            or any(x in pattern for x in ("\\", "{", "}"))
            or ".." in pattern.split("/")):
        raise ValueError("unsupported workspace pattern")
    parts = tuple(x for x in pattern.rstrip("/").split("/") if x != ".")
    path = tuple(relative.split("/"))

    @lru_cache(maxsize=None)
    def match(a, b):
        if not b:
            return not a
        if b[0] == "**":
            return match(a, b[1:]) or bool(a and match(a[1:], b))
        return bool(a and fnmatch.fnmatchcase(a[0], b[0]) and match(a[1:], b[1:]))

    return match(path, parts)


def pnpm_packages(path):
    """Globs of a block-style `packages:` list; None for any other syntax."""
    out, inside = [], False
    for ln in read(path).lstrip("\ufeff").splitlines():
        if re.match(r"packages\s*:\s*(#.*)?$", ln):
            inside = True
        elif inside and ln.strip() and not ln.lstrip().startswith("#"):
            m = re.match(r"""\s*-\s+(['"]?)([^'"#\s]+)\1\s*(#.*)?$""", ln)
            if m:
                out.append(m[2])
            elif ln[:1].isspace() or ln.startswith("-"):
                return None
            else:
                inside = False
        elif not inside and re.match(r"packages\s*:", ln):
            return None
    return out


class Unsupported(ValueError):
    """A known limitation whose own message is the not_run reason."""


def matching_lockfiles(c, manifest):
    """Return safe lockfiles, [] for absent locks, None for unknown ownership.

    Resolve explicit Cargo, npm/Yarn and block-style pnpm memberships without executing tools.
    Unsupported workspace syntax is incomplete, never guessed as covered.
    """
    manifest, root = Path(manifest), Path(c.root).resolve()
    names = LOCKS.get(manifest.name, ())

    def locks(directory):
        return [directory / name for name in names
                if safe_file(directory / name, root)]

    local = locks(manifest.parent)
    if local or manifest.name not in ("Cargo.toml", "package.json"):
        return local

    def parse(path):
        if not safe_file(path, root) or path.stat().st_size > MAX_READ:
            raise ValueError("unsafe workspace manifest")
        if path.name == "package.json":
            value = json.loads(path.read_text(encoding="utf-8").lstrip("\ufeff"))
        else:
            try:
                import tomllib
            except ImportError:
                # Keep Python 3.9/3.10 supported, but do not invent TOML semantics.
                raise Unsupported("Cargo workspace discovery requires Python 3.11+") from None
            value = tomllib.loads(path.read_text(encoding="utf-8").lstrip("\ufeff"))
        if not isinstance(value, dict):
            raise ValueError("workspace manifest must be an object")
        return value

    def unknown(reason):
        incomplete(c, "workspace discovery", manifest, reason)
        return None

    try:
        current = parse(manifest)
        # A nested workspace must not inherit an unrelated ancestor's lock.
        if (manifest.name == "Cargo.toml" and "workspace" in current
                or manifest.name == "package.json" and "workspaces" in current):
            return []
        if manifest.name == "Cargo.toml" and (current.get("package") or {}).get("workspace"):
            return unknown("explicit package.workspace pointers require manual ownership validation")
        directory = manifest.parent.parent
        while directory == root or root in directory.parents:
            parent = directory / manifest.name
            pnpm = directory / "pnpm-workspace.yaml"
            declared = False
            if manifest.name == "package.json" and os.path.lexists(pnpm):
                patterns = pnpm_packages(pnpm) if safe_file(pnpm, root) else None
                if patterns is None:
                    return unknown("pnpm YAML workspace membership requires manual ownership validation")
                relative = manifest.parent.relative_to(directory).as_posix()
                if (any(workspace_pattern(relative, x) for x in patterns if not x.startswith("!"))
                        and not any(workspace_pattern(relative, x[1:]) for x in patterns if x.startswith("!"))):
                    return locks(directory)
                declared = True
            if os.path.lexists(parent):
                data = parse(parent)
                cargo = manifest.name == "Cargo.toml"
                workspace = data.get("workspace" if cargo else "workspaces")
                if workspace is not None:
                    if cargo:
                        if not isinstance(workspace, dict):
                            raise ValueError("invalid Cargo workspace")
                        members, excludes = workspace.get("members", []), workspace.get("exclude", [])
                    else:
                        members = workspace.get("packages", []) if isinstance(workspace, dict) else workspace
                        excludes = []
                    if not all(isinstance(v, list) and all(isinstance(x, str) for x in v)
                               for v in (members, excludes)):
                        raise ValueError("invalid workspace member/exclude list")
                    relative = manifest.parent.relative_to(directory).as_posix()
                    negative = [p[1:] for p in members if p.startswith("!")] + excludes
                    if any(workspace_pattern(relative, p) for p in negative):
                        return []
                    if any(workspace_pattern(relative, p) for p in members if not p.startswith("!")):
                        return locks(directory)
                    if cargo:
                        return unknown("implicit Cargo path-dependency membership was not resolved")
                    return []
            if declared:
                return []  # Not a member of the pnpm workspace rooted here.
            if directory == root:
                break
            directory = directory.parent
    except Unsupported as exc:
        return unknown(str(exc))
    except (ValueError, OSError, UnicodeError, TypeError, AttributeError, RecursionError):
        # Never copy manifest values or exception text, which may contain secrets.
        return unknown("workspace syntax or ownership could not be validated safely")
    return []


def workflow_run_blocks(c, path, text):
    """Read separate block-style steps[*].run scalars with source line numbers.

    This is a conservative YAML subset, not a general YAML parser. Aliases,
    flow collections and unsupported forms are explicitly incomplete.
    """
    mapping = re.compile(r'''^( *)(- +)?(?:([A-Za-z0-9_.-]+)|"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)')\s*:\s*(.*)$''')
    stack, block, run_lines, step_uses = [], None, [], {}
    # A step's `uses:` may follow its `with:`; resolve it per step before the walk.
    item_uses = {x["start"] + 1: step_value(x, "uses") for x in yaml_items(text.splitlines())}
    if text.lstrip().startswith(("{", "[")):
        incomplete(c, "workflow run scan", path, "flow-style workflow requires manual review")
    for number, line in enumerate(text.splitlines(), 1):
        indent = len(line) - len(line.lstrip(" "))
        if block is not None:
            level, is_run = block
            if not line.strip() or indent > level:
                if is_run:
                    run_lines.append((number, line))
                continue
            block = None
            if run_lines:
                yield run_lines
                run_lines = []
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        sequence = re.match(r"^-\s+(.*)$", stripped)
        if sequence and sequence[1].startswith(("{", "[", "*", "&", "!", "<<:")):
            # A sequence item's flow mapping/alias does not match `mapping`.
            # Drop the previous item's keys before checking its parent, while
            # retaining `steps` for YAML's indentationless sequence form.
            while stack and stack[-1][0] > indent:
                stack.pop()
            if stack and stack[-1][1] == "steps":
                incomplete(c, "workflow run scan", path,
                           "non-block or aliased step requires manual review")
                block = (indent, False)
                continue
        if "\t" in line[:len(line) - len(stripped)] or stripped.startswith(("<<:", "*", "&")):
            incomplete(c, "workflow run scan", path, "alias, merge or indentation requires manual review")
        quoted_key = re.match(r'^(?:- +)?("(?:[^"\\]|\\.)*")\s*:', stripped)
        if quoted_key and "\\" in quoted_key[1]:
            incomplete(c, "workflow run scan", path, "escaped mapping key requires manual review")
        match = mapping.match(line)
        if not match:
            continue
        level = len(match[1]) + len(match[2] or "")
        key, value = next(x for x in match.group(3, 4, 5) if x is not None), match[6]
        while stack and stack[-1][0] >= level:
            stack.pop()
        # The `uses:` of the step at this level; a new sequence item starts a new step.
        if match[2]:
            step_uses[level] = item_uses.get(number)
        # run: is a shell script; with.script of actions/github-script is JavaScript.
        # Both evaluate ${{ }} before the code runs. Other actions' script inputs are data.
        is_run = bool(stack) and (key == "run" and stack[-1][1] == "steps"
                                  or key == "script" and stack[-1][1] == "with"
                                  and str(step_uses.get(stack[-1][0]) or "").lower().startswith("actions/github-script@"))
        if (value.startswith(("*", "&", "!"))
                or key == "steps" and value and not value.startswith("#")
                or value.startswith(("{", "[")) and (key == "jobs" or stack and stack[-1][1] == "jobs")):
            incomplete(c, "workflow run scan", path, "non-block steps or tagged/aliased values require manual review")
        if is_run:
            run_lines.append((number, value))
        # Skip the contents of every scalar block, not just run: script examples
        # in with/env values must not be mistaken for step definitions.
        if is_run or re.match(r"^[|>][0-9+-]*(?:\s|$)", value):
            block = (level, is_run)
        elif value.startswith(("'", '"')) and not value.rstrip().endswith(value[0]):
            block = (level, False)
        stack.append((level, key))
    if run_lines:
        yield run_lines

def workflow_run_lines(c, path, text):
    """Compatibility iterator over the individual lines of each run scalar."""
    for block in workflow_run_blocks(c, path, text):
        yield from block

def workflow_expressions(c, path, script):
    """Extract expressions across lines, respecting quoted strings and braces."""
    cursor = 0
    while True:
        start = script.find("${{", cursor)
        if start < 0:
            return
        index, quoted = start + 3, False
        while index < len(script):
            if script[index] == "'":
                if quoted and script[index:index + 2] == "''":
                    index += 2  # GitHub expressions escape a quote by doubling it.
                    continue
                quoted = not quoted
            elif not quoted and script[index:index + 2] == "}}":
                yield start, script[start + 3:index]
                cursor = index + 2
                break
            index += 1
        else:
            incomplete(c, "workflow run scan", path, "unterminated expression requires manual review")
            return

def untrusted_workflow_expression(c, path, expression):
    """Find event reads inside functions and static dot/index access.

    This does not evaluate expressions. Literal strings are inert; dynamic
    property selectors whose source cannot be resolved are explicitly incomplete.
    """
    tokens = re.findall(r"'(?:[^']|'')*'|[A-Za-z_][A-Za-z0-9_-]*|[0-9]+|[^\s]", expression)
    events = {"issue", "pull_request", "comment", "review", "review_comment", "head_commit", "commits",
              "discussion", "discussion_comment", "workflow_run", "pages"}
    fields = {"title", "display_title", "body", "message", "name", "ref", "label", "email", "page_name",
              "head_branch", "default_branch"}
    safe_event_paths = {
        ("event", "number"),
        ("event", "issue", "id"), ("event", "issue", "number"),
        ("event", "pull_request", "id"), ("event", "pull_request", "number"),
        ("event", "comment", "id"), ("event", "review", "id"),
        # Scalar SHAs, ids and booleans: never attacker-chosen text.
        ("event", "after"), ("event", "before"), ("event", "pull_request", "head", "sha"),
        ("event", "pull_request", "base", "sha"), ("event", "pull_request", "head", "repo", "fork"),
        ("event", "workflow_run", "id"), ("event", "workflow_run", "head_sha"),
        ("event", "workflow_run", "run_attempt"), ("event", "workflow_run", "run_number"),
    }
    # contains(github.event.pull_request.title, 'WIP') as the whole expression yields only true/false.
    k = next((k for k, tok in enumerate(tokens) if tok != "!"), len(tokens))
    if tokens[k + 1:k + 2] == ["("] and tokens[k].lower() in ("contains", "startswith", "endswith"):
        depth = 0
        for i, tok in enumerate(tokens[k + 1:], k + 1):
            depth += (tok == "(") - (tok == ")")
            if not depth:
                if i == len(tokens) - 1:
                    return False
                break
    untrusted = False
    close, stack = {}, []
    for i, tok in enumerate(tokens):
        if tok == "[":
            stack.append(i)
        elif tok == "]" and stack:
            close[stack.pop()] = i + 1
    for index, token in enumerate(tokens):
        if token.lower() != "github" or index and tokens[index - 1] == ".":
            continue
        parts, dynamic, cursor = [], False, index + 1
        while cursor < len(tokens):
            if tokens[cursor] == "." and cursor + 1 < len(tokens):
                part = tokens[cursor + 1]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*|\*", part):
                    break
                parts.append(part.lower())
                cursor += 2
            elif tokens[cursor] == "[":
                end = close.get(cursor)
                if end is None:
                    incomplete(c, "workflow run scan", path, "unclosed property selector requires manual review")
                    break
                selector = tokens[cursor + 1:end - 1]
                if len(selector) == 1 and selector[0].startswith("'"):
                    parts.append(selector[0][1:-1].replace("''", "'").lower())
                elif len(selector) == 1 and selector[0].isdigit():
                    parts.append(selector[0])
                else:
                    parts.append("?")
                    dynamic = True
                cursor = end
            else:
                break
        risky = (not parts or parts[0] in {"head_ref", "*"}
                 or parts[0] == "event" and (len(parts) == 1
                    or parts[1] in events | {"*"} and (len(parts) == 2 or any(p in fields for p in parts[2:]))))
        untrusted = untrusted or risky
        if dynamic and not risky:
            incomplete(c, "workflow run scan", path, "dynamic github property selector requires manual review")
        elif parts and parts[0] == "event" and not risky and tuple(parts) not in safe_event_paths:
            # An object/array read (for example toJSON(issue.labels)) can expose
            # nested attacker-controlled strings. Do not treat unrecognized
            # subtrees as safe scalars without knowing their event schema.
            incomplete(c, "workflow run scan", path, "unresolved github event property source requires manual review")
    return untrusted


def isolated_composer_audit(c, root, lock, exe):
    """Audit a copy of the lock with no project/global audit exclusions."""
    try:
        raw = lock.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid lock")
        manifest_path = lock.parent / "composer.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8").lstrip("\ufeff"))
            if not isinstance(manifest, dict):
                raise ValueError("invalid manifest")
            if manifest.get("repositories"):
                incomplete(c, "composer audit", lock,
                           "isolated audit uses public Packagist only; custom-repository advisory coverage is incomplete")
        with tempfile.TemporaryDirectory(prefix="security-scan-composer-") as tmp:
            work = Path(tmp)
            (work / "composer.lock").write_bytes(raw)
            (work / "composer.json").write_text(json.dumps({
                "name": "security-scan/isolated-audit",
                "config": {"allow-plugins": False, "audit": {
                    "ignore": [], "ignore-abandoned": [], "abandoned": "report"}}
            }), encoding="utf-8")
            home = work / "home"
            home.mkdir()
            env = {k: v for k, v in os.environ.items()
                   if k.upper() != "COMPOSER" and not k.upper().startswith("COMPOSER_")}
            env.update({"COMPOSER_HOME": str(home), "COMPOSER_CACHE_DIR": str(work / "cache"),
                        "COMPOSER_NO_DEV": "0"})
            return run([exe, "--no-plugins", "--no-scripts", "audit", "--format=json",
                        "--locked", "--no-interaction", "--abandoned=report"], work, env=env)
    except (OSError, ValueError, UnicodeError, RecursionError):
        incomplete(c, "composer audit", lock, "could not prepare isolated audit input")
        return None


# ---------- per-ecosystem static checks ----------

def declares_python_dependencies(text):
    """A pyproject.toml that only configures tools has nothing to lock."""
    return re.search(r"^[^\S\n]*(dev-)?(dependencies|optional-dependencies)\s*=|"
                     r"^[^\S\n]*\[(project\.optional-dependencies|tool\.poetry(\.group\.[^\]]+)?\.dependencies|"
                     r"tool\.poetry\.dev-dependencies|tool\.pdm\.dev-dependencies|dependency-groups)\]",
                     text, re.M) is not None


def declares_dependencies(p):
    """Python packaging files that only configure tools have nothing to lock or audit."""
    if p.name == "pyproject.toml":
        return declares_python_dependencies(read(p))
    if p.name in ("setup.py", "setup.cfg"):
        return re.search(r"\binstall_requires\b", read(p)) is not None
    if p.name == "package.json":
        try:
            data = json.loads(read(p).lstrip("\ufeff"))
        except (ValueError, RecursionError):
            return True
        return not isinstance(data, dict) or any(
            mapping(data.get(s)) for s in ("dependencies", "devDependencies", "optionalDependencies"))
    return True


def check_lockfile(c, p):
    locks = LOCKS.get(p.name)
    if not declares_dependencies(p):
        return
    associated = matching_lockfiles(c, p) if locks else []
    if locks and associated is not None and not associated:
        c.add("Medium", f"{p.name} has no lockfile", p,
              impact="Each install may resolve different, possibly compromised, versions",
              fix=f"Commit one of: {', '.join(locks)}")


def load_json_object(c, p, tool):
    """Parse a manifest/lockfile; a non-object or unparseable file is incomplete, not a crash."""
    text = read(p)
    try:
        value = json.loads(text.lstrip("﻿"))
    except (ValueError, RecursionError):
        value = None
    if not isinstance(value, dict):
        incomplete(c, tool, p, "unparseable or non-object JSON requires manual review")
        return text, None
    return text, value


def mapping(value):
    return value if isinstance(value, dict) else {}


NPM_EXTERNAL_SOURCE = re.compile(r"^(git(\+\w+)?:|git@|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:)"
                                 r"|^[\w.-]+/[\w.-]+(#.*)?$")


def npm_floating(spec):
    """True when any alternative of an npm range has no upper bound."""
    for alternative in spec.split("||"):
        parts = alternative.split()
        if not parts or any(x.lower() in ("*", "x", "latest") for x in parts):
            return True
        if (any(x.startswith(">") for x in parts) and not any(x.startswith("<") for x in parts)
                and " - " not in alternative):
            return True
    return False


def npm_local_path(c, manifest, spec):
    """A relative file:/link: or ./ path that stays inside this checkout is first-party code."""
    m = re.match(r"(file:|link:)?(.*)$", spec, re.S)
    if "\0" in spec or not (m[2] and not re.match(r"[/\\~]|[A-Za-z][\w+.-]*:", m[2]) if m[1] else re.match(r"\.{1,2}/", m[2])):
        return False
    # realpath follows in-checkout symlinks to their targets, as npm does.
    target, root = os.path.realpath(os.path.join(Path(manifest).parent, m[2])), os.path.realpath(c.root)
    return os.path.commonpath([target, root]) == root


def check_npm(c, p):
    text, data = load_json_object(c, p, "package.json scan")
    if data is None:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in mapping(data.get(section)).items():
            spec = str(spec).strip()
            ln = line_of(text, f'"{name}"')
            if npm_local_path(c, p, spec):
                continue
            if NPM_EXTERNAL_SOURCE.match(spec):
                c.add("Medium", f"npm dependency {name} is fetched outside the registry ({spec})", p, ln,
                      impact="Bypasses registry integrity and advisory coverage; the source can change",
                      fix="Depend on a published, version-pinned release")
            elif npm_floating(spec) and section != "peerDependencies":
                c.add("Medium", f"npm dependency {name} floats to any version ({spec or 'empty'})", p, ln,
                      impact="A newly published malicious or broken release is installed automatically",
                      fix="Use a bounded range and the lockfile")
    for hook in ("preinstall", "install", "postinstall", "prepare"):
        if hook in mapping(data.get("scripts")):
            c.add("Info", f"package.json defines a '{hook}' lifecycle script", p, line_of(text, f'"{hook}"'),
                  impact="Runs automatically on install; review what it executes",
                  fix="Keep it minimal; consider installing with --ignore-scripts in CI", category=CAT_BUILD)


def check_npm_lock(c, p):
    text = read(p)
    # Parse the complete quoted URL before discarding its scheme. Otherwise an
    # empty-path URL can turn its query/fragment into bare "host" text that the
    # final URL sanitizer no longer recognizes.
    hosts = {}
    cursor = [0, 1]
    def line_at(pos):  # finditer offsets only increase
        cursor[1] += text.count("\n", cursor[0], pos); cursor[0] = pos
        return cursor[1]
    resolved = re.compile(r'"resolved"\s*:\s*("(?:[^"\\]|\\.)*")'
                          r'|^[^\S\n]+resolved\s+("(?:[^"\\]|\\.)*")'
                          r'|\btarball:\s*("(?:[^"\\]|\\.)*"|[^\s,}]+)', re.M)
    for match in resolved.finditer(text):
        try:
            raw = match[1] or match[2] or match[3]
            url = json.loads(raw) if raw.startswith('"') else raw.strip("'")
            parsed = urlsplit(url)
            # Git hosts' archive endpoints are git sources served as tarballs.
            archive = re.match(r"(codeload\.github\.com|gitlab\.com|bitbucket\.org)$", parsed.hostname or "") and (
                parsed.hostname == "codeload.github.com" or "/-/archive/" in parsed.path or "/get/" in parsed.path)
            if archive or re.match(r"(git(\+[a-z]+)?|github|gitlab|bitbucket|file|link)$", parsed.scheme.lower()):
                if "outside" not in hosts:
                    hosts["outside"] = line_at(match.start())
                continue
            if parsed.scheme.lower() not in ("http", "https"):
                continue
            host = parsed.hostname
            parsed.port  # Reject malformed ports/authorities before reporting.
            if (not host or any(ch.isspace() for ch in url)
                    or "\\" in parsed.netloc
                    or not re.fullmatch(r"[a-zA-Z0-9._:-]+", host)):
                raise ValueError("invalid resolved URL host")
        except (ValueError, UnicodeError):
            incomplete(c, "lockfile URL scan", p, "invalid resolved URL; host requires manual review")
            continue
        if host not in hosts:
            hosts[host] = line_at(match.start())
    # pnpm records git dependencies as resolution: {commit, repo, type: git}.
    git_resolution, region_end, typed = None, -1, None
    for opener in re.finditer(r"\bresolution:\s*\{", text):
        if opener.end() <= region_end:
            continue  # Same {...} region as a failed opener: its suffix cannot match either.
        newline = text.find("\n", opener.end())
        newline = len(text) if newline < 0 else newline
        brace = text.find("}", opener.end(), newline)  # bounded: no rescan to a distant brace
        region_end = newline if brace < 0 else brace
        if typed is not None and typed.start() < opener.end():
            typed = None
        typed = typed or re.compile(r"\btype:\s*git\b").search(text, opener.end())
        if typed is None:
            break
        if typed.start() < region_end:
            git_resolution = opener
            break
    if git_resolution and "outside" not in hosts:
        hosts["outside"] = text.count("\n", 0, git_resolution.start()) + 1
    if "outside" in hosts:
        c.add("Medium", "lockfile resolves a package from git or a local path, not a registry", p,
              hosts.pop("outside"), impact="Bypasses registry integrity and advisory coverage; the source can change",
              fix="Depend on a published, version-pinned release")
    default = {"registry.npmjs.org", "registry.yarnpkg.com"}
    for h in sorted(hosts.keys() - default):
        c.add("Low", f"lockfile resolves packages from non-default host {h}", p, hosts[h],
              impact="Packages come from a registry outside the public one; confirm it is trusted",
              fix="Confirm the host is an approved internal mirror", confidence="Suspected")
    if p.name == "package-lock.json" and not re.search(r'"integrity"\s*:', text):
        c.add("Low", "package-lock.json has no integrity hashes", p,
              impact="Tampered tarballs are not detected", fix="Regenerate the lockfile with a current npm")


def registry_host(url):
    try:
        return (urlsplit(url.strip("'\"")).hostname or "").lower()
    except ValueError:
        return ""


def check_npmrc(c, p):
    text = read(p)
    default = {"registry.npmjs.org", "registry.yarnpkg.com"}
    for i, ln in enumerate(text.splitlines(), 1):
        m = (re.match(r"\s*(@[\w-]+:)?registry\s*=\s*(\S+)", ln)
             or re.match(r"""\s*()["']?npmRegistryServer["']?\s*:\s*(\S+)""", ln))
        if m and registry_host(m.group(2)) not in default:
            # An indented .yarnrc.yml npmRegistryServer sits under npmScopes/npmRegistries.
            target = m.group(1) or ("a scope" if ln[:1].isspace() and "npmRegistryServer" in ln else "all packages")
            c.add("Info", f"{p.name} points {target} at {m.group(2)}", p, i,
                  impact="Confirm the registry is trusted and scoped names cannot be claimed publicly",
                  fix="Scope private registries to your own @scope", category=CAT_BUILD)
        if (re.search(r"""(_authToken|_auth|_password)\s*=\s*["']?[^$\s"']""", ln)
                or re.match(r"""\s*["']?(npmAuthToken|npmAuthIdent)["']?\s*:\s*["']?[^$\s"']""", ln)):
            c.add("High", f"{p.name} contains a literal registry credential", p, i,
                  impact="Anyone with repository access can publish or read private packages",
                  fix="Remove it, rotate the token, use an environment variable", category="Secrets")


def check_composer(c, p):
    text, data = load_json_object(c, p, "composer.json scan")
    if data is None:
        return
    if data.get("minimum-stability") in ("dev", "alpha", "beta", "RC") and not data.get("prefer-stable"):
        c.add("Low", f"composer minimum-stability is {data['minimum-stability']} without prefer-stable", p,
              line_of(text, "minimum-stability"), impact="Unstable releases may be installed",
              fix="Set prefer-stable: true or raise minimum-stability")
    repos = data.get("repositories") or []
    # Composer accepts both a list and a name-keyed object of repositories.
    for repo in (repos.values() if isinstance(repos, dict) else repos if isinstance(repos, list) else []):
        if not isinstance(repo, dict):
            continue
        kind = repo.get("type")
        if kind in ("vcs", "git", "github", "gitlab", "bitbucket", "path", "package", "artifact") or (
                kind == "composer" and registry_host(str(repo.get("url", ""))) not in ("repo.packagist.org",
                                                                                      "packagist.org")):
            c.add("Low", f"composer repository of type {kind}: {repo.get('url', '')}", p,
                  line_of(text, '"repositories"'),
                  impact="Packages outside Packagist lack its advisory and integrity coverage",
                  fix="Prefer published releases; pin references", confidence="Suspected")
    plugins = mapping(data.get("config")).get("allow-plugins")
    if plugins is True:
        c.add("Medium", "composer allow-plugins is true for every package", p, line_of(text, "allow-plugins"),
              impact="Any dependency's plugin code runs during install",
              fix="List allowed plugins explicitly", category=CAT_BUILD)
    for section in ("require", "require-dev"):
        for name, spec in mapping(data.get(section)).items():
            spec = str(spec).strip()
            # Platform constraints (php, ext-*, lib-*) are not installed packages.
            if name in ("php", "php-64bit", "composer-plugin-api") or name.startswith(("ext-", "lib-")):
                continue
            unbounded = any(
                any(x.startswith(">") for x in alt.replace(",", " ").split())
                and not any(x.startswith("<") for x in alt.replace(",", " ").split())
                for alt in re.split(r"\|\|?", spec))
            if spec in ("*", "") or spec.startswith("dev-") or "@dev" in spec or unbounded:
                c.add("Medium", f"composer dependency {name} floats ({spec})", p, line_of(text, f'"{name}"'),
                      impact="Unreviewed code is pulled on update", fix="Require a tagged version range")


def check_requirements(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#", 1)[0].strip()
        if not s:
            continue
        editable = re.match(r"^(-e|--editable)(\s+|=)(.*)$", s)
        if editable:
            s = editable.group(3).strip()
            if not re.match(r"^(git\+|https?://|hg\+|svn\+|bzr\+)", s):
                continue  # A local editable path is first-party code, not a fetched dependency.
        extra = s.startswith("--extra-index-url")
        if extra:
            c.add("Medium", "pip --extra-index-url mixes a second index with PyPI", p, i,
                  impact="A public package can shadow an internal one with the same name",
                  fix="Use a single index (a mirror that proxies PyPI) or pin hashes", category=CAT_BUILD)
        plain = (re.match(r"^--trusted-host[\s=]+(\S*)", s)
                 or re.match(r"^(?:--index-url|--extra-index-url|-i|-f|--find-links)[\s=]+http://(?:[^@/\s]*@)?(\[[^\]]*\]|[^:/\s]*)", s))
        if plain and plain[1].strip("[]").lower() not in LOCAL_HOSTS:
            c.add("Medium", "pip installs from a source without TLS verification (see source location)", p, i,
                  impact="A network attacker can serve modified packages", category=CAT_BUILD,
                  fix="Use an https:// index with a trusted CA")
        elif extra or re.match(r"^--trusted-host\b", s):
            continue
        elif s.startswith("--index-url") or s.startswith("-i "):
            c.add("Info", "pip index overridden (see source location)", p, i, impact="Confirm the index is trusted",
                  category=CAT_BUILD)
        elif re.match(r"^(--find-links|-f)(\s|=)", s):
            c.add("Medium", "pip --find-links adds a package source beside the index", p, i,
                  impact="Packages found there can shadow or replace index releases",
                  fix="Use a single trusted index or pin hashes", category=CAT_BUILD)
        elif s.startswith("-") or s.startswith("."):
            continue
        elif re.match(r"^(git\+|https?://|hg\+|svn\+|bzr\+)", s) or " @ " in s:
            c.add("Medium", "Python dependency fetched from a URL (see source location)", p, i,
                  impact="Bypasses index integrity and advisory coverage", fix="Pin to a released version")
        elif "==" not in s and "--hash" not in s:
            c.add("Low", "Python requirement not pinned (see source location)", p, i,
                  impact="Installs whatever version is newest at install time",
                  fix="Pin with == (and --hash for reproducible installs) or use a lockfile")


def ruby_code(ln):
    """The line without a trailing # comment outside quotes."""
    quote = None
    for i, ch in enumerate(ln):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            return ln[:i]
    return ln


def check_gemfile(c, p):
    text = read(p)
    outside = r"""['"](?:/|\.\./)"""  # Only an absolute or parent path leaves this checkout.
    for i, ln in enumerate(text.splitlines(), 1):
        ln = ruby_code(ln)
        if (re.search(r"^\s*gem\s.*(\b(git|github)\s*:|:(git|github)\s*=>|\bpath\s*:\s*" + outside
                      + r"|:path\s*=>\s*" + outside + ")", ln)
                or re.match(r"""^\s*(git|github)\s*\(?\s*['"]|^\s*path\s*\(?\s*""" + outside, ln)):
            c.add("Medium", "gem fetched outside rubygems (see source location)", p, i,
                  impact="Bypasses rubygems integrity and advisory coverage", fix="Use a released gem version")
        if re.search(r"^\s*source\s+['\"](?!https://rubygems\.org)", ln):
            c.add("Info", "additional gem source (see source location)", p, i, impact="Confirm the source is trusted",
                  category=CAT_BUILD)


def check_gomod(c, p):
    text = read(p)
    in_block = False
    for i, ln in enumerate(text.splitlines(), 1):
        code = ln.split("//", 1)[0]
        if in_block:
            if code.strip() == ")":
                in_block = False
                continue
        elif re.match(r"\s*replace\s*\(\s*$", code):
            in_block = True
            continue
        elif not re.match(r"\s*replace\s", code):
            continue
        if "=>" in code and re.search(r"=>\s*(\.{1,2}/|/|\.{1,2}\s*$)", code):
            c.add("Info", f"go.mod replaces a module with a local path: {ln.strip()}", p, i,
                  impact="Builds depend on code outside module verification", category=CAT_BUILD)


# Outsider events that run with secrets; issue_comment can be posted on any PR.
PRIVILEGED_TRIGGERS = ("pull_request_target", "workflow_run", "issue_comment")
# A checkout ref/repository naming the PR head anywhere in its value, e.g.
# ${{ (github.event.pull_request.head.sha) }} or format('refs/pull/{0}/merge', github.event.number).
HEAD_REF = re.compile(r"\bgithub\.(?:head_ref|event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)|merge_commit_sha)"
                      r"|event\.workflow_run\.(?:head_(?:sha|branch|repository\.full_name|commit\.id)"
                      r"|pull_requests\[\d+\]\.head\.(?:sha|ref)))\b", re.I)
PR_NUMBER = re.compile(r"\bgithub\.event\.(?:(?:pull_request|issue)\.)?number\b", re.I)
# Any expression naming the PR head (or its number, for refs/pull/N fetches).
UNTRUSTED_HEAD = re.compile(r"\bgithub\.(?:head_ref|event\.(?:number|issue\.number|pull_request\.(?:head\.[\w.]+|merge_commit_sha|number)"
                            r"|workflow_run\.(?:head_[\w.]+|pull_requests\b)))", re.I)
ENV_USE = re.compile(r"\$\{?([A-Za-z_]\w*)|\$\{\{\s*env\.([A-Za-z_]\w*)")
OUTPUT_USE = re.compile(r"\bsteps\.([\w-]+)\.outputs\.([\w-]+)")
INPUT_USE = re.compile(r"(?<![\w.])inputs\.([\w-]+)")


BRACKET = re.compile(r"\[\s*'([\w-]+)'\s*\]")
# `NAME=value`, `export NAME=value` (also local/declare) of a run script line.
SHELL_ASSIGN = re.compile(r"\s*(?:(?:export|local|declare|readonly|typeset)(?:\s+-\w+)*\s+)?([A-Za-z_]\w*)=(.*)")


def dotted(value):
    """github['head_ref'] and github.event['pull_request']['head'] as the dotted paths they read."""
    return BRACKET.sub(r".\1", value) if "[" in value else value


def pull_ref(value):
    return "pull/" in value or "/pr/" in value


def head_expr(value):
    """UNTRUSTED_HEAD, where a bare PR or issue number counts only inside a pull/<n>/ or /pr/<n> ref."""
    value = dotted(value)
    return any(not PR_NUMBER.fullmatch(m[0]) or pull_ref(value) for m in UNTRUSTED_HEAD.finditer(value))


def head_level(value):
    """2 when value names the PR head; 1 for a bare PR number, which is the head only in a ref (counts)."""
    return 2 if head_expr(value) else 1 if PR_NUMBER.search(dotted(value)) else 0


def counts(value, level):
    """A use site of a source at `level` checks out the head: always at 2, at 1 inside a pull/<n> ref."""
    return level == 2 or level == 1 and pull_ref(value)


def strip_comment(line):
    """line without a YAML ` #...` comment outside quotes (linear scan)."""
    quote = None
    for k, ch in enumerate(line):
        if quote:
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (k == 0 or line[k - 1] in " \t"):
            return line[:k]
    return line


def head_value(value):
    """True when a checkout input names the PR head (or refs/pull/<number>)."""
    value = dotted(value)
    return bool(HEAD_REF.search(value) or "pull/" in value and PR_NUMBER.search(value))


FLOW_PAIR = re.compile(r"""\s*["']?([\w-]+)["']?\s*:\s*("(?:[^"\\]|\\.)*(?:"|$)|'(?:[^']|'')*(?:'|$)|[^,}]*)""")
FLOW_END = re.compile(r"\s*\}")


def flow_pairs(value):
    """{key: value} of a one-line flow mapping such as `{ ref: "x", path: y }` (no nesting)."""
    exprs, cursor, text = [], 0, ""
    while True:  # Hide ${{ }} so their braces and commas do not end a value (linear find loop).
        start = value.find("${{", cursor)
        end = value.find("}}", start + 3) if start >= 0 else -1
        if end < 0:
            text += value[cursor:]
            break
        text += value[cursor:start] + "\0%d\0" % len(exprs)
        exprs.append(value[start:end + 2])
        cursor = end + 2
    pairs, body, pos = {}, text.strip()[1:], 0
    while pos < len(body):  # Anchored at the start and after each comma: linear on unterminated `{aaaa`.
        m = FLOW_PAIR.match(body, pos)
        if m:
            pairs[m[1]] = re.sub(r"\0(\d+)\0", lambda e: exprs[int(e[1])], m[2]).strip()
            pos = m.end()
            if FLOW_END.match(body, pos):
                break
        pos = body.find(",", pos) + 1
        if not pos:
            break
    return pairs


def mapping_values(lines, index, value, end):
    """{key: value} of the block (or one-line flow) mapping under the key on lines[index]."""
    if value.lstrip().startswith("{"):
        return flow_pairs(value)
    key = re.match(r" *(?:- +)?", lines[index])
    entries = yaml_children(lines, index + 1, end)
    if not entries or len(lines[entries[0][1]]) - len(lines[entries[0][1]].lstrip(" ")) <= key.end():
        return {}
    return {k: "\n".join(lines[i + 1:stop]) if re.match(r"[|>][0-9+-]*\s*(#.*)?$", v) else v
            for k, i, v, stop in entries if k is not None}


def local_targets(root, rel, memo):
    """Files of this checkout that `uses: ./rel` runs (a workflow or an action directory), once per string."""
    if rel not in memo:
        target = (root / rel).resolve()
        memo[rel] = [cand for cand in (target, target / "action.yml", target / "action.yaml")
                     if (cand == root or root in cand.parents) and cand.is_file()]
    return memo[rel]


def local_calls(files, root, privileged):
    """callee -> [(caller, {input: value}, caller is privileged)] of local `uses: ./x` jobs and steps."""
    root, calls, memo = Path(root).resolve(), {}, {}
    for p in files:
        if not (is_workflow(p) or p.name in ("action.yml", "action.yaml")):
            continue
        lines = read(p).splitlines()
        sites = [(x["keys"]["uses"][1], x["keys"].get("with"), x["end"]) for x in yaml_items(lines) if "uses" in x["keys"]]
        jobs = child(yaml_children(lines), "jobs")
        for job in yaml_children(lines, jobs[1] + 1, jobs[3]) if jobs else []:
            props = yaml_children(lines, job[1] + 1, job[3])
            uses, given = child(props, "uses"), child(props, "with")
            if uses:
                sites.append((uses[2], given and given[1:3], job[3]))
        for uses, given, end in sites:
            m = re.match(r"""["']?\./([^\s"'#@]*)""", uses)
            if not m:
                continue
            values = mapping_values(lines, given[0], given[1], end) if given else {}
            for cand in local_targets(root, m[1], memo):
                calls.setdefault(cand, []).append((p, values, p.resolve() in privileged))
    # A -> B -> C: B's `inputs.x` forwarded to C carries what A passed for x.
    for _ in range(8):
        changed = False
        for entries in calls.values():
            for n, (caller, values, privileged_caller) in enumerate(entries):
                ups = calls.get(caller.resolve(), [])
                grown = {}
                for key, value in values.items():
                    extra = [g[x] for x in INPUT_USE.findall(value) for _, g, _ in ups if x in g and g[x] not in value]
                    grown[key] = (value + " " + " ".join(extra))[:4000] if extra else value
                if grown != values:
                    entries[n] = (caller, grown, privileged_caller or any(u[2] for u in ups))
                    changed = True
        if not changed:
            break
    return calls


def flow_depth(code):
    return len(re.findall(r"[\[{]", code)) - len(re.findall(r"[\]}]", code))


def on_section(text):
    """(1-based line, line, in-flow) of the top-level `on:` key, its block and multi-line flow value."""
    out, depth = [], None
    for number, ln in enumerate(text.splitlines(), 1):
        if depth is None:
            m = re.match(r"""["']?on["']?\s*:(.*)$""", ln)
            if m:
                depth = flow_depth(m[1].split("#")[0])
                out.append((number, ln, True))
            continue
        if depth > 0:
            depth += flow_depth(ln.split("#")[0])
            out.append((number, ln, True))
        elif ln.strip() and not ln[:1].isspace() and not ln.startswith(("#", "- ")) and ln != "-":
            break  # (An indentationless `- name` list still belongs to `on:`.)
        else:
            out.append((number, ln, False))
    return out


def workflow_triggers(text):
    """Trigger names, from `on: x`, flow `on: [x, y]` (also multi-line) and block `on:` keys (conservative)."""
    found, in_on = set(), None
    for n, (_, ln, flow) in enumerate(on_section(text)):
        if flow:
            found |= set(re.findall(r"[a-z_]+", (ln.split(":", 1)[1] if n == 0 else ln).split("#")[0]))
            continue
        k = re.match(r"""^(\s*)(?:-\s+)?["']?([a-z_]+)["']?\s*(:|$)""", ln)
        if k and (in_on is None or len(k.group(1)) <= in_on):
            in_on = len(k.group(1))
            found.add(k.group(2))
    return found


def hiding_escape(text):
    """A YAML double-quoted escape that can spell text (\\x, \\u, \\U, \\N, \\L, \\P, \\_ or a line break)."""
    return any(m[1] in "xuUNLP_\n" for m in re.finditer(r"\\(.|\n|$)", text))


def escaped_triggers(text):
    """Escapes inside a double-quoted `on:` value or key can spell a trigger name the raw text hides."""
    return any('"' in part and hiding_escape(part[part.index('"'):])
               for n, (_, ln, _) in enumerate(on_section(text))
               for part in [ln.split(":", 1)[1] if n == 0 else ln])


def trigger_line(text, name):
    """Line of a trigger name inside `on:` (comments excluded), else the `on:` line."""
    section = on_section(text)
    for number, ln, _ in section:
        if re.search(r"\b" + name + r"\b", ln.split("#")[0]):
            return number
    return section[0][0] if section else None


def is_workflow(p):
    """GitHub runs only the files directly in a .github/workflows directory."""
    p = Path(p)
    return p.suffix in (".yml", ".yaml") and p.parent.name == "workflows" and p.parent.parent.name == ".github"


def privileged_workflows(files, root):
    """Workflows that run with secrets on outsider events, plus local reusable
    workflows and actions they call (which inherit that context)."""
    root, priv, memo = Path(root).resolve(), {}, {}
    for p in files:
        if is_workflow(p):
            text = read(p)
            t = [x for x in PRIVILEGED_TRIGGERS if x in workflow_triggers(text)]
            if t or escaped_triggers(text):
                priv[p.resolve()] = t[0] if t else "pull_request_target"
    # Follow local calls to a fixed point: a callee's own callees run in the
    # same privileged context (a -> b.yml -> c.yml). `./` is the checkout root.
    pending = list(priv)
    while pending:
        p = pending.pop()
        for m in re.finditer(r"""\buses["']?[ \t]*:[ \t]*["']?(?:\.|\$)/([^\s"'#@]*)""", read(p)):
            for cand in local_targets(root, m.group(1), memo):  # Only files of this checkout.
                if cand not in priv:
                    priv[cand] = priv[p]
                    pending.append(cand)
    return priv


SOURCE_CONFIGS = {"pom.xml", "settings.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
                  "settings.gradle.kts", "nuget.config", "NuGet.Config", "pip.conf", "pip.ini", ".pypirc",
                  "bunfig.toml", ".npmrc", ".yarnrc", ".yarnrc.yml", ".gitmodules", "Gemfile"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
TLS_OFF = re.compile(r"""^\s*(?:strict-ssl(?:\s*=\s*|\s+)["']?false|["']?enableStrictSsl["']?\s*:\s*false|trusted-host\s*=|--trusted-host\b"""
                     r"""|allowInsecureProtocol\s*(?:=|\()\s*true|isAllowInsecureProtocol\s*=\s*true)""", re.I)


def xml_code(text):
    """Drop <!-- --> comments, keeping their line breaks so line numbers stay right."""
    return re.sub(r"<!--.*?(?:-->|\Z)", lambda m: "\n" * m[0].count("\n"), text, flags=re.S)


def check_source_transport(c, p):
    """Package/submodule sources over plaintext http:// or git://, and disabled TLS checks."""
    text = read(p)
    if p.suffix in (".xml", ".config"):
        text = xml_code(text)
    in_repo, depth, repo_depth, pending, spans = 0, 0, None, False, None
    for i, ln in enumerate(text.splitlines(), 1):
        if ln.lstrip().startswith(("#", "//", ";", "<!--")):
            continue
        if p.name == "Gemfile":
            ln = ruby_code(ln)
        if TLS_OFF.search(ln):
            c.add("Medium", f"{p.name} disables TLS verification for a package source", p, i, category=CAT_BUILD,
                  impact="A network attacker can serve modified packages", fix="Remove it and trust the CA instead")
        if p.name in (".npmrc", ".yarnrc", ".yarnrc.yml") and re.match(
                r"""\s*["']?(?:https?[-_]?proxy|proxy|no[-_]?proxy)["']?\s*[=:\s]""", ln, re.I):
            continue  # A network proxy is not a package source.
        if p.suffix in (".gradle", ".kts"):
            # Gradle: only repository declarations and applied scripts fetch code;
            # pom/license `url` values are publication metadata.
            # String contents are blanked (same length) so their braces do not count;
            # spans are the parts of the line inside a repositories block.
            code = re.sub(r"(?<!:)//.*", "", ln)
            # An unterminated string runs to the end of the line (linear, no rescans).
            bare = re.sub(r""""(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)""",
                          lambda m: m[0][0] + " " * (len(m[0]) - 1) if len(m[0]) < 2 or m[0][-1] != m[0][0]
                          else m[0][0] + " " * (len(m[0]) - 2) + m[0][-1], code)
            if pending and bare.strip() and not bare.lstrip().startswith("{"):
                pending = False
            spans, start = [], 0 if repo_depth is not None else None
            for m in re.finditer(r"\brepositories(?:[ \t]*\.[ \t]*\w+)?(?=[ \t]*(?:\{|$))|[{}]", bare):
                if m[0] == "{":
                    if pending and repo_depth is None:
                        repo_depth, start = depth, m.start()
                    pending, depth = False, depth + 1
                elif m[0] == "}":
                    pending, depth = False, depth - 1
                    if repo_depth is not None and depth <= repo_depth:
                        repo_depth = None
                        spans.append((start, m.end()))
                else:
                    pending = True  # Its block opens at the next brace, here or on the next line.
            if repo_depth is not None:
                spans.append((start, len(ln)))
            if re.search(r"\bapply\s*\(?\s*from\s*[:=]", bare):
                spans.append((0, len(ln)))
            if not spans:
                continue
        elif p.suffix == ".xml":
            # Maven: only <repository>/<pluginRepository>/<mirror> URLs fetch code;
            # project <url>, <scm> and xmlns values are metadata.
            in_repo += len(re.findall(r"<(?:repository|pluginRepository|snapshotRepository|mirror)>", ln))
            hit = in_repo > 0
            in_repo -= len(re.findall(r"</(?:repository|pluginRepository|snapshotRepository|mirror)>", ln))
            if not hit:
                continue
        elif p.name == "Gemfile" and not re.match(r"\s*(source|gem|git)\b", ln):
            continue
        for m in re.finditer(r"""\b(http|git)://([^\s"'<>/:]+)""", ln):
            if m.group(2).lower() in LOCAL_HOSTS or spans and not any(a <= m.start() < b for a, b in spans):
                continue
            c.add("Medium", f"{p.name} fetches code over plaintext {m.group(1)}://", p, i, category=CAT_BUILD,
                  impact="Anyone on the network path can substitute packages that then run in builds",
                  fix="Use https:// (or ssh for git) for every package source")
            break


def check_extra_sources(c, p):
    text = read(p)
    if p.name in ("pip.conf", "pip.ini"):
        for i, ln in enumerate(text.splitlines(), 1):
            if re.match(r"\s*extra-index-url\s*=", ln):
                c.add("Medium", "pip config adds a second index beside PyPI", p, i, category=CAT_BUILD,
                      impact="Dependency confusion: a public package with an internal name may be installed",
                      fix="Use a single index that proxies PyPI, or pin hashes")
    elif p.name.lower() == "nuget.config":
        text = xml_code(text)
        adds, cursor = [], [0, 1]  # (line, key) of <add> inside <packageSources>; offsets only increase
        for block in re.finditer(r"<packageSources\b[^<>]*>(.*?)(?:</packageSources>|\Z)", text, re.S | re.I):
            for m in re.finditer(r"""<add\s[^<>]*?\bkey\s*=\s*["']([^"']*)""", block[1], re.I):
                pos = block.start(1) + m.start()
                cursor[1] += text.count("\n", cursor[0], pos); cursor[0] = pos
                adds.append((cursor[1], m[1].lower()))
        mapped = {}
        for block in re.finditer(r"<packageSourceMapping\b[^<>]*>(.*?)(?:</packageSourceMapping>|\Z)", text, re.S | re.I):
            for src in re.finditer(r"""<packageSource\s[^<>]*?\bkey\s*=\s*["']([^"']*)["'][^<>]*>(.*?)(?:</packageSource>|\Z)""",
                                   block[1], re.S | re.I):
                mapped.setdefault(src[1].lower(), set()).update(
                    re.findall(r"""<package\s[^<>]*?\bpattern\s*=\s*["']([^"']*)""", src[2], re.I))
        # NuGet takes the most specific matching pattern and considers every source
        # that maps it, so mapping mitigates only when every source is mapped and no
        # pattern (`*` included) is mapped to two sources.
        owners = [x.lower() for _, k in adds for x in mapped.get(k, ())]
        mitigated = all(mapped.get(k) for _, k in adds) and len(owners) == len(set(owners))
        # <clear/> only drops inherited sources; two declared sources still race
        # for every package id unless packageSourceMapping assigns them.
        if len(adds) > 1 and not mitigated:
            c.add("Medium", "nuget.config mixes several package sources without packageSourceMapping", p, adds[1][0],
                  category=CAT_BUILD, impact="Dependency confusion: any source may satisfy any package id",
                  fix="Add <packageSourceMapping> so each package prefix comes from one source")
    elif p.name == ".pypirc":
        for i, ln in enumerate(text.splitlines(), 1):
            if re.match(r"\s*password\s*[=:]\s*[^\s$%{]", ln):
                c.add("High", ".pypirc contains a literal upload credential", p, i, category="Secrets",
                      impact="Anyone with repository access can publish this project's packages",
                      fix="Remove it, rotate the token, use trusted publishing or an environment variable")


ITEM_DASH, ITEM_KEY = re.compile(r" *- +"), re.compile(r"""( *)(- +)?["']?([\w.-]+)["']?\s*:(?:\s+(.*))?$""")
_items_memo = {}


def yaml_items(lines):
    """Block-sequence items (conservative): {start, end, parent, keys}; keys maps the
    item's own keys to (index, value). Block scalar contents are skipped. One file is
    parsed by several checks: the last result is reused (callers only read it)."""
    key = "\n".join(lines)
    if key not in _items_memo:
        _items_memo.clear()
        _items_memo[key] = parse_items(lines)
    return _items_memo[key]


def parse_items(lines):
    items, stack, scalar, last = [], [], None, []  # last: (indent, index, dash), indents increasing
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        if scalar is not None:
            if indent > scalar:
                continue
            scalar = None
        while stack and indent <= stack[-1][0]:
            stack.pop()[1]["end"] = i
        dash = ITEM_DASH.match(ln)
        while last and last[-1][0] > indent:
            last.pop()  # A shallower later line is always the nearer parent candidate.
        if dash:
            # The nearest shallower line, or a same-indent key (indentationless sequence).
            k = len(last) - 2 if last and last[-1][0] == indent and last[-1][2] else len(last) - 1
            parent = last[k][1] if k >= 0 else -1
            stack.append((indent, {"start": i, "end": len(lines), "level": len(dash[0]), "parent": parent, "keys": {}}))
            items.append(stack[-1][1])
        if not (dash and last and last[-1][0] == indent and not last[-1][2]):
            if last and last[-1][0] == indent:
                last.pop()
            last.append((indent, i, bool(dash)))
        m = ITEM_KEY.match(ln)
        if m:
            level, value = len(m[1]) + len(m[2] or ""), (m[4] or "").strip()
            if stack and stack[-1][1]["level"] == level:
                stack[-1][1]["keys"].setdefault(m[3], (i, value))
            if re.match(r"[|>][0-9+-]*(\s|$)", value):
                scalar = level
    return items


def yaml_children(lines, start=0, end=None):
    """[key, index, value, end] of the block-mapping entries in lines[start:end] (one indentation level)."""
    end, out, level = len(lines) if end is None else end, [], None
    for i in range(start, end):
        ln = lines[i]
        if not ln.strip() or ln.lstrip().startswith("#"):
            continue
        indent = len(ln) - len(ln.lstrip(" "))
        level = indent if level is None else level
        if indent < level:
            end = i
            break
        if indent == level:
            m = re.match(r"""\s*["']?([^\s"'#:](?:[^"':]*[^\s"':])?)["']?[ \t]*:(?:\s+(.*))?$""", ln)
            out.append([m[1] if m else None, i, (m[2] or "").strip() if m else "", end])
    for a, b in zip(out, out[1:]):
        a[3] = b[1]
    if out:
        out[-1][3] = end
    return out


def child(entries, key):
    return next((e for e in entries if e[0] == key), None)


def image_ref(value):
    """The image of a YAML scalar, or None for aliases, block scalars, expressions and empty values."""
    value = re.sub(r"\s+#.*", "", value).strip()
    if value.startswith("&"):
        value = value.split(None, 1)[1] if " " in value else ""
    value = value.strip("'\"")
    if not value or value[0] in "*>|!{[" or "$" in value:
        return None
    return value


def unpinned_image(img, digest=False):
    if img is None or "@sha256:" in img:
        return False
    name = img.split("/")[-1]
    return digest or ":" not in name or name.endswith(":latest")


def step_value(step, key):
    return re.sub(r"\s+#.*", "", step["keys"].get(key, (0, ""))[1]).strip().strip("'\"")


EXECUTES_CHECKOUT = re.compile(
    r"(?:^|[;&|(])[ \t]*(?:(?:npm|pnpm|yarn|bun)\s+(?:install|ci|i|test|t|run|exec|build|start)\b|yarn[ \t]*(?:$|[;&|])"
    r"|make\b|pip3?\s+install\s+(?:-e\s+)?\.|python3?\s+(?:-m\s+pip\s+install\s+\.|setup\.py)|\./[\w.-]"
    r"|(?:bash|sh)\s+[\w./-]+\.sh\b|mvn\b|\./mvnw\b|gradle\b|\./gradlew\b)", re.M)


GIT_MOVES = {"checkout", "switch", "reset", "worktree", "pull", "merge", "rebase", "cherry-pick", "clone"}


def shell_text(line):
    """line with shell separators inside ${{ }} blanked: they belong to the expression,
    e.g. format('pull/{0}/head', …) or `head_ref || 'main'`. Linear."""
    parts, at = [], 0
    while True:
        start = line.find("${{", at)
        end = line.find("}}", start + 3) if start >= 0 else -1
        if end < 0:
            break
        parts += [line[at:start], re.sub(r"[;&|()`,]", " ", line[start:end + 2])]
        at = end + 2
    return "".join(parts) + line[at:]


def git_commands(line):
    """(subcommand, args) of every git command in a shell line; linear, no regex backtracking."""
    out, line = [], shell_text(line)
    for seg in re.split(r"[;&|()`]", line):
        words = [w.strip("'\"") for w in seg.split()]  # "a:b" and a:b name the same refspec
        starts = [k for k, w in enumerate(words) if w == "git" or w.endswith("/git")]
        for start, stop in zip(starts, starts[1:] + [len(words)]):
            i = start + 1
            while i < stop and words[i].startswith("-"):
                i += 2 if words[i] in ("-C", "-c") else 1
            if i < stop:
                out.append((words[i], words[i + 1:stop]))
    return out


def github_writes(line):
    """(GITHUB_ENV|GITHUB_OUTPUT, name, value) of each `NAME=value >> $GITHUB_ENV` write in a shell line."""
    out = []
    for seg in re.split(r"[;&|]", line):
        m = re.search(r""">>\s*["']?\$\{?(GITHUB_ENV|GITHUB_OUTPUT)\b""", seg)
        if m:
            before, eq, value = seg[:m.start()].partition("=")
            name = re.search(r"(?<![\w-])([A-Za-z_][\w-]*)$", before)
            if eq and name:
                out.append((m[1], name[1], value))
    return out


def scalar_rows(lines):
    """Flags for rows inside `key: |` / `key: >` block scalars, whose text is data, not YAML."""
    inside, level = bytearray(len(lines)), None
    for i, ln in enumerate(lines):
        if level is not None:
            if not ln.strip() or len(ln) - len(ln.lstrip(" ")) > level:
                inside[i] = 1
                continue
            level = None
        m = re.match(r"""( *)(- +)?["']?[\w.-]+["']?[ \t]*:[ \t]+[|>][0-9+-]*[ \t]*(#.*)?$""", ln)
        if m:
            level = len(m[1]) + len(m[2] or "")
    return inside


def moved_args(commands):
    """git_commands without the new branch name of checkout/switch -b/-c/--orphan (one word, or one
    `${{ }}` expression over several): that branch is created, not checked out."""
    out = []
    for sub, args in commands:
        kept, skip, depth = [], False, 0
        for a in args:
            if skip or depth > 0:
                skip, depth = False, depth + a.count("${{") - a.count("}}")
                continue
            kept.append(a)
            skip = sub in ("checkout", "switch") and a in ("-b", "-B", "-c", "-C", "--orphan")
        out.append((sub, kept))
    return out


def branch(ref):
    """`pr`, `heads/pr` and `refs/heads/pr` name one local branch for checkout; `refs/remotes/origin/pr`
    and `remotes/origin/pr` the remote-tracking branch `origin/pr`."""
    ref = ref.lstrip("+")
    prefix = next((x for x in ("refs/heads/", "heads/", "refs/remotes/", "remotes/") if ref.startswith(x)), "")
    return ref[len(prefix):]


def check_workflow(c, p, privileged=None, calls=None):
    text = read(p)
    lines = text.splitlines()
    triggers = workflow_triggers(text)
    callers = (calls or {}).get(Path(p).resolve(), [])
    if escaped_triggers(text):
        incomplete(c, "workflow scan", p, "escaped trigger names require manual review")
    if "workflow_run" in triggers:
        c.add("Medium", "workflow triggers on workflow_run", p, trigger_line(text, "workflow_run"),
              category=CAT_BUILD, confidence="Suspected",
              impact="Runs with repository secrets after fork PR workflows; dangerous if it uses their artifacts or code",
              fix="Treat artifacts and head refs of the triggering run as untrusted data; never execute them")
    items = yaml_items(lines)
    by_start, owned = {x["start"]: x for x in items}, {}

    def own(st):
        """Row indices of a sequence item, without the items nested inside it."""
        if id(st) not in owned:
            rows, i = [], st["start"]
            while i < st["end"]:
                nested = by_start.get(i)
                if nested is not None and nested is not st:
                    i = max(nested["end"], i + 1)
                else:
                    rows.append(i)
                    i += 1
            owned[id(st)] = rows
        return owned[id(st)]

    import bisect
    steps = [x for x in items if "uses" in x["keys"] or "run" in x["keys"]]
    top = yaml_children(lines)
    jobs_entry = child(top, "jobs")
    jobs = [(e, yaml_children(lines, e[1] + 1, e[3]))
            for e in (yaml_children(lines, jobs_entry[1] + 1, jobs_entry[3]) if jobs_entry else [])]
    job_starts = [e[1] for e, _ in jobs]

    def job_of(row):
        k = bisect.bisect_right(job_starts, row) - 1
        return (jobs[k][0][1], jobs[k][0][3]) if k >= 0 and row < jobs[k][0][3] else None

    def run_rows(st):
        """(line number, text) of a run step; double-quoted YAML escapes decoded into lines."""
        rows = [(i + 1, lines[i]) for i in own(st) if i >= st["keys"]["run"][0]]
        if st["keys"]["run"][1].startswith('"'):
            decode = {"n": "\n", "t": "\t"}
            rows = [(n, part) for n, x in rows
                    for part in re.sub(r"\\(.)", lambda m: decode.get(m[1], m[1]), x).split("\n")]
        joined = []  # A shell line ending in `\` continues on the next row: one command, first row's number.
        for n, x in rows:
            if joined and joined[-1][1][-1].endswith("\\"):
                joined[-1][1][-1] = joined[-1][1][-1][:-1]
                joined[-1][1].append(x)
            else:
                joined.append((n, [x]))
        return [(n, " ".join(parts)) for n, parts in joined]

    head_checkout = False
    if privileged:
        top_rows = range(0, jobs_entry[1] if jobs_entry else len(lines))
        depth, in_step = [0] * (len(lines) + 1), bytearray(len(lines))
        for st in steps:
            depth[st["start"]] += 1
            depth[st["end"]] -= 1
        running = 0
        for i in range(len(lines)):
            running += depth[i]
            in_step[i] = running > 0

        def caller_level(value):
            """head_level of what privileged local callers pass for each inputs.X in value."""
            return max((head_level(given[name]) for name in (INPUT_USE.findall(value) if "inputs" in value else ())
                        for _, given, caller_privileged in callers if caller_privileged and name in given), default=0)

        def taint(value):
            return max(head_level(value), caller_level(value))

        def assigned(rows):
            """{name: level} of `name: value` rows, also quoted keys and one-line flow maps (env: {A: x})."""
            out, until = {}, 0
            for i in rows:
                if i < until:
                    continue  # inside a block scalar already read as a value
                m = re.match(r"""([ \t]*)(?:-[ \t]+)?["']?([A-Za-z_]\w*)["']?[ \t]*:[ \t]*["']?(.*)$""", lines[i])
                if m:
                    value = m[3]
                    if re.match(r"[|>][-+0-9]*[ \t]*(?:#.*)?$", value):  # block scalar: its lines are the value
                        k, body = i + 1, []
                        while k < len(lines) and (not lines[k].strip() or
                                                  len(lines[k]) - len(lines[k].lstrip()) > m.start(2)):
                            body.append(lines[k])
                            k += 1
                        value, until = "\n".join(body), k
                    pairs = flow_pairs(value).items() if value.lstrip().startswith("{") else ()
                    for name, v in [(m[2], value), *pairs]:
                        out[name] = max(out.get(name, 0), taint(v))
            return out

        workflow_env, job_env, job_names, written, outputs = assigned(top_rows), {}, {}, {}, {}

        def step_env(st, job, writes=True):
            """Env names holding the PR head for this step: step, then job, then workflow, then $GITHUB_ENV."""
            # One generic pattern plus set membership: no per-step regex compile or set copies.
            if job not in job_env:
                job_env[job] = dict(workflow_env, **(assigned(i for i in range(*job) if not in_step[i]) if job else {}))
            if (job, writes) not in job_names:
                names = job_names[job, writes] = dict(job_env[job])
                for k, v in written.get(job, {}).items() if writes else ():
                    names[k] = max(names.get(k, 0), v)
            step, names, shell = assigned(own(st)), job_names[job, writes], {}

            def env_level(x):
                out = 0
                for m in ENV_USE.finditer(x):
                    n = m[1] or m[2]
                    out = max(out, 2 if n == "GITHUB_HEAD_REF" else step[n] if n in step else names.get(n, 0),
                              shell.get(n, 0))
                    if out == 2:
                        break
                return out
            matcher = lambda x: counts(x, env_level(x))
            matcher.defined = lambda n: n in step or n in job_env[job]
            matcher.level, matcher.shell = env_level, shell
            return matcher

        for st in steps:  # $GITHUB_ENV / $GITHUB_OUTPUT writes of PR-head values, per job
            if "run" in st["keys"]:
                job, env_ref = job_of(st["start"]), None
                for _, x in run_rows(st):
                    for kind, name, value in github_writes(x) if "GITHUB_" in x else ():
                        env_ref = env_ref or step_env(st, job, writes=False)
                        bad = max(taint(value), env_ref.level(value))
                        bad = 2 if counts(value, bad) or head_value(value) else bad
                        if kind == "GITHUB_ENV":
                            written.setdefault(job, {})[name] = max(written.get(job, {}).get(name, 0), bad)
                        elif step_value(st, "id"):
                            outputs.setdefault(job, {})[(step_value(st, "id"), name)] = bad

        def ref_source(value, job, env_ref):
            """'head' when a checkout input is the PR head; else the unresolved sources it names."""
            if head_value(value) or env_ref(value) or counts(value, caller_level(value)):
                return "head"
            kinds = set()
            for sid, name in OUTPUT_USE.findall(value):
                if counts(value, outputs.get(job, {}).get((sid, name), 0)):
                    return "head"
                kinds.add("a step output")
            for name in INPUT_USE.findall(value):
                for _, given, caller_privileged in callers:
                    v = given.get(name, "")
                    if caller_privileged and "${{" in v and not HEAD_REF.search(v):
                        kinds.add("a caller's input")
            if re.search(r"\bneeds\.[\w-]+\.outputs\.", value):
                kinds.add("a job output")
            if re.search(r"\bmatrix\.", value):
                kinds.add("a matrix value")
            for name in re.findall(r"\benv\.([A-Za-z_]\w*)", value):
                if name in written.get(job, {}) or not env_ref.defined(name):
                    kinds.add("an environment variable")
            return kinds

        # Steps that execute their checkout: computed once, not per head checkout.
        executing, last_exec = {}, {}
        for n, x in enumerate(steps):
            if "run" in x["keys"]:
                script = "\n".join(lines[i] for i in own(x) if i >= x["keys"]["run"][0]).split(":", 1)[1]
                if EXECUTES_CHECKOUT.search(script):
                    executing.setdefault(x["parent"], []).append((n, "\n".join(lines[i] for i in own(x))))

        def executed_later(n, parent, path):
            if (parent, path) not in last_exec:
                last_exec[parent, path] = max((k for k, t in executing.get(parent, []) if not path or path in t),
                                              default=-1)
            return last_exec[parent, path] > n

        job_fetched = {}  # refs an earlier step of the job fetched from the PR head
        for n, st in enumerate(steps):
            job = job_of(st["start"])
            env_ref = step_env(st, job)
            uses = step_value(st, "uses")
            rows = own(st)
            body = [lines[i] for i in rows]
            hits = []
            # The PR head is only executed when a checkout step fetches it; the same
            # value passed to another action's ref/repository input is data.
            if re.match(r"actions/checkout@", uses, re.I):
                j = 0
                for k, i in enumerate(rows):
                    if k < j:
                        continue  # already read as part of a multi-line value
                    m = re.match(r"""\s*(?:-\s+)?(?:["']?with["']?\s*:\s*(\{.*)|["']?(?:ref|repository)["']?\s*:(.*))""", lines[i])
                    if not m:
                        continue
                    if m[1] is not None:  # flow mapping, possibly over several lines
                        parts, j = [strip_comment(m[1])], k + 1
                        depth = flow_depth(parts[0])  # running depth: each row is scanned once
                        while depth > 0 and j < len(rows):
                            parts.append(strip_comment(lines[rows[j]]).strip())
                            depth, j = depth + flow_depth(parts[-1]), j + 1
                        values = [v for key, v in flow_pairs(" ".join(parts)).items() if key in ("ref", "repository")]
                    else:  # plain, quoted or block scalar value, possibly continued on later lines
                        value, level, j = strip_comment(m[2]), len(lines[i]) - len(lines[i].lstrip()), k + 1
                        while j < len(rows) and (not lines[rows[j]].strip()
                                                 or len(lines[rows[j]]) - len(lines[rows[j]].lstrip()) > level):
                            value, j = value + "\n" + strip_comment(lines[rows[j]]), j + 1
                        values = [value]
                    for value in values:
                        source = ref_source(value, job, env_ref)
                        if source == "head":
                            hits.append(i + 1)
                            continue
                        for kind in sorted(source):
                            incomplete(c, "workflow scan", p, f"checkout ref from {kind} requires manual review")
                hits = list(dict.fromkeys(hits))
                title = f"{privileged} workflow checks out the pull request's code"
            elif "run" in st["keys"]:
                run = run_rows(st)
                untrusted = lambda x: (counts(x, taint(x)) or env_ref(x)
                                       or re.search(r"\bpull/[^\s/]*/(?:head|merge)\b", x)
                                       or any(counts(x, outputs.get(job, {}).get(o, 0)) for o in OUTPUT_USE.findall(x)))
                # Rows run in order: SHA=${{ …head.sha }} taints a later "$SHA" until SHA is
                # reassigned; fetching the PR head is data until a later row checks out,
                # resets or merges onto FETCH_HEAD, the fetched ref or a refspec target.
                fetched, hits = job_fetched.setdefault(job, set()), []
                # One row may hold several commands (`SHA=…; git checkout "$SHA"`, or an
                # inline `run: …`): each runs after the ones before it on the row.
                segments = [(k, seg) for k, row in run
                            for seg in re.split(r";|&&|\|\|", shell_text(re.sub(r"""^\s*(?:-\s+)?["']?run["']?\s*:\s*""", "", row)))]
                for k, x in segments:
                    if not hits and (re.search(r"\bgh\s+pr\s+checkout\b", x)
                                     or re.search(r"\bgh\s+repo\s+clone\b", x) and untrusted(x)):
                        hits = [k]
                    commands = git_commands(x)
                    for (sub, args), (_, kept) in zip(commands, moved_args(commands)):
                        if not hits and sub in GIT_MOVES and (untrusted(" ".join(kept))
                                                              or fetched & {branch(a) for a in kept}):
                            hits = [k]
                        if sub == "fetch" and untrusted(" ".join(args)):
                            fetched |= {"FETCH_HEAD"} | {branch(a.split(":", 1)[1]) for a in args if ":" in a}
                    a = "=" in x and SHELL_ASSIGN.match(x)
                    if a:
                        env_ref.shell[a[1]] = 2 if untrusted(a[2]) else max(taint(a[2]), env_ref.level(a[2]))
                title = f"{privileged} workflow checks out the pull request's code in a run step"
            for line in hits:
                head_checkout = True
                path = next((re.sub(r"\s+#.*", "", x.split(":", 1)[1]).strip().strip("'\"")
                             for x in body if re.match(r"\s*path\s*:", x)), "")
                runs = executed_later(n, st["parent"], path)
                c.add("High", title, p, line, category=CAT_BUILD, confidence="Confirmed" if runs else "Suspected",
                      impact="Fork authors' code runs with repository secrets and a write token (pwn request)"
                             + ("; a later step executes the checkout" if runs else ""),
                      fix="Use pull_request for building PR code, or never run anything from the checkout")
            # Artifacts of the triggering run: download actions with run-id, gh run download, github-script.
            if "workflow_run" in (privileged, *triggers) and (
                    re.match(r"[\w.-]+/[\w.-]*download-artifact@", uses, re.I)
                    and not (re.match(r"actions/download-artifact@", uses, re.I)
                             and not any(re.match(r"\s*run-id\s*:", x) for x in body))
                    or re.match(r"actions/github-script@", uses, re.I) and "downloadArtifact" in "\n".join(body)
                    or "run" in st["keys"] and any(re.search(r"\bgh\s+run\s+download\b", x) for _, x in run_rows(st))):
                c.add("Medium", "workflow_run workflow downloads artifacts from the triggering run", p,
                      (st["keys"].get("uses") or st["keys"]["run"])[0] + 1, category=CAT_BUILD, confidence="Suspected",
                      impact="A fork PR controls the artifact; executing or interpolating it runs with secrets",
                      fix="Extract to a temp dir, validate as data, never execute it or write it to GITHUB_ENV")
        hosted = {i for i, ln in enumerate(lines, 1) if re.match(r"""\s*runs-on\s*:.*\bself-hosted\b""", ln)}
        for _, props in jobs:  # also block lists and `labels:` under runs-on
            runs_on = child(props, "runs-on")
            if runs_on and any(re.search(r"\bself-hosted\b", re.sub(r"(?:^|\s)#.*", "", x))
                               for x in lines[runs_on[1]:runs_on[3]]):
                hosted.add(runs_on[1] + 1)
        for i in sorted(hosted):
            c.add("Medium", f"{privileged} job runs on a self-hosted runner", p, i, category=CAT_BUILD,
                  confidence="Suspected",
                  impact="Outsider-triggered jobs can persist on the runner host and its network",
                  fix="Use GitHub-hosted or ephemeral, isolated runners for outsider-triggered events")
    if "pull_request_target" in triggers and not head_checkout:
        c.add("Medium", "workflow triggers on pull_request_target", p, trigger_line(text, "pull_request_target"),
              category=CAT_BUILD, confidence="Suspected",
              impact="Runs with repository secrets on events from forks; dangerous if it checks out PR code",
              fix="Do not check out or execute PR code in this workflow")
    for i, ln in enumerate(lines, 1):
        if re.match(r"""\s*permissions\s*:\s*["']?write-all\b""", ln):
            c.add("Medium" if privileged else "Low", "workflow grants permissions: write-all", p, i,
                  category=CAT_BUILD, impact="Any compromised step can push code, releases and packages",
                  fix="Grant only the scopes each job needs, read-only by default")
    for _, props in jobs:  # `secrets: inherit` anywhere in the same job as the external `uses:`
        uses, secrets = child(props, "uses"), child(props, "secrets")
        m = uses and re.match(r"""["']?([\w.-]+/[\w.-]+/\.github/workflows/[^\s"'#]+)""", uses[2])
        if m and secrets and re.match(r"""["']?inherit\b""", secrets[2]):
            c.add("Medium", f"every secret is passed to external reusable workflow {m.group(1)}", p, uses[1] + 1,
                  category=CAT_BUILD, impact="A change in that repository can read all of this repository's secrets",
                  fix="Pass only the named secrets it needs and pin it to a commit SHA")
    images = []  # (line, image) of docker:// actions, job containers and service containers
    data = scalar_rows(lines)
    for i, ln in enumerate(lines, 1):
        # Only a YAML `uses:` key; comments, shell text and other block scalar text are not steps.
        m = not data[i - 1] and re.match(r"""^\s*(?:-\s+)?(?:\{\s*)?["']?uses["']?\s*:\s*([^\s#,}]+)""", ln)
        if m:
            ref = m.group(1).strip("'\"")
            if ref.startswith("docker://"):
                images.append((i, image_ref(ref[len("docker://"):])))
                continue
            if ref.startswith(("./", "$/")):
                continue
            owner = ref.split("/", 1)[0]
            if "@" not in ref:
                c.add("Medium", f"action {ref} has no version", p, i, category=CAT_BUILD,
                      impact="Runs whatever the default branch contains", fix="Pin to a full commit SHA")
            elif not re.search(r"@[0-9a-f]{40}$", ref):
                sev = "Low" if owner in ("actions", "github") else "Medium"
                c.add(sev, f"action {ref} is pinned to a mutable tag, not a commit SHA", p, i, category=CAT_BUILD,
                      impact="A moved or compromised tag changes the code that runs with your secrets",
                      fix="Pin to the full commit SHA and note the version in a comment")
    for job, props in jobs:
        container = child(props, "container")
        if container and container[2]:
            images.append((container[1] + 1, image_ref(container[2])))
        elif container:
            image = child(yaml_children(lines, container[1] + 1, container[3]), "image")
            if image:
                images.append((image[1] + 1, image_ref(image[2])))
        services = child(props, "services")
        for service in yaml_children(lines, services[1] + 1, services[3]) if services else []:
            image = child(yaml_children(lines, service[1] + 1, service[3]), "image")
            if image:
                images.append((image[1] + 1, image_ref(image[2])))
    for i, img in images:
        if unpinned_image(img, digest=True):
            c.add("Low", f"workflow container image {img} is not pinned to a digest", p, i, category=CAT_BUILD,
                  impact="A moved or replaced tag changes the container that runs with your secrets",
                  fix="Pin the image to its @sha256: digest")
    owner, envs = {}, {}  # row -> innermost item; scope -> env {name: value}
    for st in items:
        owner.update((i, st) for i in own(st))
    job_props = {(e[1], e[3]): props for e, props in jobs}

    def env_of(scope, entry, end):
        if scope not in envs:
            envs[scope] = mapping_values(lines, entry[0], entry[1], end) if entry else {}
        return envs[scope]

    taint_memo = {}  # One long env value can be referenced many times: parse it once.

    def tainted(path, value):
        key, memo = (str(path), value), taint_memo
        if key not in memo:
            memo[key] = any(untrusted_workflow_expression(c, path, e) for _, e in workflow_expressions(c, path, value))
        return memo[key]

    on = child(top, "on")
    call = on and child(yaml_children(lines, on[1] + 1, on[3]), "workflow_call")
    declared = child(yaml_children(lines, call[1] + 1, call[3]), "inputs") if call else child(top, "inputs")
    # A boolean or number input is coerced by GitHub, so caller text cannot reach the script.
    typed = {e[0] for e in (yaml_children(lines, declared[1] + 1, declared[3]) if declared else [])
             if re.match(r"""["']?(boolean|number)\b""", (child(yaml_children(lines, e[1] + 1, e[3]), "type")
                                                         or [None, 0, ""])[2])}

    def indirect(expression, row):
        """env.X resolved through step, job and workflow env maps; inputs.X through local callers."""
        for kind, name in re.findall(r"(?<![\w.])(env|inputs)\s*\.\s*([A-Za-z_][\w-]*)", expression):
            if kind == "inputs":
                if name not in typed and any(name in given and tainted(caller, given[name]) for caller, given, _ in callers):
                    return True
                continue
            st, job = owner.get(row), job_of(row)
            job_entry, top_entry = child(job_props.get(job, []), "env"), child(top, "env")
            for scope in ([env_of(("step", id(st)), st["keys"].get("env"), st["end"])] if st else []) + [
                    env_of(("job", job), job_entry and job_entry[1:3], job_entry and job_entry[3]),
                    env_of("workflow", top_entry and top_entry[1:3], len(lines))]:
                if name in scope:  # The innermost definition wins.
                    if tainted(p, scope[name]):
                        return True
                    break
        return False

    for block in workflow_run_blocks(c, p, text):
        script = "\n".join(line for _, line in block)
        scalar_start = next((line.lstrip() for _, line in block
                             if line.strip() and not line.lstrip().startswith("#")), "")
        if scalar_start.startswith("'"):
            # YAML single-quoted scalar: '' is one quote. Decoding keeps line
            # breaks, so expression offsets still map to source lines.
            script = script.replace("''", "'")
        if scalar_start.startswith('"') and (hiding_escape(script)
                                             or re.search(r"\$\{\{(?:(?!\}\}|\$\{\{).)*\\", script, re.S)):
            # YAML double-quoted scalars decode escapes before GitHub evaluates
            # expressions; raw text could hide both an opener and a source name.
            # Escapes elsewhere (\\n, \\t, \\") cannot form expression text.
            incomplete(c, "workflow run scan", p, "double-quoted run escapes require manual review")
            continue
        reported = set()
        seen_pos, seen_nl = 0, 0
        for start, expression in workflow_expressions(c, p, script):
            if untrusted_workflow_expression(c, p, expression) or indirect(expression, block[0][0] - 1):
                seen_nl += script.count("\n", seen_pos, start)
                seen_pos = start
                line = block[seen_nl][0]
                if line in reported:
                    continue
                reported.add(line)
                c.add("Medium", "untrusted event text interpolated into a workflow", p, line, category=CAT_BUILD,
                      impact="Text controlled by outsiders becomes part of a shell command",
                      fix="Pass it through an env variable and quote it")


def check_dockerfile(c, p):
    text = read(p)
    stages, args, seen_from = set(), {}, False
    for i, ln in enumerate(text.splitlines(), 1):
        a = re.match(r"\s*ARG\s+(\w+)=(\S+)", ln, re.I)
        if a and not seen_from:  # Only ARGs before the first FROM apply to FROM lines.
            args[a.group(1)] = a.group(2).strip("'\"")
        add = re.match(r"\s*ADD\s+(?:--\S+\s+)*(https?://\S+)", ln, re.I)
        if add and "--checksum=" not in ln:
            c.add("Low", "build downloads a remote file with ADD and no --checksum", p, i, category=CAT_BUILD,
                  impact="The image contains whatever the URL serves at build time",
                  fix="Add --checksum=sha256:... or download a pinned release and verify it")
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", ln, re.I)
        if m:
            seen_from = True
            img = re.sub(r"\$\{?(\w+)\}?", lambda v: args.get(v.group(1), v.group(0)), m.group(1))
            earlier_stage = img.lower() in stages
            if m.group(2):
                stages.add(m.group(2).lower())
            if earlier_stage or img.lower() == "scratch" or "$" in img or "@sha256:" in img:
                continue
            name = img.split("/")[-1]
            if ":" not in name or name.endswith(":latest"):
                c.add("Low", f"base image {img} is not pinned", p, i, category=CAT_BUILD,
                      impact="Rebuilds pull a different image", fix="Pin a version tag, ideally a digest")
        segments = ln.split("|")
        if any(re.match(r"\s*(sh|bash)\b", seg) and re.search(r"curl|wget", prev)
               for prev, seg in zip(segments, segments[1:])):
            c.add("Low", "remote script piped into a shell during build", p, i, category=CAT_BUILD,
                  impact="Build executes whatever the URL serves at that moment",
                  fix="Download a pinned version and verify its checksum")

COMPOSE_FILE = re.compile(r"(?:docker-)?compose(?:[.-][\w.-]+)?\.ya?ml$")


def check_compose(c, p):
    lines = read(p).splitlines()
    top = yaml_children(lines)
    services = child(top, "services")
    # Legacy (v1) files have no services: key; their services are top-level keys.
    # x-* extension fields are usually anchors merged into services (<<: *base).
    entries = yaml_children(lines, services[1] + 1, services[3]) if services else []
    for service in entries + [e for e in top if e not in entries and (not services or str(e[0]).startswith("x-"))]:
        props = yaml_children(lines, service[1] + 1, service[3])
        image = child(props, "image")
        if not image or child(props, "build"):
            continue  # With build:, image: names the locally built image.
        img = image_ref(image[2])
        if unpinned_image(img):
            c.add("Low", f"compose image {img} is not pinned", p, image[1] + 1, category=CAT_BUILD,
                  impact="Each pull can run a different image", fix="Pin a version tag, ideally a digest")


# ---------- inventory ----------

def packages_list(value):
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []


def inventory_composer_lock(c, p):
    _, data = load_json_object(c, p, "composer.lock inventory")
    if data is None:
        return
    pkgs = packages_list(data.get("packages")) + packages_list(data.get("packages-dev"))
    c.inventory.append({"ecosystem": "composer", "lockfile": c.rel(p), "packages": len(pkgs),
                        "notable": {x["name"]: x.get("version") for x in pkgs
                                    if x.get("name") in ("laravel/framework", "symfony/http-kernel",
                                                         "guzzlehttp/guzzle", "laravel/sanctum")},
                        "platform": mapping(data.get("platform"))})


def inventory_npm_lock(c, p):
    _, data = load_json_object(c, p, "package-lock.json inventory")
    if data is None:
        return
    n = len(mapping(data.get("packages")) or mapping(data.get("dependencies")))
    c.inventory.append({"ecosystem": "npm", "lockfile": c.rel(p), "packages": n})


def inventory_generic(c, p):
    eco = ECOSYSTEM.get(p.name) or {"yarn.lock": "npm", "pnpm-lock.yaml": "npm", "Gemfile.lock": "bundler",
                                    "go.sum": "go", "Cargo.lock": "cargo", "poetry.lock": "python",
                                    "uv.lock": "python", "Pipfile.lock": "python", "pdm.lock": "python",
                                    "bun.lock": "npm", "bun.lockb": "npm", "npm-shrinkwrap.json": "npm"}.get(p.name, "?")
    c.inventory.append({"ecosystem": eco, "lockfile": c.rel(p)})


# ---------- audit tools ----------

SEV_MAP = {"critical": "High", "high": "High", "moderate": "Medium", "medium": "Medium", "low": "Low",
           "info": "Info", "unknown": "Medium"}


def run(cmd, cwd, timeout=600, env=None):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env,
                           encoding="utf-8", errors="replace")
        return r.returncode, r.stdout, r.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return None, "", str(e)


def audit_json(c, tool, path, code, out, success_codes=(0, 1)):
    """Accept a result only after both process and envelope validation."""
    reason = ""
    if code not in success_codes:
        reason = f"unexpected exit {code}"
    else:
        try:
            data = json.loads(out)
        except (json.JSONDecodeError, TypeError):
            reason = "invalid or missing JSON output"
        else:
            if not isinstance(data, (dict, list)):
                reason = "unexpected JSON result type"
            elif isinstance(data, dict) and ("error" in data or data.get("errors")):
                reason = "audit returned an error object"
            else:
                return data
    c.not_run.append({"tool": tool, "reason": f"{c.rel(path)}: {reason}"})
    return None


REF_ORDER = {"advisory": 0, "fix": 1, "article": 2, "report": 3, "source": 4, "web": 5, "package": 6}


def dedupe_refs(refs, limit=8):
    seen, out = set(), []
    for r in sorted(refs, key=lambda r: REF_ORDER.get(r.get("type"), 9)):
        u = redact_urls(r.get("url", ""))
        if u and u not in seen and u.startswith(("https://", "http://")):
            seen.add(u)
            out.append({"type": r.get("type", "web"), "url": u, "title": redact_urls(r.get("title", ""))})
    return out[:limit]


def advisory_refs(ids):
    refs = []
    for i in ids:
        if not i:
            continue
        if i.startswith("GHSA-"):
            refs.append({"type": "advisory", "url": f"https://github.com/advisories/{i}", "title": i})
        elif i.startswith("CVE-"):
            refs.append({"type": "advisory", "url": f"https://nvd.nist.gov/vuln/detail/{i}", "title": i})
        elif i.startswith(("PKSA-",)):
            continue
        else:
            refs.append({"type": "advisory", "url": f"https://osv.dev/vulnerability/{i}", "title": i})
    return refs


def osv_refs(v):
    kinds = {"ADVISORY": "advisory", "FIX": "fix", "ARTICLE": "article", "REPORT": "report",
             "WEB": "web", "PACKAGE": "package", "EVIDENCE": "report", "INTRODUCED": "source"}
    refs = [{"type": "advisory", "url": f"https://osv.dev/vulnerability/{v.get('id')}", "title": v.get("id", "")}]
    for r in v.get("references") or []:
        url = r.get("url", "")
        kind = kinds.get(r.get("type"), "web")
        if "github.com" in url and "/commit/" in url:
            kind, title = "fix", "fix commit"
        elif "github.com" in url and "/pull/" in url:
            kind, title = "fix", "pull request"
        else:
            title = ""
        refs.append({"type": kind, "url": url, "title": title})
    return refs


def vuln(c, sev, pkg, version, ids, summary, path, tool, fixed="", refs=None):
    advisory_ids = sorted(set(i for i in ids if i))
    ids = ", ".join(advisory_ids)
    malicious = any(str(i).startswith("MAL-") for i in ids.split(", "))
    c.add("High" if malicious else SEV_MAP.get(str(sev).lower(), "Medium"),
          f"{'MALICIOUS package' if malicious else 'Vulnerable dependency'}: {pkg}"
          f"{' ' + version if version else ''} ({ids})",
          path, impact=summary or f"Reported by {tool}",
          fix=(f"Upgrade to {fixed}" if fixed else "Upgrade to a fixed version or remove the dependency"))
    c.findings[-1].update({"package": pkg, "version": version, "lockfile": c.rel(path), "malicious": malicious,
                           "references": dedupe_refs(refs or []), "advisory_ids": advisory_ids})
    c.findings[-1] = safe_output(c.findings[-1])


OSV_LOCKFILES = {"composer.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                 "Gemfile.lock", "go.mod", "Cargo.lock", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
                 "gradle.lockfile", "pom.xml", "pubspec.lock", "mix.lock", "packages.lock.json", "conan.lock", "bun.lock"}

# One registry drives inventory and the catch-all for unsupported audit inputs.
KNOWN_LOCKFILES = OSV_LOCKFILES | {name for names in LOCKS.values() for name in names} | {"go.sum"}


def osv_severity(v, group_sev):
    ms = group_sev.get(v.get("id"))
    if ms:
        try:
            s = float(ms)
            return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"
        except ValueError:
            pass
    return str((v.get("database_specific") or {}).get("severity") or "unknown").lower()


def osv_fixed(v, name):
    fixed = []
    for aff in v.get("affected") or []:
        if (aff.get("package") or {}).get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue  # A fixed commit hash is not a version to upgrade to.
            fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return ", ".join(dict.fromkeys(fixed))


def parse_osv(c, data, root, lock):
    """Validate one file's JSON result before granting audit coverage."""
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("OSV results must be a list")
    for res in data["results"]:
        source = res["source"]
        if not isinstance(source, dict) or not isinstance(source.get("path"), str):
            raise ValueError("missing OSV source")
        src = Path(source["path"])
        if not src.is_absolute():
            src = Path(root) / src
        if src.resolve() != Path(lock).resolve():
            raise ValueError("OSV returned a different source")
        if not isinstance(res.get("packages"), list):
            raise ValueError("OSV packages must be a list")
        for pk in res["packages"]:
            info = pk["package"]
            if (not isinstance(info, dict) or not isinstance(info.get("name"), str)
                    or not info["name"] or not isinstance(info.get("version", ""), str)):
                raise ValueError("invalid OSV package")
            groups = pk.get("groups", [])
            vulnerabilities = pk.get("vulnerabilities", [])
            if not isinstance(groups, list) or not isinstance(vulnerabilities, list):
                raise ValueError("invalid OSV groups/vulnerabilities")
            group_sev, group_of, reported = {}, {}, set()
            for number, g in enumerate(groups):
                ids, aliases = g.get("ids", []), g.get("aliases", [])
                if not isinstance(ids, list) or not isinstance(aliases, list):
                    raise ValueError("invalid OSV group IDs")
                for identifier in ids + aliases:
                    if not isinstance(identifier, str):
                        raise ValueError("invalid OSV group ID")
                    group_sev[identifier] = g.get("max_severity", "")
                    group_of[identifier] = number
            for v in vulnerabilities:
                if (not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"]
                        or not isinstance(v.get("summary", ""), str)):
                    raise ValueError("invalid OSV vulnerability")
                aliases = v.get("aliases", [])
                if not isinstance(aliases, list) or not all(isinstance(a, str) for a in aliases):
                    raise ValueError("invalid OSV aliases")
                # One finding per OSV group: GHSA/PYSEC/CVE records of one issue are aliases.
                group = group_of.get(v["id"])
                if group is not None and group in reported:
                    continue
                reported.add(group)
                ids = list(groups[group].get("ids", [])) if group is not None else []
                # Fix versions and references may sit on any alias record of the group.
                members = [v] + [x for x in vulnerabilities if x is not v and isinstance(x, dict)
                                 and group is not None and group_of.get(x.get("id")) == group]
                aliases = aliases + [a for x in members[1:] for a in x.get("aliases") or [] if isinstance(a, str)]
                malicious = [a for a in aliases + ids if a.startswith("MAL-")]
                aliases = sorted({a for a in aliases if a.startswith("CVE-")})[:2]
                fixed = ", ".join(dict.fromkeys(x for m in members for x in osv_fixed(m, info["name"]).split(", ") if x))
                refs = [r for m in members for r in osv_refs(m)]
                vuln(c, osv_severity(v, group_sev), info["name"], info.get("version", ""),
                     [v["id"]] + aliases + malicious + ids, v.get("summary", ""), lock, "osv-scanner",
                     fixed, refs)


def audit_osv(c, root, files):
    """Scan explicit files independently, using an auditor-owned empty config.

    A single-file invocation makes clean output attributable to that input;
    one malformed result must not mark other inputs as audited.
    """
    exe = shutil.which("osv-scanner")
    if not exe:
        c.not_run.append({"tool": "osv-scanner", "reason": "not installed"})
        return set()
    locks = [p for p in files if p.name in OSV_LOCKFILES or re.match(r"^requirements.*\.txt$", p.name)]
    covered = set()
    if not locks:
        return covered
    with tempfile.TemporaryDirectory(prefix="security-scan-osv-") as tmp:
        config = Path(tmp) / "osv-scanner.toml"
        # --config overrides per-directory configs, including package exclusions.
        config.write_text("# Independent audit: no vulnerability or package exclusions.\n", encoding="utf-8")
        for lock in locks:
            if not audit_input(c, root, lock):
                continue
            code, out, _ = run([exe, "scan", "source", "--format", "json",
                                "--config", str(config), "-L", str(lock)], root)
            data = audit_json(c, "osv-scanner", lock, code, out)
            if data is None:
                continue
            start = len(c.findings)
            try:
                parse_osv(c, data, root, lock)
                if (code == 1) != (len(c.findings) > start):
                    raise ValueError("OSV exit code disagrees with findings")
            except (ValueError, AttributeError, TypeError, KeyError, OSError, RuntimeError):
                del c.findings[start:]
                c.not_run.append({"tool": "osv-scanner", "reason": f"{c.rel(lock)}: "
                                  "invalid or inconsistent result schema"})
                continue
            covered.add(lock)
    return covered


def audit_composer(c, root, lock, abandoned_only=False):
    if not audit_input(c, root, lock, ("composer.json", "auth.json")):
        return
    exe = shutil.which("composer")
    if not exe:
        c.not_run.append({"tool": "composer audit", "reason": "composer not installed"})
        return
    result = isolated_composer_audit(c, root, lock, exe)
    if result is None:
        return
    code, out, err = result
    data = audit_json(c, "composer audit", lock, code, out, (0, 1, 2, 3))
    if data is None:
        return
    # PHP encodes an empty map as []; accept that, but not an absent result.
    if (not isinstance(data, dict) or "advisories" not in data
            or not (isinstance(data["advisories"], dict) or data["advisories"] == [])
            or not (isinstance(data.get("abandoned", {}), dict) or data.get("abandoned") == [])):
        c.not_run.append({"tool": "composer audit", "reason": f"{c.rel(lock)}: invalid result schema"})
        return
    if not all(isinstance(items, list) and all(isinstance(a, dict) for a in items)
               for items in (data["advisories"] or {}).values()):
        c.not_run.append({"tool": "composer audit", "reason": f"{c.rel(lock)}: invalid advisory entries"})
        return
    try:
        lockdata = json.loads(read(lock))
        installed = {x["name"]: x.get("version", "") for x in
                     packages_list(lockdata.get("packages")) + packages_list(lockdata.get("packages-dev"))
                     if isinstance(x.get("name"), str)}
    except (ValueError, RecursionError, AttributeError):
        installed = {}
    advisories = {} if abandoned_only else (data.get("advisories") or {})
    if isinstance(advisories, dict):
        for pkg, items in advisories.items():
            for a in items:
                summary = a.get("title", "")
                if a.get("affectedVersions"):
                    summary += f" (affected: {a['affectedVersions']})"
                refs = advisory_refs([a.get("cve")])
                if a.get("link"):
                    refs.insert(0, {"type": "advisory", "url": a["link"], "title": a.get("advisoryId", "")})
                for src_ in a.get("sources") or []:
                    if src_.get("name") == "GitHub" and str(src_.get("remoteId", "")).startswith("GHSA-"):
                        refs += advisory_refs([src_["remoteId"]])
                vuln(c, a.get("severity") or "unknown", pkg, installed.get(pkg, ""),
                     [a.get("cve"), a.get("advisoryId")], summary, lock, "composer audit", refs=refs)
    for pkg, info in (data.get("abandoned") or {}).items():
        c.add("Low", f"abandoned composer package {pkg}", lock,
              impact="No longer maintained; future flaws will not be fixed",
              fix=f"Replace with {info}" if info else "Replace with a maintained alternative")


def audit_npm(c, root, lock):
    if not audit_input(c, root, lock, ("package.json", ".npmrc")):
        return
    if lock.name not in ("package-lock.json", "npm-shrinkwrap.json"):
        c.not_run.append({"tool": "npm audit", "reason": f"{c.rel(lock)} is not an npm lockfile; use the matching package manager's audit"})
        return
    # npm's workspace selection is inherited from project/user configuration
    # and the environment. There is no supported CLI reset for that list, and
    # disabling workspaces would silently omit members of a shared lock. Keep
    # this fallback single-project only instead of claiming partial coverage.
    try:
        data = json.loads(lock.read_text(encoding="utf-8").lstrip("\ufeff"))
        manifest = lock.parent / "package.json"
        project = json.loads(manifest.read_text(encoding="utf-8").lstrip("\ufeff")) if manifest.exists() else {}
        if not isinstance(data, dict) or not isinstance(project, dict):
            raise ValueError("invalid npm input")
        packages = data.get("packages", {})
        if not isinstance(packages, dict) or not all(isinstance(v, dict) for v in packages.values()):
            raise ValueError("invalid npm lock packages")
        dependencies = data.get("dependencies", {})
        if not isinstance(dependencies, dict):
            raise ValueError("invalid npm lock dependencies")
        legacy = list(dependencies.values())
        linked = False
        while legacy:
            item = legacy.pop()
            if not isinstance(item, dict):
                raise ValueError("invalid npm lock dependency")
            linked = linked or bool(item.get("link")) or str(item.get("version", "")).startswith("file:")
            children = item.get("dependencies", {})
            if not isinstance(children, dict):
                raise ValueError("invalid npm nested dependencies")
            legacy.extend(children.values())
        if (linked or "workspaces" in project or "workspaces" in packages.get("", {})
                or any(v.get("link") or (name and not name.startswith("node_modules/"))
                       for name, v in packages.items())):
            incomplete(c, "npm audit", lock,
                       "workspace or linked-package lock requires osv-scanner; "
                       "npm fallback cannot guarantee whole-lock coverage")
            return
    except (OSError, ValueError, UnicodeError, RecursionError):
        incomplete(c, "npm audit", lock, "could not validate single-project audit input")
        return
    exe = shutil.which("npm")
    if not exe:
        c.not_run.append({"tool": "npm audit", "reason": "npm not installed"})
        return
    result = isolated_npm_audit(c, lock, exe)
    if result is None:
        return
    code, out, err = result
    data = audit_json(c, "npm audit", lock, code, out)
    if data is None:
        return
    if (not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict)
            or not all(isinstance(v, dict) and isinstance(v.get("via"), list)
                       and all(isinstance(x, (str, dict)) for x in v["via"])
                       for v in data["vulnerabilities"].values())
            or (code == 1 and not data["vulnerabilities"])):
        c.not_run.append({"tool": "npm audit", "reason": f"{c.rel(lock)}: invalid or inconsistent result schema"})
        return
    for name, v in (data.get("vulnerabilities") or {}).items():
        via = [x for x in v.get("via", []) if isinstance(x, dict)]
        if not via:
            continue  # transitive-only entry; the root advisory is reported on its own package
        ids = [str(x.get("url", "")).rsplit("/", 1)[-1] for x in via]
        fix = v.get("fixAvailable")
        fixed = f"{fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict) else ""
        refs = [{"type": "advisory", "url": x.get("url", ""), "title": x.get("title", "")} for x in via]
        vuln(c, v.get("severity", "unknown"), name, "", ids,
             f"{via[0].get('title', '')} (affected: {v.get('range', '')})", lock, "npm audit", fixed, refs)


def isolated_npm_audit(c, lock, exe):
    """Audit a copy of the lock against the public registry with no repo/user npm config.

    A project .npmrc (or inherited npm_config_* variables) could otherwise point
    the advisory request at a server that answers "no vulnerabilities".
    """
    try:
        with tempfile.TemporaryDirectory(prefix="security-scan-npm-") as tmp:
            work = Path(tmp)
            (work / "package-lock.json").write_bytes(lock.read_bytes())
            manifest = lock.parent / "package.json"
            if manifest.exists():
                (work / "package.json").write_bytes(manifest.read_bytes())
            # Two files: npm 10 refuses to load one file as both user and global config.
            user, globalconfig = work / "empty-user-npmrc", work / "empty-global-npmrc"
            user.write_text("", encoding="utf-8")
            globalconfig.write_text("", encoding="utf-8")
            env = {k: v for k, v in os.environ.items() if not k.lower().startswith("npm_config_")}
            env.update({"npm_config_cache": str(work / "cache"), "npm_config_update_notifier": "false"})
            return run([exe, "audit", "--json", "--package-lock-only",
                        "--include=prod", "--include=dev", "--include=optional",
                        "--include=peer", "--ignore-scripts", "--package-lock=true",
                        "--registry=https://registry.npmjs.org/",
                        "--userconfig=" + str(user), "--globalconfig=" + str(globalconfig),
                        "--workspaces=null", "--prefix=" + str(work)], work, env=env)
    except (OSError, ValueError):
        incomplete(c, "npm audit", lock, "could not prepare isolated audit input")
        return None


def audit_simple(c, root, tool, cmd, cwd, parse, target=None):
    target = target or cwd
    exe = shutil.which(cmd[0])
    if not exe:
        c.not_run.append({"tool": tool, "reason": f"{c.rel(target)}: {cmd[0]} not installed"})
        return
    code, out, err = run([exe] + cmd[1:], cwd)
    data = audit_json(c, tool, target, code, out)
    if data is None:
        return
    start = len(c.findings)
    try:
        parse(c, data, cwd)
        if code == 1 and len(c.findings) == start:
            raise ValueError("nonzero audit without findings")
    except (ValueError, AttributeError, TypeError, KeyError):
        del c.findings[start:]
        c.not_run.append({"tool": tool, "reason": f"{c.rel(target)}: invalid or inconsistent result schema"})


def parse_pip_audit(c, data, cwd):
    dependencies = data if isinstance(data, list) else data.get("dependencies") if isinstance(data, dict) else None
    if not isinstance(dependencies, list):
        raise ValueError("pip-audit dependencies must be a list")
    for d in dependencies:
        if not isinstance(d, dict) or not isinstance(d.get("name"), str):
            raise ValueError("invalid pip-audit dependency")
        if d.get("skip_reason"):
            c.not_run.append({"tool": "pip-audit", "reason": f"{c.rel(cwd)}: a dependency was skipped"})
            continue
        if not isinstance(d.get("vulns"), list):
            raise ValueError("pip-audit vulns must be a list")
        for v in d["vulns"]:
            if not isinstance(v, dict) or not isinstance(v.get("id"), str):
                raise ValueError("invalid pip-audit vulnerability")
            ids = [v["id"]] + v.get("aliases", [])[:2]
            vuln(c, "unknown", d["name"], d.get("version", ""), ids,
                 v.get("description", "")[:200], cwd, "pip-audit", ", ".join(v.get("fix_versions", [])),
                 advisory_refs(ids))


def parse_cargo_audit(c, data, cwd):
    if (not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), dict)
            or not isinstance(data["vulnerabilities"].get("list"), list)):
        raise ValueError("cargo audit vulnerabilities.list must be a list")
    for v in (data.get("vulnerabilities") or {}).get("list", []):
        a, pk = v.get("advisory", {}), v.get("package", {})
        refs = advisory_refs([a.get("id")]) + ([{"type": "web", "url": a["url"]}] if a.get("url") else [])
        vuln(c, "unknown", pk.get("name"), pk.get("version", ""), [a.get("id")], a.get("title", ""),
             cwd / "Cargo.lock", "cargo audit", ", ".join((v.get("versions") or {}).get("patched", [])), refs)


PINNED_REQUIREMENT = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)")


def audit_requirements(c, root, path):
    """Audit only explicit pins, never resolve dependencies or execute package code.

    Deliberately reject includes, options, URLs, markers, extras and wildcards.
    A temporary normalized input also prevents the original file changing into
    executable input between validation and invocation.
    """
    if not audit_input(c, root, path):
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        c.not_run.append({"tool": "pip-audit", "reason": f"{c.rel(path)}: cannot read requirements"})
        return
    pins = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = PINNED_REQUIREMENT.fullmatch(line)
        if not match:
            c.not_run.append({"tool": "pip-audit", "reason": f"{c.rel(path)}: only plain name==version pins "
                              "are supported safely; use osv-scanner for this input"})
            return
        pins.append("==".join(match.groups()))
    with tempfile.TemporaryDirectory(prefix="security-scan-pins-") as tmp:
        normalized = Path(tmp) / "requirements.txt"
        normalized.write_text("\n".join(pins) + "\n", encoding="utf-8")
        # Keep the reported finding location at the original file, not the temp input.
        def parse(c, data, cwd):
            parse_pip_audit(c, data, path)
        audit_simple(c, root, "pip-audit",
                     ["pip-audit", "-f", "json", "--no-deps", "--disable-pip", "-r", str(normalized)],
                     Path(tmp), parse, target=path)


def audits(c, root, files):
    # The top-level walk rejects links. Recheck operands immediately before use.
    files = [p for p in files if audit_input(c, root, p)]
    covered = audit_osv(c, root, files)
    # Ecosystem tools fill what osv-scanner did not cover; composer audit also
    # reports abandoned packages, which OSV does not.
    for p in files:
        if p.name == "composer.lock":
            audit_composer(c, root, p, abandoned_only=p in covered)
        elif p.name in ("package-lock.json", "npm-shrinkwrap.json") and p not in covered:
            audit_npm(c, root, p)
        elif p.name in ("yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb") and p not in covered:
            tool = {"yarn.lock": "yarn npm audit (Berry) / yarn audit (v1)", "pnpm-lock.yaml": "pnpm audit",
                    "bun.lock": "bun audit", "bun.lockb": "bun audit"}[p.name]
            c.not_run.append({"tool": tool, "reason": f"{c.rel(p)} not audited; run it in that directory "
                                                      "or install osv-scanner"})
        elif is_requirements(p, ("txt",)) and p not in covered:
            audit_requirements(c, root, p)
        elif p.name in ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock") and p not in covered:
            c.not_run.append({"tool": "Python lockfile audit", "reason": f"{c.rel(p)}: requires osv-scanner; "
                              "the scanner's Python environment is never used as a substitute"})
        elif p.name == "Cargo.lock" and p not in covered:
            incomplete(c, "cargo audit", p,
                       "automatic Cargo fallback is disabled for read-only safety; requires osv-scanner")
        elif p.name == "Gemfile.lock" and p not in covered:
            c.not_run.append({"tool": "bundle-audit", "reason": "run `bundle-audit check --update` manually; no JSON parser here"})
        elif p.name == "go.sum":
            if p.parent / "go.mod" not in covered:
                c.not_run.append({"tool": "govulncheck", "reason": "run `govulncheck ./...` in the module manually"})
        elif p not in covered and (p.name in KNOWN_LOCKFILES or p.name in ECOSYSTEM
                                    or is_requirements(p, ("in",))):
            if not declares_dependencies(p):
                continue
            if p.name in LOCKS:
                associated = matching_lockfiles(c, p)
                if associated is None or any(lock in files for lock in associated):
                    continue  # Matching lock is audited/not_run, or ownership is incomplete.
            c.not_run.append({"tool": "dependency audit", "reason": f"{c.rel(p)}: "
                              "no supported audit completed for this input"})


# ---------- validation (triage) of dependency findings ----------

CODE_EXT = {".php", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".py", ".rb", ".go", ".rs",
            ".java", ".kt", ".scala"}


def source_index(root):
    """Text of first-party source files (no vendored code, no manifests)."""
    texts = []
    for f in walk(root):
        if f.suffix in CODE_EXT or f.name.endswith(".blade.php"):
            try:
                if f.stat().st_size <= 1_000_000:
                    texts.append(read(f))
            except OSError:
                pass
    return texts


def lock_context(lock):
    """For a lockfile: runtime/dev package sets, direct dependencies, and code needles per package."""
    ctx = {"runtime": set(), "dev": set(), "direct": set(), "needles": {}}
    lock = Path(lock)
    def load(path):
        try:
            value = json.loads(read(path).lstrip("\ufeff"))
        except (ValueError, RecursionError):
            return {}
        return value if isinstance(value, dict) else {}

    if lock.name == "composer.lock":
        data = load(lock)
        for key, bucket in (("packages", "runtime"), ("packages-dev", "dev")):
            for x in packages_list(data.get(key)):
                if not isinstance(x.get("name"), str):
                    continue
                ctx[bucket].add(x["name"])
                ns = []
                for kind in ("psr-4", "psr-0"):
                    ns += [n.rstrip("\\") for n in mapping(mapping(x.get("autoload")).get(kind)) if n.strip("\\")]
                ctx["needles"][x["name"]] = [n + "\\" for n in ns]
        man = load(lock.parent / "composer.json")
        ctx["direct"] = set(mapping(man.get("require"))) | set(mapping(man.get("require-dev")))
        return ctx
    # npm-family lockfiles: direct dependencies and dev flags from package.json
    man = load(lock.parent / "package.json")
    prod = set(mapping(man.get("dependencies"))) | set(mapping(man.get("optionalDependencies")))
    dev = set(mapping(man.get("devDependencies")))
    ctx["direct"] = prod | dev
    ctx["runtime"] |= prod
    ctx["dev"] |= dev
    if lock.name == "package-lock.json":
        for k, v in mapping(load(lock).get("packages")).items():
            name = k.rsplit("node_modules/", 1)[-1]
            if name and isinstance(v, dict):
                (ctx["dev"] if v.get("dev") else ctx["runtime"]).add(name)
    return ctx


def npm_import(name):
    """Import forms of an npm package: require/import calls, static imports, test mocks."""
    target = r"""\s*['"`]""" + re.escape(name) + r"""['"`/]"""
    return re.compile(r"(?:\brequire(?:\.resolve)?|\bimport|\bjest\.(?:mock|requireActual))\s*\(" + target
                      + r"|\b(?:from|import)" + target)


_IMPORT_SITE = re.compile(r"""(?=(?:\brequire(?:\.resolve)?|\bimport|\bjest\.(?:mock|requireActual))\s*\(\s*['"`]([^'"`]{0,257})"""
                          r"""|\b(?:from|import)\s*['"`]([^'"`]{0,257}))""")
_QUOTE_SITE = re.compile(r"""(?=(['"`])([^'"`]{0,257}))""")


def npm_index(texts):
    """One pass: every name npm_import() could match, and every quoted name form."""
    imports, quoted = set(), set()
    for t in texts:
        for m in _IMPORT_SITE.finditer(t):
            run = m[1] if m[1] is not None else m[2]
            end = m.end(1) if m[1] is not None else m.end(2)
            if len(run) <= 256 and t[end:end + 1] in ("'", '"', "`"):
                imports.add(run)
            imports.update(run[:j] for j, ch in enumerate(run) if ch == "/" and j <= 256)
        for m in _QUOTE_SITE.finditer(t):
            q, run, end = m[1], m[2], m.end(2)
            if len(run) <= 256 and t[end:end + 1] == q:
                quoted.add(q + run + q)
            quoted.update(q + run[:j] + "/" for j, ch in enumerate(run) if ch == "/" and j <= 256)
    return imports, quoted


def npm_referenced(name, texts, index=None):
    """yes for an import form; unknown when the quoted name appears another way; else no."""
    if index is not None and name and len(name) <= 256 and not any(q in name for q in "'\"`"):
        imports, quoted = index
        if name in imports:
            return "yes"
        forms = [q + name + q for q in ("'", '"', "`")] + [q + name + "/" for q in ("'", '"', "`")]
        return "unknown" if any(n in quoted for n in forms) else "no"
    pattern = npm_import(name)
    if any(pattern.search(t) for t in texts):
        return "yes"
    quoted = [q + name + q for q in ("'", '"', "`")] + [q + name + "/" for q in ("'", '"', "`")]
    return "unknown" if any(n in t for t in texts for n in quoted) else "no"


def triage(c, root):
    deps = [f for f in c.findings if f.get("package")]
    if not deps:
        return
    texts = source_index(root)
    index = None
    ctxs = {}
    for f in deps:
        lock = str(Path(root) / f["lockfile"])
        if lock not in ctxs:  # setdefault() would re-parse the lockfile per finding
            ctxs[lock] = lock_context(lock)
        ctx = ctxs[lock]
        name = f["package"]
        if name in ctx["dev"] and name not in ctx["runtime"]:
            exposure = "dev-only"
        elif name in ctx["runtime"]:
            exposure = "runtime"
        else:
            exposure = "unknown"
        direct = "direct" if name in ctx["direct"] else ("transitive" if ctx["direct"] else "unknown")
        npm_family = Path(lock).name in LOCKS["package.json"]
        # Other ecosystems have no needle model: report "unknown", never a false "no".
        needles = ctx["needles"].get(name)
        if needles:
            referenced = "yes" if any(n in t for t in texts for n in needles) else "no"
        elif npm_family:
            if index is None:
                index = npm_index(texts)
            referenced = npm_referenced(name, texts, index)
        else:
            referenced = "unknown"
        if f.get("malicious"):
            verdict = "Likely"
            why = "malicious-package report: treat as valid until removed"
        elif exposure == "runtime" and (direct == "direct" or referenced == "yes"):
            verdict = "Likely"
            why = "installed for runtime and used by the application"
        elif exposure == "dev-only" and referenced != "yes":
            verdict = "Unlikely"
            why = "development-only and not imported by application code; build/CI exposure remains"
        else:
            verdict = "Unverified"
            why = "reachability not established automatically"
        f["validation"] = {
            "verdict": verdict,
            "evidence": (f"auto-triage: {why}. exposure={exposure}, dependency={direct}, "
                         f"referenced-in-source={referenced}. Confirm the vulnerable function or "
                         f"configuration is actually used before marking Valid or NotApplicable."),
            "exposure": exposure, "dependency": direct, "referenced": referenced, "method": "auto"}


# ---------- main ----------

def dependency_file(name):
    """A manifest or lockfile name this scanner knows."""
    return name in LOCKS or name in ECOSYSTEM or name in KNOWN_LOCKFILES or is_requirements(name)


def scan_input(name):
    return (dependency_file(name) or name in SOURCE_CONFIGS or name.startswith("Dockerfile")
            or name.endswith((".Dockerfile", ".yml", ".yaml")))


def pinned_count(p):
    """Packages a lockfile (or == pins of a requirements file) records; None when not counted."""
    text = read(p)
    if p.name in ("composer.lock", "Pipfile.lock", "package-lock.json", "npm-shrinkwrap.json"):
        try:
            data = json.loads(text.lstrip("\ufeff"))
        except (ValueError, RecursionError):
            return None
        if not isinstance(data, dict):
            return None
        if p.name == "composer.lock":
            return len(packages_list(data.get("packages")) + packages_list(data.get("packages-dev")))
        if p.name == "Pipfile.lock":
            return len(mapping(data.get("default"))) + len(mapping(data.get("develop")))
        return len([k for k in mapping(data.get("packages")) if k]) or len(mapping(data.get("dependencies")))
    if p.name in ("Cargo.lock", "poetry.lock", "uv.lock", "pdm.lock"):
        return len(re.findall(r"^\[\[package\]\]", text, re.M))
    if p.name == "Gemfile.lock":
        return len(re.findall(r"^    \S+ \(", text, re.M))
    if p.name == "gradle.lockfile":
        return len(re.findall(r"^[^#\s=:]+:[^#\s=:]+:[^#\s=]+=", text, re.M))
    if p.name == "go.sum":
        return len({tuple(x.split()[:2]) for x in text.splitlines() if len(x.split()) == 3 and "/go.mod" not in x.split()[1]})
    if p.name == "yarn.lock":
        return len(re.findall(r'^(?!__metadata)[^\s#][^\n]*:[ \t]*$', text, re.M))
    if p.name == "pnpm-lock.yaml":
        packages = child(yaml_children(text.splitlines()), "packages")
        return len(yaml_children(text.splitlines(), packages[1] + 1, packages[3])) if packages else 0
    if is_requirements(p, ("txt",)):
        return sum(1 for x in text.splitlines() if PINNED_REQUIREMENT.match(x.split("#", 1)[0].strip()))
    return None


def scan(root, audit):
    root = Path(root).resolve()
    c = Collector(root)
    _OVERSIZED.clear()
    files = sorted(walk(root, c.not_run))
    privileged = privileged_workflows(files, root)
    # A privileged workflow's local action under a pruned directory (build/, dist/)
    # still runs with its secrets, so it is scanned too.
    files += sorted(set(privileged) - set(files))
    calls = local_calls(files, root, privileged)
    for p in files:
        n = p.name
        if n in LOCKS:
            check_lockfile(c, p)
        if n == "package.json":
            check_npm(c, p)
        elif n in ("package-lock.json", "yarn.lock", "npm-shrinkwrap.json", "pnpm-lock.yaml"):
            check_npm_lock(c, p)
        elif n == ".npmrc" or n == ".yarnrc" or n == ".yarnrc.yml":
            check_npmrc(c, p)
        elif n == "composer.json":
            check_composer(c, p)
        elif is_requirements(p):
            check_requirements(c, p)
        elif n == "Gemfile":
            check_gemfile(c, p)
        elif n == "go.mod":
            check_gomod(c, p)
        elif n.startswith("Dockerfile") or n.endswith(".Dockerfile"):
            check_dockerfile(c, p)
        elif is_workflow(p) or n in ("action.yml", "action.yaml"):
            check_workflow(c, p, privileged.get(p.resolve()), calls)
        elif COMPOSE_FILE.fullmatch(n):
            check_compose(c, p)
        if n in SOURCE_CONFIGS or p.parent.name == ".cargo" and n in ("config", "config.toml"):
            check_source_transport(c, p)
            check_extra_sources(c, p)
        if n == "composer.lock":
            inventory_composer_lock(c, p)
        elif n == "package-lock.json":
            inventory_npm_lock(c, p)
        elif n in KNOWN_LOCKFILES:
            inventory_generic(c, p)
    if audit:
        audits(c, root, files)
        triage(c, root)
    else:
        counts = [pinned_count(p) for p in files if p.name in KNOWN_LOCKFILES - {"go.mod", "pom.xml"}
                  or is_requirements(p, ("txt",))]
        c.not_run.append({"tool": "vulnerability audit", "reason": "not requested (--audit); advisories not matched "
                          f"for {sum(x for x in counts if x)} pinned packages"
                          + (f" (+{counts.count(None)} lockfiles not counted)" if None in counts else "")})
    for path in sorted(_OVERSIZED):
        if path == root or root in path.parents:
            incomplete(c, "file scan", path, f"larger than {MAX_READ >> 20} MiB; not read")
    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    def location_key(f):
        path, _, line = f["location"].rpartition(":")
        return (path, int(line)) if path and line.isdigit() else (f["location"], 0)

    c.findings.sort(key=lambda f: (rank[f["severity"]], location_key(f)))
    for i, f in enumerate(c.findings, 1):
        f["id"] = f"D-{i:03d}"
    return safe_output({"inventory": c.inventory, "findings": c.findings, "not_run": c.not_run})


def finding_key(f):
    """Identity is project/path-specific; display IDs are not stable across scans."""
    location = os.path.normpath(str(f.get("location", "")).replace("\\", "/")).replace(os.sep, "/")
    return (location, f.get("package"), f.get("version"), f.get("title"),
            tuple(sorted(f.get("advisory_ids") or [])))


def merge_into(path, result, audit=None):
    """Replace D-* findings in path under the shared writer lock, atomically."""
    original = Path(path).read_bytes()
    try:
        data = json.loads(original.decode("utf-8"))
    except RecursionError:
        raise ValueError("findings file is nested too deeply") from None
    if not isinstance(data, dict):
        raise ValueError("findings file must hold a JSON object")
    if not isinstance(data.get("findings", []), list) or not all(isinstance(f, dict) for f in data.get("findings", [])):
        raise ValueError("findings must be a list of objects")
    if not isinstance(data.get("limitations", []), list):
        raise ValueError("limitations must be a list")
    old = [f for f in data.get("findings", []) if str(f.get("id", "")).startswith("D-")]
    # Never silently reuse a reachability decision after code/config changes.
    # Keep a matching review as history, requiring revalidation on every scan.
    kept = {}
    for f in old:
        val = f.get("validation") if isinstance(f.get("validation"), dict) else {}
        previous = val if val and val.get("method") != "auto" else f.get("previous_validation")
        if previous:
            kept[finding_key(f)] = previous
    for f in result["findings"]:
        previous = kept.get(finding_key(f))
        if previous:
            f["previous_validation"] = previous
            f.setdefault("validation", {"verdict": "Unverified", "method": "auto",
                                        "evidence": "Re-scan: previous manual review needs revalidation."})
    data["findings"] = [f for f in data.get("findings", []) if not str(f.get("id", "")).startswith("D-")]
    # Sanitize only what this scan writes: other findings (for example an F-*
    # request URL that is the attack payload) are the assessor's record.
    data["findings"] += safe_output(result["findings"])
    lim = [x for x in data.get("limitations", []) if not str(x).startswith("Dependency audit not run:")]
    lim += safe_output([f"Dependency audit not run: {n['tool']} - {n['reason']}" for n in result["not_run"]])
    data["limitations"] = lim
    # contract_check.py compares this with the D-* count to reject hand-written D-* findings.
    data["dependency_scan"] = {"tool": "deps_scan.py", "audit": audit,
                               "findings": len(result["findings"]), "not_run": len(result["not_run"])}
    # Same lock and compare-and-replace as findings.py merge.
    write_report(Path(path), data, original)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("--audit", action="store_true", help="also run installed vulnerability audit tools")
    p.add_argument("--strict", action="store_true", help="exit 3 if any audit was not completed (requires --audit)")
    p.add_argument("--out", help="write the result JSON here (default: stdout)")
    p.add_argument("--into", help="replace D-* findings in this findings.json with the new ones")
    a = p.parse_args(argv)
    if a.strict and not a.audit:
        p.error("--strict requires --audit")
    root = os.path.abspath(a.repo)
    if not os.path.isdir(root):
        print(f"deps_scan.py: {a.repo} is not a directory", file=sys.stderr)
        return 2
    result = safe_output(scan(root, a.audit))
    blob = json.dumps(result, ensure_ascii=False, indent=2)
    if a.out:
        try:
            Path(a.out).write_text(blob + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"deps_scan.py: cannot write {a.out}: {exc.strerror or exc}", file=sys.stderr)
            return 2
    elif not a.into:
        print(blob)
    if a.into:
        if not os.path.isfile(a.into):
            print(f"deps_scan.py: {a.into} missing; merge the first fragment with findings.py first",
                  file=sys.stderr)
            return 2
        try:
            merge_into(a.into, result, audit=a.audit)
        except RecursionError:
            print(f"deps_scan.py: {a.into}: findings file is nested too deeply", file=sys.stderr)
            return 2
        except (OSError, ValueError, MergeConflict) as exc:
            print(f"deps_scan.py: {a.into}: {exc}", file=sys.stderr)
            return 2
    counts = {}
    for f in result["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"deps_scan: {len(result['findings'])} findings {counts}, "
          f"{len(result['inventory'])} lockfiles, {len(result['not_run'])} not run", file=sys.stderr)
    return 3 if a.strict and result["not_run"] else 0


if __name__ == "__main__":
    sys.exit(main())
