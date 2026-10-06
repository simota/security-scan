#!/usr/bin/env python3
"""Inventory dependencies and flag supply-chain and known-vulnerability risks.

    python3 deps_scan.py REPO [--audit] [--out deps.json] [--into findings.json]

Static checks (always, no network):
  - manifests without a lockfile, unpinned or floating versions
  - dependencies fetched from git / URLs / local paths, non-default registries
  - extra package indexes (dependency-confusion exposure), install-time scripts
  - CI workflows: third-party actions not pinned to a commit SHA,
    pull_request_target triggers, untrusted event data inside run steps
  - container base images without a pinned tag or digest
--audit additionally runs whichever audit tools are installed
(osv-scanner, composer audit, npm audit, pip-audit, bundle-audit, govulncheck,
cargo audit) and converts their results into findings. These need network
access to vulnerability databases; a tool that is missing or fails is listed
under "not_run", never silently skipped.

Output: {"inventory": [...], "findings": [...], "not_run": [...]} with findings
in the findings.json shape. --into appends them to an existing findings.json.
Standard library only.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "dist", "build",
             "target", "__pycache__", ".next", ".nuxt", "bower_components", ".tox"}

LOCKS = {
    "package.json": ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json"],
    "composer.json": ["composer.lock"],
    "Gemfile": ["Gemfile.lock"],
    "go.mod": ["go.sum"],
    "Cargo.toml": ["Cargo.lock"],
    "pyproject.toml": ["poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock", "requirements.lock"],
    "Pipfile": ["Pipfile.lock"],
}
ECOSYSTEM = {"package.json": "npm", "composer.json": "composer", "Gemfile": "bundler", "go.mod": "go",
             "Cargo.toml": "cargo", "pyproject.toml": "python", "Pipfile": "python",
             "requirements.txt": "python", "pom.xml": "maven", "build.gradle": "gradle",
             "build.gradle.kts": "gradle"}

CAT_DEP = "Dependencies and platform"
CAT_BUILD = "Build and delivery"


class Collector:
    def __init__(self, root):
        self.root = root
        self.findings = []
        self.inventory = []
        self.not_run = []

    def rel(self, p):
        return os.path.relpath(p, self.root)

    def add(self, severity, title, path, line=None, impact="", fix="", confidence="Confirmed", category=CAT_DEP):
        loc = self.rel(path) + (f":{line}" if line else "")
        self.findings.append({
            "id": f"D-{len(self.findings) + 1:03d}", "title": title, "severity": severity,
            "confidence": confidence, "category": category, "location": loc, "actor": "",
            "request": "", "impact": impact, "fix": fix, "status": "Open"})


def walk(root):
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".cache")]
        for f in files:
            yield Path(d) / f


def line_of(text, needle):
    for i, ln in enumerate(text.splitlines(), 1):
        if needle in ln:
            return i
    return None


def read(p):
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------- per-ecosystem static checks ----------

def check_lockfile(c, p):
    locks = LOCKS.get(p.name)
    if locks and not any((p.parent / l).exists() for l in locks):
        c.add("Medium", f"{p.name} has no lockfile", p,
              impact="Each install may resolve different, possibly compromised, versions",
              fix=f"Commit one of: {', '.join(locks)}")


def check_npm(c, p):
    text = read(p)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            ln = line_of(text, f'"{name}"')
            if re.match(r"^(git(\+\w+)?:|github:|https?:|file:|link:)|^[\w.-]+/[\w.-]+(#.*)?$", spec):
                c.add("Medium", f"npm dependency {name} is fetched outside the registry ({spec})", p, ln,
                      impact="Bypasses registry integrity and advisory coverage; the source can change",
                      fix="Depend on a published, version-pinned release")
            elif spec in ("*", "latest", "") or spec.startswith(">") or spec == "x":
                c.add("Medium", f"npm dependency {name} floats to any version ({spec or 'empty'})", p, ln,
                      impact="A newly published malicious or broken release is installed automatically",
                      fix="Use a bounded range and the lockfile")
    for hook in ("preinstall", "install", "postinstall", "prepare"):
        if hook in (data.get("scripts") or {}):
            c.add("Info", f"package.json defines a '{hook}' lifecycle script", p, line_of(text, f'"{hook}"'),
                  impact="Runs automatically on install; review what it executes",
                  fix="Keep it minimal; consider installing with --ignore-scripts in CI", category=CAT_BUILD)


def check_npm_lock(c, p):
    text = read(p)
    hosts = set(re.findall(r'"resolved":\s*"https?://([^/"]+)', text)) | \
        set(re.findall(r'^\s+resolved\s+"https?://([^/"]+)', text, re.M))
    default = {"registry.npmjs.org", "registry.yarnpkg.com"}
    for h in sorted(hosts - default):
        c.add("Low", f"lockfile resolves packages from non-default host {h}", p, line_of(text, h),
              impact="Packages come from a registry outside the public one; confirm it is trusted",
              fix="Confirm the host is an approved internal mirror", confidence="Suspected")
    if "integrity" not in text and p.name == "package-lock.json":
        c.add("Low", "package-lock.json has no integrity hashes", p,
              impact="Tampered tarballs are not detected", fix="Regenerate the lockfile with a current npm")


def check_npmrc(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*(@[\w-]+:)?registry\s*=\s*(\S+)", ln)
        if m and "registry.npmjs.org" not in m.group(2):
            c.add("Info", f".npmrc points {m.group(1) or 'all packages'} at {m.group(2)}", p, i,
                  impact="Confirm the registry is trusted and scoped names cannot be claimed publicly",
                  fix="Scope private registries to your own @scope", category=CAT_BUILD)
        if re.search(r"_authToken\s*=\s*[^$\s]", ln):
            c.add("High", ".npmrc contains a literal registry token", p, i,
                  impact="Anyone with repository access can publish or read private packages",
                  fix="Remove it, rotate the token, use an environment variable", category="Secrets")


def check_composer(c, p):
    text = read(p)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if data.get("minimum-stability") in ("dev", "alpha", "beta", "RC") and not data.get("prefer-stable"):
        c.add("Low", f"composer minimum-stability is {data['minimum-stability']} without prefer-stable", p,
              line_of(text, "minimum-stability"), impact="Unstable releases may be installed",
              fix="Set prefer-stable: true or raise minimum-stability")
    for repo in data.get("repositories") or []:
        if isinstance(repo, dict) and repo.get("type") in ("vcs", "path", "package", "artifact"):
            c.add("Low", f"composer repository of type {repo.get('type')}: {repo.get('url', '')}", p,
                  line_of(text, '"repositories"'),
                  impact="Packages outside Packagist lack its advisory and integrity coverage",
                  fix="Prefer published releases; pin references", confidence="Suspected")
    plugins = (data.get("config") or {}).get("allow-plugins")
    if plugins is True:
        c.add("Medium", "composer allow-plugins is true for every package", p, line_of(text, "allow-plugins"),
              impact="Any dependency's plugin code runs during install",
              fix="List allowed plugins explicitly", category=CAT_BUILD)
    for section in ("require", "require-dev"):
        for name, spec in (data.get(section) or {}).items():
            if str(spec).strip() in ("*", "dev-master", "dev-main") or str(spec).startswith("dev-"):
                c.add("Medium", f"composer dependency {name} floats ({spec})", p, line_of(text, f'"{name}"'),
                      impact="Unreviewed code is pulled on update", fix="Require a tagged version range")


def check_requirements(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        s = ln.split("#", 1)[0].strip()
        if not s:
            continue
        if s.startswith("--extra-index-url"):
            c.add("Medium", "pip --extra-index-url mixes a second index with PyPI", p, i,
                  impact="A public package can shadow an internal one with the same name",
                  fix="Use a single index (a mirror that proxies PyPI) or pin hashes", category=CAT_BUILD)
        elif s.startswith("--index-url") or s.startswith("-i "):
            c.add("Info", f"pip index overridden: {s}", p, i, impact="Confirm the index is trusted",
                  category=CAT_BUILD)
        elif s.startswith("-") or s.startswith("."):
            continue
        elif re.match(r"^(git\+|https?://|hg\+|svn\+)", s) or " @ " in s:
            c.add("Medium", f"Python dependency fetched from a URL: {s}", p, i,
                  impact="Bypasses index integrity and advisory coverage", fix="Pin to a released version")
        elif "==" not in s and "--hash" not in s:
            c.add("Low", f"Python requirement not pinned: {s}", p, i,
                  impact="Installs whatever version is newest at install time",
                  fix="Pin with == (and --hash for reproducible installs) or use a lockfile")


def check_gemfile(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        if re.search(r"^\s*gem\s.*(git:|github:|path:)", ln):
            c.add("Medium", f"gem fetched outside rubygems: {ln.strip()}", p, i,
                  impact="Bypasses rubygems integrity and advisory coverage", fix="Use a released gem version")
        if re.search(r"^\s*source\s+['\"](?!https://rubygems\.org)", ln):
            c.add("Info", f"additional gem source: {ln.strip()}", p, i, impact="Confirm the source is trusted",
                  category=CAT_BUILD)


def check_gomod(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        if re.match(r"\s*replace\s", ln) and "=>" in ln and re.search(r"=>\s*\.{1,2}/", ln):
            c.add("Info", f"go.mod replaces a module with a local path: {ln.strip()}", p, i,
                  impact="Builds depend on code outside module verification", category=CAT_BUILD)


def check_workflow(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.search(r"uses:\s*([^\s#]+)", ln)
        if m:
            ref = m.group(1).strip("'\"")
            if ref.startswith("./") or ref.startswith("docker://"):
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
        if re.search(r"^\s*pull_request_target\s*:", ln) or re.search(r"on:\s*\[?.*pull_request_target", ln):
            c.add("Medium", "workflow triggers on pull_request_target", p, i, category=CAT_BUILD,
                  confidence="Suspected",
                  impact="Runs with repository secrets on events from forks; dangerous if it checks out PR code",
                  fix="Do not check out or execute PR code in this workflow")
        if "run:" in ln or ln.strip().startswith("- run") or re.match(r"^\s{2,}\S", ln):
            if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|commits)\b[^}]*(title|body|message|name|ref|label)", ln):
                c.add("Medium", "untrusted event text interpolated into a workflow", p, i, category=CAT_BUILD,
                      impact="Text controlled by outsiders becomes part of a shell command",
                      fix="Pass it through an env variable and quote it")


def check_dockerfile(c, p):
    text = read(p)
    for i, ln in enumerate(text.splitlines(), 1):
        m = re.match(r"\s*FROM\s+(?:--platform=\S+\s+)?(\S+)", ln, re.I)
        if m:
            img = m.group(1)
            if img.lower() == "scratch" or "$" in img or "@sha256:" in img:
                continue
            name = img.split("/")[-1]
            if ":" not in name or name.endswith(":latest"):
                c.add("Low", f"base image {img} is not pinned", p, i, category=CAT_BUILD,
                      impact="Rebuilds pull a different image", fix="Pin a version tag, ideally a digest")
        if re.search(r"(curl|wget)[^|\n]*\|\s*(sh|bash)", ln):
            c.add("Low", "remote script piped into a shell during build", p, i, category=CAT_BUILD,
                  impact="Build executes whatever the URL serves at that moment",
                  fix="Download a pinned version and verify its checksum")


# ---------- inventory ----------

def inventory_composer_lock(c, p):
    try:
        data = json.loads(read(p))
    except json.JSONDecodeError:
        return
    pkgs = data.get("packages", []) + data.get("packages-dev", [])
    c.inventory.append({"ecosystem": "composer", "lockfile": c.rel(p), "packages": len(pkgs),
                        "notable": {x["name"]: x.get("version") for x in pkgs
                                    if x.get("name") in ("laravel/framework", "symfony/http-kernel",
                                                         "guzzlehttp/guzzle", "laravel/sanctum")},
                        "platform": data.get("platform") or {}})


def inventory_npm_lock(c, p):
    try:
        data = json.loads(read(p))
    except json.JSONDecodeError:
        return
    n = len(data.get("packages") or data.get("dependencies") or {})
    c.inventory.append({"ecosystem": "npm", "lockfile": c.rel(p), "packages": n})


def inventory_generic(c, p):
    eco = ECOSYSTEM.get(p.name) or {"yarn.lock": "npm", "pnpm-lock.yaml": "npm", "Gemfile.lock": "bundler",
                                    "go.sum": "go", "Cargo.lock": "cargo", "poetry.lock": "python",
                                    "uv.lock": "python", "Pipfile.lock": "python"}.get(p.name, "?")
    c.inventory.append({"ecosystem": eco, "lockfile": c.rel(p)})


# ---------- audit tools ----------

SEV_MAP = {"critical": "High", "high": "High", "moderate": "Medium", "medium": "Medium", "low": "Low",
           "info": "Info", "unknown": "Medium"}


def run(cmd, cwd, timeout=600):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
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
        u = r.get("url")
        if u and u not in seen and u.startswith(("https://", "http://")):
            seen.add(u)
            out.append({"type": r.get("type", "web"), "url": u, "title": r.get("title", "")})
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
    c.findings[-1].update({"package": pkg, "version": version, "lockfile": str(path), "malicious": malicious,
                           "references": dedupe_refs(refs or []), "advisory_ids": advisory_ids})


OSV_LOCKFILES = {"composer.lock", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                 "Gemfile.lock", "go.mod", "Cargo.lock", "poetry.lock", "Pipfile.lock", "uv.lock", "pdm.lock",
                 "gradle.lockfile", "pom.xml", "pubspec.lock", "mix.lock", "packages.lock.json", "conan.lock"}


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
            fixed += [e["fixed"] for e in rng.get("events") or [] if "fixed" in e]
    return ", ".join(dict.fromkeys(fixed))


def audit_osv(c, root, files):
    """Scan each lockfile with osv-scanner. Returns the set of lockfiles it covered.

    Lockfiles are passed explicitly with -L: directory scanning is not used
    because some osv-scanner builds stop at the root without walking it.
    """
    exe = shutil.which("osv-scanner")
    if not exe:
        c.not_run.append({"tool": "osv-scanner",
                          "reason": "not installed (covers every ecosystem and OpenSSF malicious-package reports)"})
        return set()
    locks = [p for p in files if p.name in OSV_LOCKFILES or re.match(r"^requirements.*\.txt$", p.name)]
    if not locks:
        return set()
    cmd = [exe, "scan", "source", "--format", "json"]
    for p in locks:
        cmd += ["-L", str(p)]
    code, out, err = run(cmd, root)
    # 0 = clean, 1 = vulnerabilities found; anything else is a failure
    try:
        data = json.loads(out) if code in (0, 1) else None
    except json.JSONDecodeError:
        data = None
    if data is None:
        c.not_run.append({"tool": "osv-scanner", "reason": f"exit {code}: " + (err or "no JSON output").strip()[-300:]})
        return set()
    for res in data.get("results", []):
        src = Path(res.get("source", {}).get("path", root))
        for pk in res.get("packages", []):
            info = pk.get("package", {})
            group_sev = {}
            for g in pk.get("groups", []):
                for i in (g.get("ids") or []) + (g.get("aliases") or []):
                    group_sev[i] = g.get("max_severity", "")
            for v in pk.get("vulnerabilities", []):
                aliases = [a for a in (v.get("aliases") or []) if a.startswith("CVE-")][:2]
                vuln(c, osv_severity(v, group_sev), info.get("name"), info.get("version", ""),
                     [v.get("id")] + aliases, v.get("summary", ""), src, "osv-scanner",
                     osv_fixed(v, info.get("name")), osv_refs(v))
    return {Path(p) for p in locks}


def audit_composer(c, root, lock, abandoned_only=False):
    exe = shutil.which("composer")
    if not exe:
        c.not_run.append({"tool": "composer audit", "reason": "composer not installed"})
        return
    code, out, err = run([exe, "--no-plugins", "--no-scripts", "audit", "--format=json",
                          "--locked", "--no-interaction"], lock.parent)
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
                     lockdata.get("packages", []) + lockdata.get("packages-dev", [])}
    except (json.JSONDecodeError, KeyError):
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
    if lock.name != "package-lock.json":
        c.not_run.append({"tool": "npm audit", "reason": f"{c.rel(lock)} is not an npm lockfile; use the matching package manager's audit"})
        return
    exe = shutil.which("npm")
    if not exe:
        c.not_run.append({"tool": "npm audit", "reason": "npm not installed"})
        return
    code, out, err = run([exe, "audit", "--json", "--package-lock-only"], lock.parent)
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
    covered = audit_osv(c, root, files)
    # Ecosystem tools fill what osv-scanner did not cover; composer audit also
    # reports abandoned packages, which OSV does not.
    for p in files:
        if p.name == "composer.lock":
            audit_composer(c, root, p, abandoned_only=p in covered)
        elif p.name == "package-lock.json" and p not in covered:
            audit_npm(c, root, p)
        elif p.name in ("yarn.lock", "pnpm-lock.yaml", "bun.lockb") and p not in covered:
            tool = {"yarn.lock": "yarn npm audit (Berry) / yarn audit (v1)", "pnpm-lock.yaml": "pnpm audit",
                    "bun.lockb": "bun audit"}[p.name]
            c.not_run.append({"tool": tool, "reason": f"{c.rel(p)} not audited; run it in that directory "
                                                      "or install osv-scanner"})
        elif re.match(r"^requirements.*\.txt$", p.name) and p not in covered:
            audit_requirements(c, root, p)
        elif p.name in ("poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock") and p not in covered:
            c.not_run.append({"tool": "Python lockfile audit", "reason": f"{c.rel(p)}: requires osv-scanner; "
                              "the scanner's Python environment is never used as a substitute"})
        elif p.name == "Cargo.lock" and p not in covered:
            audit_simple(c, root, "cargo audit", ["cargo", "audit", "--json"], p.parent, parse_cargo_audit)
        elif p.name == "Gemfile.lock" and p not in covered:
            c.not_run.append({"tool": "bundle-audit", "reason": "run `bundle-audit check --update` manually; no JSON parser here"})
        elif p.name == "go.sum" and p.parent / "go.mod" not in covered:
            c.not_run.append({"tool": "govulncheck", "reason": "run `govulncheck ./...` in the module manually"})


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
    if lock.name == "composer.lock":
        try:
            data = json.loads(read(lock))
        except json.JSONDecodeError:
            return ctx
        for key, bucket in (("packages", "runtime"), ("packages-dev", "dev")):
            for x in data.get(key, []):
                ctx[bucket].add(x["name"])
                ns = []
                for kind in ("psr-4", "psr-0"):
                    ns += [n.rstrip("\\") for n in ((x.get("autoload") or {}).get(kind) or {}) if n.strip("\\")]
                ctx["needles"][x["name"]] = [n + "\\" for n in ns]
        try:
            man = json.loads(read(lock.parent / "composer.json"))
            ctx["direct"] = set((man.get("require") or {})) | set((man.get("require-dev") or {}))
        except json.JSONDecodeError:
            pass
        return ctx
    # npm-family lockfiles: direct dependencies and dev flags from package.json
    try:
        man = json.loads(read(lock.parent / "package.json"))
    except json.JSONDecodeError:
        man = {}
    prod = set(man.get("dependencies") or {}) | set(man.get("optionalDependencies") or {})
    dev = set(man.get("devDependencies") or {})
    ctx["direct"] = prod | dev
    ctx["runtime"] |= prod
    ctx["dev"] |= dev
    if lock.name == "package-lock.json":
        try:
            data = json.loads(read(lock))
            for k, v in (data.get("packages") or {}).items():
                name = k.rsplit("node_modules/", 1)[-1]
                if name:
                    (ctx["dev"] if v.get("dev") else ctx["runtime"]).add(name)
        except json.JSONDecodeError:
            pass
    return ctx


def npm_needles(name):
    return [f"'{name}'", f'"{name}"', f"'{name}/", f'"{name}/', f"`{name}`", f"`{name}/"]


def triage(c, root):
    deps = [f for f in c.findings if f.get("package")]
    if not deps:
        return
    texts = source_index(root)
    ctxs = {}
    for f in deps:
        lock = f["lockfile"]
        ctx = ctxs.setdefault(lock, lock_context(lock))
        name = f["package"]
        if name in ctx["dev"] and name not in ctx["runtime"]:
            exposure = "dev-only"
        elif name in ctx["runtime"]:
            exposure = "runtime"
        else:
            exposure = "unknown"
        direct = "direct" if name in ctx["direct"] else ("transitive" if ctx["direct"] else "unknown")
        needles = ctx["needles"].get(name) or ([] if Path(lock).name == "composer.lock" else npm_needles(name))
        referenced = "yes" if needles and any(n in t for t in texts for n in needles) else ("no" if needles else "unknown")
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

def scan(root, audit):
    c = Collector(root)
    files = sorted(walk(root))
    for p in files:
        n = p.name
        if n in LOCKS:
            check_lockfile(c, p)
        if n == "package.json":
            check_npm(c, p)
        elif n in ("package-lock.json", "yarn.lock", "npm-shrinkwrap.json"):
            check_npm_lock(c, p)
        elif n == ".npmrc" or n == ".yarnrc" or n == ".yarnrc.yml":
            check_npmrc(c, p)
        elif n == "composer.json":
            check_composer(c, p)
        elif re.match(r"^requirements.*\.(txt|in)$", n):
            check_requirements(c, p)
        elif n == "Gemfile":
            check_gemfile(c, p)
        elif n == "go.mod":
            check_gomod(c, p)
        elif n.startswith("Dockerfile") or n.endswith(".Dockerfile"):
            check_dockerfile(c, p)
        elif p.suffix in (".yml", ".yaml") and ".github/workflows" in str(p).replace(os.sep, "/"):
            check_workflow(c, p)
        if n == "composer.lock":
            inventory_composer_lock(c, p)
        elif n == "package-lock.json":
            inventory_npm_lock(c, p)
        elif n in ("yarn.lock", "pnpm-lock.yaml", "Gemfile.lock", "go.sum", "Cargo.lock", "poetry.lock",
                   "uv.lock", "Pipfile.lock"):
            inventory_generic(c, p)
    if audit:
        audits(c, root, files)
        triage(c, root)
    else:
        c.not_run.append({"tool": "vulnerability audit", "reason": "not requested (--audit)"})
    rank = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    c.findings.sort(key=lambda f: (rank[f["severity"]], f["location"]))
    for i, f in enumerate(c.findings, 1):
        f["id"] = f"D-{i:03d}"
    return {"inventory": c.inventory, "findings": c.findings, "not_run": c.not_run}


def finding_key(f):
    """Identity is project/path-specific; display IDs are not stable across scans."""
    location = os.path.normpath(str(f.get("location", "")).replace("\\", "/")).replace(os.sep, "/")
    return (location, f.get("package"), f.get("version"), f.get("title"),
            tuple(sorted(f.get("advisory_ids") or [])))


def merge_into(path, result):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    old = [f for f in data.get("findings", []) if str(f.get("id", "")).startswith("D-")]
    # Never silently reuse a reachability decision after code/config changes.
    # Keep a matching review as history, requiring revalidation on every scan.
    kept = {}
    for f in old:
        val = f.get("validation") or {}
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
    data["findings"] += result["findings"]
    lim = [x for x in data.get("limitations", []) if not x.startswith("Dependency audit not run:")]
    lim += [f"Dependency audit not run: {n['tool']} - {n['reason']}" for n in result["not_run"]]
    data["limitations"] = lim
    Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
    result = scan(root, a.audit)
    blob = json.dumps(result, ensure_ascii=False, indent=2)
    if a.out:
        Path(a.out).write_text(blob + "\n", encoding="utf-8")
    elif not a.into:
        print(blob)
    if a.into:
        merge_into(a.into, result)
    counts = {}
    for f in result["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print(f"deps_scan: {len(result['findings'])} findings {counts}, "
          f"{len(result['inventory'])} lockfiles, {len(result['not_run'])} not run", file=sys.stderr)
    return 3 if a.strict and result["not_run"] else 0


if __name__ == "__main__":
    sys.exit(main())
