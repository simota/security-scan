"""Bounded, read-only evidence byte checks and local Git-object association.

No application commands, network operations, worktree source reads, or repository
configuration are executed. Git only reads an auditor-owned temporary object
snapshot with an empty, fixed configuration. Receipts record observations, not
execution, authenticity, reviewer independence, or coverage. JSON receipts are
never accepted as live verification contexts.

Supported filesystems must provide POSIX dir_fd and O_NOFOLLOW semantics. Every
path component is held open and checked again; regular files must have exactly
one link and stable identity, size, mtime and ctime. This detects ordinary path
swaps and mutations, but is not a security boundary against a hostile kernel or
privileged adversary. Worktrees using a .git file, alternate object stores,
promisor packs, grafts and dirty source evidence are deliberately unsupported.
"""
import argparse
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import tempfile
import time

# Sibling modules (verification) must import under `python3 -I` / PYTHONSAFEPATH too.
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

RECEIPT_VERSION = 1
GIT_BINARY = "/usr/bin/git"  # Never resolve a program through target PATH/config.
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024
MAX_OBJECT_FILES = 8192
MAX_EVIDENCE = 512
MAX_PATH_BYTES = 4096
MAX_COMPONENTS = 64
MAX_SECONDS = 30
GIT_TIMEOUT = 5
_TOKEN = object()
_HEX = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
_LIMITATIONS = [
    "Bytes and Git object association only; no claim truth, execution, authenticity or coverage attestation.",
    "Runtime and environment revision associations remain declared.",
    "A saved receipt is a historical observation and cannot authorize or replace fresh checks.",
]


class EvidenceError(ValueError):
    """Sanitized machine-readable failure; never carries a local path or stderr."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise EvidenceError("invalid_declarations") from None


def declaration_digest(data):
    """Bind evidence declarations and policy, not mutable finding/review progress."""
    if not isinstance(data, dict):
        raise EvidenceError("invalid_declarations")
    fields = ("schema_version", "assessment", "evidence", "test_runs", "evidence_integrity")
    # Preserve absent-vs-present keys, including explicit empty test_runs/policy.
    return hashlib.sha256(_canonical({k: data[k] for k in fields if k in data})).hexdigest()


def _record_digest(data):
    return hashlib.sha256(_canonical(data)).hexdigest()


class VerificationResult:
    """An in-process observation; serialize .receipt, never reconstruct authority."""
    __slots__ = ("__receipt", "__digest", "__token")

    def __init__(self, receipt, token=None):
        if token is not _TOKEN:
            raise EvidenceError("live_result_required")
        self.__receipt = copy.deepcopy(receipt)
        self.__digest = receipt["input_sha256"]
        self.__token = token

    @property
    def receipt(self):
        return copy.deepcopy(self.__receipt)

    def matches(self, data):
        try:
            return self.__token is _TOKEN and self.__digest == declaration_digest(data)
        except EvidenceError:
            return False

    def __reduce__(self):
        raise TypeError("VerificationResult cannot be serialized; use .receipt")


def _validate(data, evidence_ids):
    if not isinstance(data, dict) or type(data.get("schema_version")) is not int or data["schema_version"] != 2:
        raise EvidenceError("schema_version_2_required")
    assessment = data.get("assessment")
    if not isinstance(assessment, dict) or not isinstance(assessment.get("commit"), str) or not _HEX.fullmatch(assessment["commit"]):
        raise EvidenceError("invalid_assessment")
    if not isinstance(assessment.get("repository"), str) or not assessment["repository"].strip():
        raise EvidenceError("invalid_assessment")
    if assessment.get("worktree") not in ("clean", "dirty"):
        raise EvidenceError("invalid_assessment")
    dirty = assessment.get("diff_sha256")
    if (assessment["worktree"] == "dirty") != bool(dirty) or (dirty and (not isinstance(dirty, str) or not _SHA256.fullmatch(dirty))):
        raise EvidenceError("invalid_assessment")
    records = data.get("evidence", [])
    if not isinstance(records, list) or len(records) > MAX_EVIDENCE:
        raise EvidenceError("invalid_evidence_registry")
    catalog = {}
    for record in records:
        if not isinstance(record, dict):
            raise EvidenceError("invalid_evidence_record")
        identifier = record.get("id")
        if not isinstance(identifier, str) or not identifier.strip() or any(ord(c) < 32 or ord(c) == 127 for c in identifier) or len(identifier) > 512:
            raise EvidenceError("invalid_evidence_id")
        if identifier in catalog:
            raise EvidenceError("duplicate_evidence_id")
        if record.get("kind") not in ("source", "runtime", "environment"):
            raise EvidenceError("invalid_evidence_kind")
        for field, pattern in (("commit", _HEX), ("sha256", _SHA256)):
            if not isinstance(record.get(field), str) or not pattern.fullmatch(record[field]):
                raise EvidenceError("invalid_evidence_" + field)
        if "diff_sha256" in record and (not isinstance(record["diff_sha256"], str) or not _SHA256.fullmatch(record["diff_sha256"])):
            raise EvidenceError("invalid_evidence_diff_sha256")
        if not isinstance(record.get("location"), str) or not record["location"].strip():
            raise EvidenceError("invalid_evidence_location")
        if "source_path" in record and (not isinstance(record["source_path"], str) or not record["source_path"].strip()):
            raise EvidenceError("invalid_source_path")
        catalog[identifier] = record
    if evidence_ids is None:
        selected = sorted(catalog)
    else:
        if not isinstance(evidence_ids, (list, tuple, set, frozenset)) or any(not isinstance(i, str) for i in evidence_ids):
            raise EvidenceError("invalid_evidence_selection")
        selected = sorted(set(evidence_ids))
        if len(selected) != len(evidence_ids) or any(i not in catalog for i in selected):
            raise EvidenceError("invalid_evidence_selection")
    declaration_digest(data)
    return catalog, selected


def _parts(path):
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path or ":" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        raise EvidenceError("unsafe_path")
    try:
        encoded = path.encode("utf-8")
    except UnicodeError:
        raise EvidenceError("unsafe_path") from None
    parts = path.split("/")
    if len(encoded) > MAX_PATH_BYTES or len(parts) > MAX_COMPONENTS or any(p in ("", ".", "..") or len(p.encode("utf-8")) > 255 for p in parts):
        raise EvidenceError("unsafe_path")
    return parts


def _snapshot(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def _directory_snapshot(st):
    # Parent directories such as /tmp can change for unrelated reasons. Holding
    # their fd and comparing identity/mode still detects path replacement.
    return (st.st_dev, st.st_ino, st.st_mode)


def _deadline(until):
    if time.monotonic() > until:
        raise EvidenceError("time_limit")


def _os_error(exc):
    if exc.errno == errno.ENOENT:
        return EvidenceError("file_missing")
    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
        return EvidenceError("unsafe_path")
    if exc.errno in (errno.EACCES, errno.EPERM):
        return EvidenceError("file_unreadable")
    return EvidenceError("file_io_error")


class _Root:
    """Hold every root component by fd, then walk only beneath that root."""
    def __init__(self, path, until):
        self.until, self.chain = until, []
        required = (os.open, os.stat)
        if os.name != "posix" or not all(f in os.supports_dir_fd for f in required) or os.stat not in os.supports_follow_symlinks or not all(hasattr(os, k) for k in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
            raise EvidenceError("unsupported_platform")
        try:
            raw = os.fspath(path)
            if not isinstance(raw, str) or not raw or "\x00" in raw:
                raise EvidenceError("unsafe_root")
            absolute = os.path.abspath(raw)
            parts = absolute.split("/")[1:]
            if any(p == ".." for p in raw.split("/")):
                # '.' is lexical and unambiguous ('./out'); '..' could cross a
                # symlinked parent after lexical normalization.
                raise EvidenceError("unsafe_root")
            fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            self.chain.append((None, None, fd, _directory_snapshot(os.fstat(fd))))
            for part in filter(None, parts):
                fd = self._open_dir(fd, part, self.chain)
            self.fd = fd
        except OSError as exc:
            self.close()
            raise _os_error(exc) from None
        except EvidenceError:
            self.close()
            raise
        except (TypeError, ValueError):
            self.close()
            raise EvidenceError("unsafe_root") from None

    def _open_dir(self, parent, name, chain):
        _deadline(self.until)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        chain.append((parent, name, fd, _directory_snapshot(os.fstat(fd))))
        return fd

    def _check(self, chain):
        for parent, name, fd, before in chain:
            now = os.fstat(fd)
            if _directory_snapshot(now) != before:
                raise EvidenceError("path_changed")
            if parent is not None and _directory_snapshot(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before:
                raise EvidenceError("path_changed")
        _deadline(self.until)

    def check(self):
        try:
            self._check(self.chain)
        except OSError:
            raise EvidenceError("path_changed") from None

    def _walk(self, parts, chain):
        fd = self.fd
        for part in parts:
            fd = self._open_dir(fd, part, chain)
        return fd

    def read(self, path, limit=MAX_FILE_BYTES, budget=None, with_identity=False):
        parts, extra, fd = _parts(path), [], None
        try:
            self.check()
            parent = self._walk(parts[:-1], extra)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceError("not_regular_file")
            if before.st_nlink != 1:
                raise EvidenceError("hardlinked_file")
            if before.st_size > limit:
                raise EvidenceError("size_limit")
            if budget is not None and before.st_size > budget[0]:
                raise EvidenceError("total_read_limit")
            chunks, size = [], 0
            # Never read a sentinel byte beyond either budget. A stable fstat
            # after exactly the initial size detects growth/shrinkage instead.
            while size < before.st_size:
                _deadline(self.until)
                remaining = before.st_size - size
                if budget is not None:
                    remaining = min(remaining, budget[0])
                if remaining <= 0:
                    raise EvidenceError("total_read_limit")
                chunk = os.read(fd, min(65536, remaining))
                if budget is not None:
                    budget[0] -= len(chunk)  # Debit unsuccessful reads as well.
                if not chunk:
                    raise EvidenceError("file_changed")
                chunks.append(chunk)
                size += len(chunk)
            if size != before.st_size or _snapshot(os.fstat(fd)) != _snapshot(before) or _snapshot(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)) != _snapshot(before):
                raise EvidenceError("file_changed")
            self._check(extra)
            self.check()
            content = b"".join(chunks)
            identity = (_snapshot(before), tuple((name, snapshot) for _, name, _, snapshot in extra))
            return (content, identity) if with_identity else content
        except OSError as exc:
            raise _os_error(exc) from None
        finally:
            if fd is not None:
                os.close(fd)
            for _, _, child, _ in reversed(extra):
                os.close(child)

    def listing(self, path=None):
        extra = []
        try:
            self.check()
            fd = self._walk(_parts(path), extra) if path else self.fd
            # Read one entry at a time: don't materialize an unbounded listdir.
            result = []
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    _deadline(self.until)
                    if len(result) >= MAX_OBJECT_FILES:
                        raise EvidenceError("object_count_limit")
                    result.append(entry.name)
            self._check(extra)
            self.check()
            return sorted(result)
        except OSError as exc:
            raise _os_error(exc) from None
        finally:
            for _, _, child, _ in reversed(extra):
                os.close(child)

    def entry_stat(self, path):
        parts, extra = _parts(path), []
        try:
            self.check()
            fd = self._walk(parts[:-1], extra)
            result = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            self._check(extra)
            self.check()
            return result
        except OSError as exc:
            raise _os_error(exc) from None
        finally:
            for _, _, child, _ in reversed(extra):
                os.close(child)

    def exists(self, path):
        try:
            self.entry_stat(path)
            return True
        except EvidenceError as exc:
            if exc.reason == "file_missing":
                return False
            raise

    def close(self):
        for _, _, fd, _ in reversed(self.chain):
            os.close(fd)
        self.chain = []


class _GitSnapshot:
    def __init__(self, repository, object_length, until):
        self.until, self.object_length, self.temp = until, object_length, None
        root = _Root(repository, until)
        try:
            prefix = ""
            if root.exists(".git"):
                if not stat.S_ISDIR(root.entry_stat(".git").st_mode):
                    raise EvidenceError("git_directory_file_unsupported")
                prefix = ".git/"
            for forbidden in ("commondir", "info/grafts", "objects/info/alternates", "objects/info/http-alternates"):
                if root.exists(prefix + forbidden):
                    raise EvidenceError("git_external_store_unsupported")
            self.temp = tempfile.TemporaryDirectory(prefix="evidence-git-")
            self.path = Path(self.temp.name)
            (self.path / "objects").mkdir()
            (self.path / "refs").mkdir()
            (self.path / "HEAD").write_text("ref: refs/heads/unborn\n", encoding="ascii")
            config = "[core]\n\tbare = true\n\trepositoryformatversion = " + ("1" if object_length == 64 else "0") + "\n"
            if object_length == 64:
                config += "[extensions]\n\tobjectformat = sha256\n"
            (self.path / "config").write_text(config, encoding="ascii")
            snapshot_budget, count = [MAX_SNAPSHOT_BYTES], 0
            store = prefix + "objects"
            for bucket in root.listing(store):
                if bucket == "info":
                    continue
                if bucket == "pack":
                    names = root.listing(store + "/pack")
                    if any(n.endswith(".promisor") for n in names):
                        raise EvidenceError("git_promisor_unsupported")
                    names = [n for n in names if re.fullmatch(r"pack-[0-9a-f]{" + str(object_length) + r"}\.(?:pack|idx)", n)]
                elif re.fullmatch(r"[0-9a-f]{2}", bucket):
                    names = root.listing(store + "/" + bucket)
                    if any(not re.fullmatch(r"[0-9a-f]{" + str(object_length - 2) + r"}", n) for n in names):
                        raise EvidenceError("git_object_layout_unsupported")
                else:
                    raise EvidenceError("git_object_layout_unsupported")
                (self.path / "objects" / bucket).mkdir()
                for name in names:
                    count += 1
                    if count > MAX_OBJECT_FILES:
                        raise EvidenceError("object_count_limit")
                    content = root.read(store + "/" + bucket + "/" + name, MAX_SNAPSHOT_BYTES, budget=snapshot_budget)
                    (self.path / "objects" / bucket / name).write_bytes(content)
            root.check()
            self.env = {"PATH": "/usr/bin:/bin", "HOME": str(self.path), "XDG_CONFIG_HOME": str(self.path),
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                        "GIT_CONFIG_SYSTEM": os.devnull, "GIT_CONFIG_COUNT": "0",
                        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                        "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
        except BaseException:
            self.close()
            raise
        finally:
            root.close()

    def _command(self, args, limit):
        _deadline(self.until)
        until = min(self.until, time.monotonic() + GIT_TIMEOUT)
        command = [GIT_BINARY, "--no-replace-objects", "--git-dir=" + str(self.path),
                   "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                   "-c", "protocol.allow=never", "cat-file"] + args
        process = None
        try:
            process = subprocess.Popen(command, cwd=str(self.path), env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, close_fds=True)
            result, size = [], 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = until - time.monotonic()
                    if remaining <= 0:
                        raise EvidenceError("git_timeout")
                    if not selector.select(remaining):
                        raise EvidenceError("git_timeout")
                    block = os.read(process.stdout.fileno(), min(65536, limit + 1 - size))
                    if not block:
                        break
                    size += len(block)
                    if size > limit:
                        raise EvidenceError("git_object_size_limit")
                    result.append(block)
            try:
                code = process.wait(timeout=max(0.001, until - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise EvidenceError("git_timeout") from None
            if code != 0:
                raise EvidenceError("git_object_unavailable")
            return b"".join(result)
        except OSError:
            raise EvidenceError("trusted_git_unavailable") from None
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdout.close()

    def object(self, oid, kind):
        if len(oid) != self.object_length:
            raise EvidenceError("git_object_format_mismatch")
        # Object kind is fixed by the caller; oid is always full validated hex.
        raw = self._command([kind, oid], MAX_FILE_BYTES)
        algorithm = hashlib.sha1 if self.object_length == 40 else hashlib.sha256
        identity = algorithm(kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
        if identity != oid.lower():
            raise EvidenceError("git_object_identity_mismatch")
        return raw

    def source(self, commit, path):
        parts = _parts(path)
        raw = self.object(commit.lower(), "commit")
        first = raw.partition(b"\n")[0]
        if not first.startswith(b"tree ") or not re.fullmatch(rb"[0-9a-f]{" + str(self.object_length).encode("ascii") + rb"}", first[5:]) or b"\n\n" not in raw:
            raise EvidenceError("git_commit_invalid")
        oid = first[5:].decode("ascii")
        for index, component in enumerate(parts):
            tree = self.object(oid, "tree")
            cursor, selected, seen = 0, None, set()
            while cursor < len(tree):
                _deadline(self.until)
                space = tree.find(b" ", cursor)
                end = tree.find(b"\0", space + 1) if space >= 0 else -1
                next_cursor = end + 1 + self.object_length // 2
                if space < 0 or end < 0 or next_cursor > len(tree):
                    raise EvidenceError("git_tree_invalid")
                mode, name = tree[cursor:space], tree[space + 1:end]
                if not name or b"/" in name or name in seen or name in (b".", b".."):
                    raise EvidenceError("git_tree_invalid")
                seen.add(name)
                if name == component.encode("utf-8"):
                    selected = (mode, tree[end + 1:next_cursor].hex())
                cursor = next_cursor
            if selected is None:
                raise EvidenceError("git_source_path_missing")
            mode, oid = selected
            if index < len(parts) - 1:
                if mode != b"40000":
                    raise EvidenceError("git_source_not_regular")
            elif mode not in (b"100644", b"100755"):
                raise EvidenceError("git_source_not_regular")
        return self.object(oid, "blob")

    def close(self):
        if self.temp is not None:
            self.temp.cleanup()
            self.temp = None


def _limits():
    return {"file_bytes": MAX_FILE_BYTES, "total_artifact_bytes": MAX_TOTAL_BYTES,
            "git_snapshot_bytes": MAX_SNAPSHOT_BYTES, "git_object_files": MAX_OBJECT_FILES,
            "evidence_records": MAX_EVIDENCE, "seconds": MAX_SECONDS,
            "git_command_seconds": GIT_TIMEOUT}


def verify_evidence(data, evidence_root, repository=None, evidence_ids=None):
    """Read selected evidence under explicit roots, returning a live result.

    Invalid declarations raise EvidenceError; unavailable/unsafe artifacts and
    unsupported Git layouts instead produce incomplete per-record observations.
    Source artifacts are whole-file bytes, not a line range or inferred excerpt.
    """
    try:
        data = copy.deepcopy(data)
    except (TypeError, ValueError, RecursionError):
        raise EvidenceError("invalid_declarations") from None
    catalog, selected = _validate(data, evidence_ids)
    until, root, git, root_error, git_error = time.monotonic() + MAX_SECONDS, None, None, None, None
    results, observations, budget = [], {}, [MAX_TOTAL_BYTES]
    try:
        try:
            root = _Root(evidence_root, until)
        except EvidenceError as exc:
            root_error = exc.reason
        for identifier in selected:
            record = catalog[identifier]
            item = {"evidence_id": identifier, "bytes": "unavailable", "source": "not_checked", "reason": "not_checked"}
            results.append(item)
            try:
                if root_error:
                    raise EvidenceError(root_error)
                content, identity = root.read(record["location"], MAX_FILE_BYTES, budget=budget, with_identity=True)
                digest = hashlib.sha256(content).hexdigest()
                # Mismatches disclose no new hash/size that could fingerprint an unintended file.
                if digest != record["sha256"].lower():
                    item.update(bytes="mismatch", reason="sha256_mismatch")
                    continue
                item.update(bytes="matched", observed_sha256=digest, observed_size=len(content))
                observations[identifier] = identity
                if record["kind"] != "source":
                    item.update(source="declared", reason="bytes_matched_revision_declared")
                    continue
                if record.get("diff_sha256"):
                    item.update(source="unsupported", reason="dirty_source_unsupported")
                    continue
                if not record.get("source_path"):
                    item.update(source="unsupported", reason="source_path_required")
                    continue
                _parts(record["source_path"])
                if repository is None:
                    item.update(source="unavailable", reason="repository_required")
                    continue
                if git is None and git_error is None:
                    try:
                        git = _GitSnapshot(repository, len(data["assessment"]["commit"]), until)
                    except (EvidenceError, OSError) as exc:
                        git_error = exc.reason if isinstance(exc, EvidenceError) else "git_snapshot_error"
                if git_error:
                    raise EvidenceError(git_error)
                source = git.source(record["commit"], record["source_path"])
                if source != content:
                    item.update(source="mismatch", reason="git_source_bytes_mismatch")
                else:
                    item.update(source="matched", reason="source_bytes_and_commit_matched")
            except EvidenceError as exc:
                if item["bytes"] == "matched":
                    item["source"] = "unsupported" if "unsupported" in exc.reason else "unavailable"
                elif "unsupported" in exc.reason:
                    item["bytes"] = "unsupported"
                item["reason"] = exc.reason
        # Recheck all successful observations after later evidence/Git work.
        # This is a bounded stability check, not an atomic multi-file snapshot.
        for item in results:
            if item["bytes"] != "matched":
                continue
            try:
                record = catalog[item["evidence_id"]]
                content, identity = root.read(record["location"], MAX_FILE_BYTES, budget=budget, with_identity=True)
                if identity != observations[item["evidence_id"]] or hashlib.sha256(content).hexdigest() != item["observed_sha256"]:
                    raise EvidenceError("file_changed")
            except EvidenceError as exc:
                item.update(bytes="unavailable", source="not_checked", reason=exc.reason)
                item.pop("observed_sha256", None)
                item.pop("observed_size", None)
        if root is not None:
            try:
                root.check()
            except EvidenceError as exc:
                for item in results:
                    if item["bytes"] == "matched":
                        item.update(bytes="unavailable", source="not_checked", reason=exc.reason)
                        item.pop("observed_sha256", None)
                        item.pop("observed_size", None)
        receipt = {"receipt_version": RECEIPT_VERSION, "input_sha256": declaration_digest(data),
                   "engine_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                   "limits": _limits(), "selection": selected, "items": results,
                   "status": "matched" if selected and all(_matched(catalog[i["evidence_id"]], i) for i in results) else "incomplete",
                   "limitations": list(_LIMITATIONS)}
        return VerificationResult(receipt, _TOKEN)
    finally:
        if root is not None:
            root.close()
        if git is not None:
            git.close()


def _matched(record, item):
    return item.get("bytes") == "matched" and (record.get("kind") != "source" or item.get("source") == "matched")


def provenance_state(data, evidence_ids, result=None):
    """Describe fresh checks separately from declarations and stored receipts."""
    catalog, selected = _validate(data, evidence_ids)
    reason = "not_checked"
    live = isinstance(result, VerificationResult)
    if result is not None and not live:
        reason = "recorded_receipt_only"
    elif live and not result.matches(data):
        reason = "context_stale"
    if not live or reason == "context_stale":
        return {"status": "incomplete" if reason == "context_stale" else "declared", "reasons": [reason],
                "records": [{"evidence_id": i, "bytes": "declared", "source": "declared", "reason": reason} for i in selected]}
    checked = {item["evidence_id"]: item for item in result.receipt["items"]}
    records = [checked.get(i, {"evidence_id": i, "bytes": "unavailable", "source": "not_checked", "reason": "evidence_not_checked"}) for i in selected]
    reasons = sorted({r["reason"] for r in records if not _matched(catalog[r["evidence_id"]], r)})
    if not selected:
        reasons = ["no_evidence_selected"]
    return {"status": "incomplete" if reasons else "checked", "reasons": reasons, "records": records}


def _json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise EvidenceError("duplicate_json_key")
        obj[key] = value
    return obj


def _read_json(path):
    absolute = os.path.abspath(os.fspath(path))
    root = _Root(os.path.dirname(absolute), time.monotonic() + MAX_SECONDS)
    try:
        raw = root.read(os.path.basename(absolute))
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("invalid_json_number")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, EvidenceError):
            raise
        raise EvidenceError("invalid_json") from None
    finally:
        root.close()


def _write_new(path, value):
    absolute = os.path.abspath(os.fspath(path))
    root = _Root(os.path.dirname(absolute), time.monotonic() + MAX_SECONDS)
    fd = None
    try:
        name = os.path.basename(absolute)
        _parts(name)
        # Creating the requested receipt changes only its explicit parent directory.
        root.check()
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=root.fd)
        raw = _canonical(value) + b"\n"
        while raw:
            written = os.write(fd, raw)
            if written <= 0:
                raise EvidenceError("receipt_write_failed")
            raw = raw[written:]
        os.fsync(fd)
        root.check()
        written_stat = os.fstat(fd)
        if written_stat.st_nlink != 1 or _snapshot(written_stat) != _snapshot(os.stat(name, dir_fd=root.fd, follow_symlinks=False)):
            raise EvidenceError("receipt_write_changed")
    except OSError as exc:
        raise EvidenceError("receipt_exists" if exc.errno == errno.EEXIST else "receipt_write_failed") from None
    finally:
        if fd is not None:
            os.close(fd)
        root.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    verify = sub.add_parser("verify", help="Check local bytes and optional pinned Git sources; never execute target code")
    verify.add_argument("findings")
    verify.add_argument("--root", required=True)
    verify.add_argument("--repository")
    verify.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        data = _read_json(args.findings)
        # The shared verifier expects basic finding shapes from its renderer.
        # Check those assumptions at this independent CLI entry point too.
        if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
            raise EvidenceError("invalid_findings")
        if "meta" in data and not isinstance(data["meta"], dict):
            raise EvidenceError("invalid_findings")
        identifiers = set()
        for finding in data["findings"]:
            if not isinstance(finding, dict) or not isinstance(finding.get("id"), str) or not finding["id"].strip() or finding["id"] in identifiers:
                raise EvidenceError("invalid_findings")
            identifiers.add(finding["id"])
            for key in ("validation", "previous_validation"):
                if key in finding:
                    value = finding[key]
                    if not isinstance(value, dict) or any(k in value and not isinstance(value[k], str) for k in ("verdict", "evidence", "method")):
                        raise EvidenceError("invalid_findings")
        # Structured record validation stays in the existing shared model.
        import verification
        try:
            verification.derive_verification(data, EvidenceError)
        except EvidenceError:
            raise
        except (KeyError, AttributeError, IndexError, TypeError, ValueError, OverflowError, RecursionError):
            raise EvidenceError("invalid_findings") from None
        result = verify_evidence(data, args.root, args.repository)
        _write_new(args.out, result.receipt)
        print("evidence_integrity: " + result.receipt["status"])
        return 0 if result.receipt["status"] == "matched" else 3
    except EvidenceError as exc:
        # The record validator can supply descriptive errors: emit no raw input.
        reason = exc.reason if re.fullmatch(r"[a-z0-9_]+", exc.reason) else "invalid_findings"
        print("evidence_integrity: " + reason, file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError):
        print("evidence_integrity: operation_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
