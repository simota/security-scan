"""Safe output writing for report directories. Standard library only."""

import os
import shutil
import stat
import tempfile
from pathlib import Path


def write_output(path, text):
    """Write via a temporary file in the same directory and os.replace(), which
    replaces a link at path instead of following it.

    Existing regular files keep their permission bits. New reports are private
    to the owner, as they may contain security findings or source excerpts.
    """
    path = Path(path)
    mode = None
    try:
        existing = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISREG(existing.st_mode):
            mode = stat.S_IMODE(existing.st_mode) & 0o777
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_outputs(directory, texts, remove=()):
    """Stage a set of text files, then replace them and remove stale outputs.

    Names must be distinct basenames in an existing directory. Existing files
    remain untouched until every text file is staged. A failed commit restores
    the old files; if restoration fails, recovery files are kept and their
    location is reported in OSError. Existing HTML/text permissions are kept.

    Each rename is atomic, but the whole set is not atomic to other processes.
    """
    directory = Path(directory)
    texts, remove = dict(texts), tuple(remove)
    names = tuple(texts) + remove
    if any(not isinstance(name, str) or not name or name in (".", "..")
           or "/" in name or "\\" in name or "\0" in name or Path(name).name != name for name in names):
        raise ValueError("output names must be plain basenames")
    if len(set(names)) != len(names):
        raise ValueError("output and removal names must be distinct")
    bad = unsafe_target(directory, names)
    if bad:
        raise OSError(f"refusing to write {bad}: symlink or non-regular file")
    if not names:
        return
    work = Path(tempfile.mkdtemp(prefix=".scan-report-output-", dir=directory))
    prepared, previous = work / "new", work / "previous"
    keep_recovery = False
    installing = set()
    try:
        prepared.mkdir()
        previous.mkdir()
        # Reserve every name on this filesystem before touching originals.
        # This also catches case-folding aliases on case-insensitive volumes.
        for name in names:
            (prepared / name).touch(mode=0o600, exist_ok=False)
        for name, text in texts.items():
            write_output(prepared / name, text)
        try:
            # Move all originals, including stale PDFs, before installing any
            # replacement. Backup existence also records a rename interrupted
            # just after it completed, before Python can update bookkeeping.
            for name in names:
                target = directory / name
                try:
                    info = target.lstat()
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise OSError(f"refusing to write {target}: symlink or non-regular file")
                if name in texts:
                    os.chmod(prepared / name, stat.S_IMODE(info.st_mode) & 0o777)
                os.replace(target, previous / name)
            for name in texts:
                bad = unsafe_target(directory, [name])
                if bad:
                    raise OSError(f"refusing to write {bad}: symlink or non-regular file")
                installing.add(name)
                os.replace(prepared / name, directory / name)
        except BaseException as error:
            rollback_errors = []
            for name in reversed(names):
                try:
                    saved, target = previous / name, directory / name
                    if os.path.lexists(saved):
                        os.replace(saved, target)
                    elif name in installing:
                        # This output did not exist before the transaction.
                        target.unlink(missing_ok=True)
                except BaseException as rollback:
                    rollback_errors.append(f"{name}: {rollback or type(rollback).__name__}")
            if rollback_errors:
                keep_recovery = True
                raise OSError(f"could not update outputs: {error or type(error).__name__}; "
                              f"recovery files are preserved at {work}; could not restore "
                              + "; ".join(rollback_errors)) from error
            raise
    finally:
        if not keep_recovery:
            shutil.rmtree(work)


def unsafe_target(out, names):
    """The first out/name that exists as a symlink or non-regular file, else None.

    A planted symlink (or FIFO, directory...) at an output name would redirect
    the write outside the output directory: callers refuse to write then.
    """
    for name in names:
        target = Path(out) / name
        if target.is_symlink() or (os.path.lexists(target) and not target.is_file()):
            return target
    return None
