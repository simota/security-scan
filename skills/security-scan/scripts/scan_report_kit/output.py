"""Safe output writing for report directories. Standard library only."""

import os
import tempfile
from pathlib import Path


def write_output(path, text):
    """Write via a temporary file in the same directory and os.replace(), which
    replaces a link at path instead of following it."""
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix="." + path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        mask = os.umask(0)
        os.umask(mask)
        os.chmod(tmp, 0o666 & ~mask)  # The permissions write_text would give.
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


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
