"""Writing derived, shareable files (comparisons and exports) safely.

`shareable` masks secret-looking values the same way the rendered reports do;
`write_file` replaces one regular file atomically and refuses symlinks and
non-regular targets, so an export can never follow a link out of the chosen
directory or leave a half-written file behind.
Standard library only; never imports the renderer.
"""
import os
from pathlib import Path
import stat
import tempfile

from secret_redaction import PRIVATE_KEY_RE, mask_multiline, redact

WITHHELD = "[value withheld: private key material]"


class OutputError(Exception):
    pass


def shareable(value):
    """Record text with secret-looking values masked; private-key material is withheld entirely."""
    text = "" if value is None else str(value)
    if PRIVATE_KEY_RE.search(text):
        return WITHHELD
    return mask_multiline("\n".join(redact(line) for line in text.split("\n")))


def _umask():
    mask = os.umask(0)
    os.umask(mask)
    return mask


def check_target(path):
    path = Path(path)
    if path.is_symlink():
        raise OutputError(f"{path}: refusing to write through a symlink")
    if path.exists() and not path.is_file():
        raise OutputError(f"{path}: exists and is not a regular file")
    if not path.parent.is_dir():
        raise OutputError(f"{path.parent}: directory does not exist")
    return path


def write_file(path, data):
    """Atomically replace PATH with DATA (bytes or str), keeping an existing file's mode."""
    path = check_target(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o666 & ~_umask()
    fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None and os.path.exists(temp):
            os.unlink(temp)
    return path
