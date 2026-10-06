"""Shared URL sanitization for generated findings and source excerpts."""
import re
from urllib.parse import urlsplit, urlunsplit


# Apostrophes are valid URL data, including in userinfo; do not stop mid-secret.
URL_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"<>]+")


def redact_urls(text):
    """Remove URL credentials, queries and fragments from a string."""
    def clean(match):
        token = match.group()
        # Preserve a surrounding single-quote pair without splitting internal quotes.
        suffix = ""
        if text[match.start() - 1:match.start()] == "'" and token.endswith("'"):
            token, suffix = token[:-1], "'"
        # Adjacent quoted URLs can be one token: urlsplit would sanitize only
        # the first authority and leave later credentials in its path. Quotes
        # can also be secret data, so redact the ambiguous token as a whole.
        if "://" in token.partition("://")[2]:
            return "[redacted URL]" + suffix
        try:
            u = urlsplit(token)
            if not u.hostname:
                return "[redacted URL]" + suffix
            u.port  # Validate the authority before retaining it.
            return urlunsplit((u.scheme, u.netloc.rsplit("@", 1)[-1], u.path, "", "")) + suffix
        except ValueError:
            return "[redacted URL]" + suffix
    return URL_RE.sub(clean, text)
