"""Shared URL sanitization for generated findings and source excerpts."""
import re
from urllib.parse import urlsplit, urlunsplit


# A Unicode word boundary misses URLs after prose or underscores. Anchor at
# each ASCII scheme-character run, but retain any leading digits/punctuation
# that cannot start a scheme. This also avoids retrying a long non-URL run at
# every character. Apostrophes can be userinfo data; do not stop mid-secret.
URL_RE = re.compile(r"(?<![A-Za-z0-9+.-])(?P<prefix>[0-9+.-]*)"
                    r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*://[^\s\"<>]+)")


def redact_urls(text):
    """Remove URL credentials, queries and fragments from a string."""
    def clean(match):
        prefix, token = match.group("prefix"), match.group("url")
        # Preserve a surrounding single-quote pair without splitting internal quotes.
        suffix = ""
        if text[match.start() - 1:match.start()] == "'" and token.endswith("'"):
            token, suffix = token[:-1], "'"
        # Adjacent quoted URLs can be one token: urlsplit would sanitize only
        # the first authority and leave later credentials in its path. Quotes
        # can also be secret data, so redact the ambiguous token as a whole.
        if "://" in token.partition("://")[2]:
            return prefix + "[redacted URL]" + suffix
        try:
            u = urlsplit(token)
            if not u.hostname:
                return prefix + "[redacted URL]" + suffix
            u.port  # Validate the authority before retaining it.
            return prefix + urlunsplit((u.scheme, u.netloc.rsplit("@", 1)[-1], u.path, "", "")) + suffix
        except ValueError:
            return prefix + "[redacted URL]" + suffix
    return URL_RE.sub(clean, text)
