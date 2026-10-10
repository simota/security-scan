"""Shared URL sanitization for generated findings and source excerpts."""
import re
from urllib.parse import urlsplit, urlunsplit


# A Unicode word boundary misses URLs after prose or underscores. Anchor at
# each ASCII scheme-character run, but retain any leading digits/punctuation
# that cannot start a scheme. This also avoids retrying a long non-URL run at
# every character. Apostrophes can be userinfo data; do not stop mid-secret.
# JSON-escaped URLs (https:\/\/user:pw@host\/x, as written by PHP json_encode)
# carry the same credentials and are matched too.
URL_RE = re.compile(r"(?<![A-Za-z0-9+.-])(?P<prefix>[0-9+.-]*)"
                    r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*:(?://|\\/\\/)[^\s\"<>]+)")
# A quote or angle bracket inside the userinfo ends URL_RE's match before the
# '@' (https://user:p"ss@host): redact through the rest of the token.
QUOTED_USERINFO_RE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*:(?://|\\/\\/)"
                                r"[^\s/\\@\"<>]*[\"<>][^\s/\\@<>]*@[^\s\"'<>]*")
# Scheme-relative URLs (//user:pw@host/path) carry userinfo without a scheme; a
# colon is required so XPath ('//input[@value]') and paths ('//todo@txt') are not.
SCHEMELESS_USERINFO_RE = re.compile(r"(?<![\w:/\\.-])//[^\s/?#\"'<>@:\[\]()]+:[^\s/?#\"'<>@\[\]()]*@(?=[\w\[])")
# A package version after '@' (unpkg.com/react@18.3.1/, pkg.go.dev/net@v0.17.0), not a host.
VERSION_RE = re.compile(r"v?\d+(?:\.\d+){0,2}(?:[-+][\w.]+)?(?=[/?#]|$)")
# A percent-encoded URL (https%3A%2F%2Fuser%3Apw%40host): its userinfo hides in %40.
ENCODED_URL_RE = re.compile(r"(?i)(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]*%3A%2F%2F[^\s\"'<>&]*")


def hidden_userinfo(token):
    """True when '@' after the parsed authority is likely the end of userinfo.

    A password containing '/', '?' or '#' (postgres://app:5432/Secret@db/app,
    redis://default:1234#Abcd@cache) makes urlsplit end the authority early, so
    part of the credential would be kept as host, port or path.
    """
    rest = token.partition("://")[2]
    end = min([i for i in (rest.find(c) for c in "/?#") if i >= 0] or [len(rest)])
    netloc, after = rest[:end], rest[end:]
    at = after.find("@")
    if at < 0:
        return False
    segment = after[1:at]
    if "@" in netloc:
        return True
    if not segment:
        return False  # '/@scope' (npm) and '/@vite/client' paths.
    name, colon, port = netloc.rpartition(":")
    # NAME:digits or NAME:non-port before '/', '?' or '#' is userinfo, not a host and port
    # (postgres://app:5432/Secret@db, https://user:/s3cr3t@host); a dotted host or localhost
    # with a port (api.example.com:8443/users/alice@example.com) is judged like a portless one.
    if colon and "]" not in port and (not port.isdigit() or "." not in name and "[" not in name
                                      and name.lower() != "localhost"):
        return True
    # user/name@host: '@' inside the first path segment and not before a package version.
    return not re.search(r"[/?#]", segment) and not VERSION_RE.match(after, at + 1)


def _encoded_secret(token):
    authority = re.split(r"(?i)%2F", token[token.lower().index("%2f%2f") + 6:], maxsplit=1)[0]
    return "%40" in authority.lower() or "@" in authority


def has_url_credentials(text):
    """True when text holds a URL whose userinfo is (or may be) a credential."""
    if QUOTED_USERINFO_RE.search(text) or SCHEMELESS_USERINFO_RE.search(text):
        return True
    if any(_encoded_secret(m.group()) for m in ENCODED_URL_RE.finditer(text)):
        return True
    for m in URL_RE.finditer(text):
        token = m.group("url").replace("\\/", "/")
        rest = token.partition("://")[2]
        if "://" in rest and "@" in rest or hidden_userinfo(token):
            return True
        try:
            parts = urlsplit(token)
            # https://TOKEN@host carries a credential as the user name alone.
            if parts.password or parts.username and parts.scheme.lower() in ("http", "https"):
                return True
        except ValueError:
            return True
    return False


def redact_urls(text):
    """Remove URL credentials, queries and fragments from a string."""
    text = QUOTED_USERINFO_RE.sub("[redacted URL]", text)
    text = SCHEMELESS_USERINFO_RE.sub("//", text)
    text = ENCODED_URL_RE.sub(lambda m: "[redacted URL]" if _encoded_secret(m.group()) else m.group(), text)

    def clean(match):
        prefix, token = match.group("prefix"), match.group("url")
        # Preserve a surrounding single-quote pair without splitting internal quotes.
        suffix = ""
        if text[match.start() - 1:match.start()] == "'" and token.endswith("'"):
            token, suffix = token[:-1], "'"
        escaped = token.partition(":")[2].startswith("\\/\\/")
        if escaped:
            token = token.replace("\\/", "/")
        # Adjacent quoted URLs can be one token: urlsplit would sanitize only
        # the first authority and leave later credentials in its path. Quotes
        # can also be secret data, so redact the ambiguous token as a whole.
        # A password with '/', '?' or '#' hides the userinfo's '@' past the
        # parsed authority: the whole URL is redacted (over-redaction is safe).
        if "://" in token.partition("://")[2] or hidden_userinfo(token):
            return prefix + "[redacted URL]" + suffix
        try:
            u = urlsplit(token)
            # ';user=sa;pwd=...' (JDBC style) and similar parameters land in the
            # host part; they are credentials, not a host name.
            if not u.hostname or re.search(r"[;=&,]", u.hostname):
                return prefix + "[redacted URL]" + suffix
            u.port  # Validate the authority before retaining it.
            kept = urlunsplit((u.scheme, u.netloc.rsplit("@", 1)[-1], u.path, "", ""))
            return prefix + (kept.replace("/", "\\/") if escaped else kept) + suffix
        except ValueError:
            return prefix + "[redacted URL]" + suffix
    return URL_RE.sub(clean, text)
