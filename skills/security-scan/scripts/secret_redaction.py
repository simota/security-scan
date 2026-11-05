"""Secret detection and masking for text that reaches shareable report output.

`redact` masks one line, `mask_multiline` masks values whose key sits on an
earlier line, `secret_in_source` decides whether a file would expose a secret,
and `sensitive_path` names files whose content is never excerpted.
Standard library only.
"""
import re
from pathlib import Path

from url_redaction import has_url_credentials, redact_urls


SECRET_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)"
    r"[\w.-]*['\"]?\s*(?:=>|:=|[:=])\s*['\"]?)"
    r"(?!\$|[A-Za-z_][\w.]*\(|process\.env|os\.environ|null\b|None\b|true\b|false\b)([^'\"\s,;)]{4,})")


SENSITIVE_NAMES = {".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", ".git-credentials",
                   "auth.json", "credentials", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml",
                   "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pgpass", ".htpasswd", ".dockercfg",
                   "terraform.tfstate.backup"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".tfstate", ".tfvars"}
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
# The ordinary-character branch must exclude backslashes: otherwise an
# unterminated quoted value explores exponentially many escape combinations.
QUOTED_SECRET_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)"
    r"[\w.-]*['\"]?\s*(?:=>|:=|[:=])\s*)(['\"])(?:\\.|(?!\2)[^\\\n])*\2")


def sensitive_path(path):
    path = Path(path)
    name = path.name.lower()
    return (name == ".env" or name.startswith(".env.") or name.endswith(".env")
            or name in SENSITIVE_NAMES or path.suffix.lower() in SENSITIVE_SUFFIXES
            or name.endswith((".tfstate.backup", ".tfvars.json"))
            # Docker registry logins: .docker/config.json holds base64 user:password.
            or name == "config.json" and path.parent.name.lower() == ".docker"
            or any(part.lower() in {".ssh", ".aws", ".kube", "secrets"} for part in path.parts))


_KEY_RUN = re.compile(r"[\w.-]+")
_KEY = re.compile(r"(?i)password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential")
# Short names count only as a whole name segment: `pass=`, `db_pwd:` but not `bypass` or `passed`.
_KEY_END = re.compile(r"(?i)(?:^|[_.-])(?:pass|pwd|passphrase)$")
# Every tail allows the key's closing quote, and after it a closing subscript
# bracket, before the operator: app.config["SECRET_KEY"] = "...", [ "SECRET_KEY" ] = ...,
# os.environ['TOKEN'] = ...; an unquoted subscript (errors[CONF_PASSWORD] =
# "invalid_auth") names a constant, not the secret.
_SECRET_TAIL = re.compile(r"""(?i)((?:['"](?:[ \t]*\])?)?\s*(?:=>|:=|[:=])\s*['"]?)"""
                          r"""(?!\$|[A-Za-z_][\w.]*\(|process\.env|os\.environ|null\b|None\b|true\b|false\b)([^'"\s,;)]{4,})""")
# Python/JS string prefixes (b"...", r'...', f"...") still delimit a literal.
_QUOTED_TAIL = re.compile(r"""(?i)((?:['"](?:[ \t]*\])?)?\s*(?:=>|:=|[:=])\s*(?:[rbfu]{1,2}(?=['"]))?)(['"])(?:\\.|(?!\2)[^\\\n])*\2""")
# A literal fallback default after an environment lookup is a hardcoded secret
# too: os.environ.get("X", "lit"), getenv('X', 'lit'), ENV['X'] || 'lit',
# value or "lit", value ?? "lit". Masked on lines that name a secret key.
_FALLBACK_LITERAL = re.compile(r"""(?i)((?:\b(?:get|getenv|fetch|getProperty|env)\s*\(\s*[^,()\n]{1,200},\s*"""
                               r"""|\|\|\s*|\?\?\s*|\?:\s*|\bor\s+)(?:[rbfu]{1,2}(?=['"]))?)(['"])(?:\\.|(?!\2)[^\\\n])+\2""")
# Signed JSON Web Tokens: header.payload.signature, each base64url.
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


def _sub_keyed(line, tail, repl):
    """SECRET_RE / QUOTED_SECRET_RE .sub() with one attempt per key-character run.

    Every keyword position inside one run reaches the same tail at the run's
    end, so only the run's leftmost keyword can start a match.
    """
    out, pos = [], 0
    for run in _KEY_RUN.finditer(line):
        if run.start() < pos:
            continue
        key = _KEY.search(line, run.start(), run.end())
        start = key.start() if key else run.start() if _KEY_END.search(run.group()) else None
        m = start is not None and tail.match(line, run.end())
        if m:
            out.append(line[pos:start])
            out.append(repl(line[start:run.end()], m))
            pos = m.end()
    return "".join(out) + line[pos:] if out else line


# Every keyed step below needs a _KEY match or a run ending in _KEY_END; both
# imply one of these substrings (same case folding), so a line without any is
# returned unchanged by those steps.
_KEY_HINT = re.compile(r"(?i)pass|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential")


def redact(line):
    line = redact_urls(line)
    # Recognizable credentials are masked wherever they appear, keyed or not.
    line = JWT_RE.sub("********", TOKEN_RE.sub("********", line))
    line = JWT_KEY_LITERAL.sub(_mask_jwt_key, line)
    if not _KEY_HINT.search(line):
        return line
    line = _sub_keyed(line, _QUOTED_TAIL, lambda key, m: key + m.group(1) + m.group(2) + "********" + m.group(2))
    line = _sub_keyed(line, _SECRET_TAIL, lambda key, m: key + m.group(1) + "********")
    if _KEY.search(line) or any(_KEY_END.search(run.group()) for run in _KEY_RUN.finditer(line)):
        line = _FALLBACK_LITERAL.sub(lambda m: m.group(1) + m.group(2) + "********" + m.group(2), line)
    return line


def _mask_jwt_key(m):
    return m.group(1) + m.group(2) + "********" + m.group(2)


def mask_multiline(text):
    """A literal JWT key or Authorization value whose call or key is on an earlier line,
    masked in place: no line break is touched, so line numbers hold."""
    return _AUTH_VALUE.sub(lambda m: m.group(1) + "********", JWT_KEY_LITERAL.sub(_mask_jwt_key, text))


# secret_in_source: a key whose last name segment (snake, kebab, dotted, camel or
# SCREAMING case) is a secret name, optionally followed by an encoding suffix
# (secret_key_base, private_key_pem), assigned a value that is not a placeholder,
# version, path, URL or plain words. A quoted secret name passed with a quoted
# value (define('DB_PASSWORD', '...'), setdefault("SECRET_KEY", "...")) is an
# assignment too. Values are bounded so an unterminated quote costs at most 1 KiB per key.
_SECRET_NAME = re.compile(r"(?i)(?:^|[_.-])(?:token|secret|password|passwd|api[_-]?key|access[_-]?key"
                          r"|private[_-]?key|secret[_-]?key|client[_-]?secret|auth|credentials?)"
                          r"(?:[_.-](?:base|pem|value|b64|base64|hex|raw))?$")
_LITERAL_TAIL = re.compile(r"""(?:(?P<comma>['"][ \t]*,)|(?:['"](?:[ \t]*\])?)?[ \t]*(?::[ \t]*[A-Za-z_][\w.\[\], |]{0,40}?[ \t]*(?==))?(?:=>|:=|[:=]))[ \t]*"""
                           r"""(?:(?P<q>['"`])(?P<v>(?:\\.|(?!(?P=q))[^\\\n]){0,1024})(?P=q)|(?P<bare>[^'"`\s,;)#]{1,1024}))""")
# A second argument naming another field, variable, flag or code ("csrf_token", "DATABASE_URL",
# "--github-token", "password2") is not a value.
_FIELD_NAME = re.compile(r"-{0,2}[A-Za-z]+(?:[_.-][A-Za-z]+)*[0-9]?")
# A backtick quotes a template literal here; in shell, Ruby or Perl it runs a command.
TEMPLATE_SUFFIXES = {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"}
_NOT_SECRET = re.compile(r"[$<{%]|process\.env|os\.environ|[A-Za-z_][\w.]*\(")
_PLAIN_VALUE = re.compile(r"[\^~<>=].*|v?\d+(?:\.\d+)+[\w.+-]*|(?:~|\.{1,2})?(?:/[a-z0-9_.{}:-]*)+"
                          r"|[a-z][a-z0-9+.-]*://[^?#@\s]*|[A-Za-z][A-Za-z ]*[.!?:]?")
# Recognizable credentials, keyed or not: provider token prefixes, webhook and
# bot URLs whose path is the credential, and an HTTP Authorization value
# (Bearer/Basic followed by a token holding a digit, or any token right after an
# Authorization key (`:`, `=`, `,` or `=>`), also on the next line or after a YAML block-scalar indicator, so `Bearer ${token}`, `"Bearer " + token` and prose stay readable).
_AUTH_CTX = r"(?i:authorization)[\"']?[ \t]*\]?[ \t]*(?:=>|[:=,])(?:[ \t]*[|>][-+0-9]{0,2}[ \t]*(?=[\r\n]))?\s{0,40}[\"'`]?(?i:bearer|basic)[ \t]+"
# After an Authorization key any whole token counts, but not a placeholder (one repeated
# character, YOUR_TOKEN, token), prose (`Bearer flows; …`) nor an expression (`abc" + x`, `abc${x}`).
_AUTH_END = r"""(?:[ \t]*(?:[\r\n]|$)|["'`,)}\]\\])"""
_AUTH_TOKEN = (r"(?!(?:(?P<c>[\w.~+/-])(?P=c)*|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|(?i:(?:your|my)?[_-]?token))=*" + _AUTH_END
               + r")[\w.~+/-]{4,}=*(?=" + _AUTH_END + ")")
TOKEN_RE = re.compile(r"\b(?:gh[opsu]_[A-Za-z0-9]{36,}|github_pat_\w{22,}|A(?:KIA|SIA)[0-9A-Z]{16}"
                      r"|xox[abprse]-[A-Za-z0-9-]{10,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}|glpat-[\w-]{20,}"
                      r"|AIza[\w-]{35}|sk-(?:proj|ant|svcacct|admin)-[\w-]{20,}|sk-[A-Za-z0-9]{32,}"
                      r"|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,}|SG\.[\w-]{16,}\.[\w-]{16,}"
                      r"|hooks\.slack\.com/(?:services|workflows|triggers)/[\w/-]{20,}"
                      r"|discord(?:app)?\.com/api/webhooks/\d+/[\w-]{20,}"
                      r"|(?:api\.telegram\.org/bot)?\d{6,12}:AA[\w-]{30,}"
                      r"|(?i:bearer)[ \t]+(?=[A-Za-z._~+/-]*\d)[\w.~+/-]{16,}=*"
                      r"|(?i:basic)[ \t]+(?=[A-Za-z+/]*\d)[A-Za-z0-9+/]{16,}={0,2}(?![\w.~+/-])"
                      r"|" + _AUTH_CTX + _AUTH_TOKEN + ")")
_AUTH_VALUE = re.compile("(" + _AUTH_CTX + ")" + _AUTH_TOKEN)
# A literal signing key passed positionally or by keyword: jwt.sign(payload, "key"),
# jwt.encode(claims, 'key', ...), jwt.decode(token, "key"), jwt.encode(payload,
# algorithm="HS256", key="key") (also secret=, signing_key=), the keyword form also first:
# jwt.encode(key="key", payload=p). A `template` literal counts unless it interpolates ${…}. The first argument is a simple expression, call or
# object literal; the call may span lines.
# A bracketed group nested at most two deep, each level bounded: makePayload(user), {id: f(x)}.
_GROUP = r"[({](?:[^(){}\n]|[({][^(){}\n]{0,200}[)}]){0,200}[)}]"
# Keyword arguments skipped before key= are bounded too, a [list] kept whole: algorithms=["HS256", "RS256"].
_KWARG = r"[a-z_]\w{0,40}\s{0,40}=(?!=)(?:[^,(){}\[\]\n]|\[[^\[\](){}\n]{0,200}\]|%s){0,199},\s{0,40}" % _GROUP
_JWT_KW = r"(?:key|secret|signing_key)\s{0,40}=\s{0,40}"
JWT_KEY_LITERAL = re.compile(r"""(?i)(\b(?:jwt|jsonwebtoken|jose|jws)\.(?:sign|encode|verify|decode)\s{0,40}\(\s{0,40}"""
                             r"""(?:(?:[^\s,(){}]|%s)(?:[^,(){}\n]|%s){0,199},\s{0,40}(?:(?:%s){0,4}%s)?|%s)(?:[rbfu]{1,2}(?=['"]))?)"""
                             r"""(['"`])(?!(?<=`)[^`\n]{0,1024}\$\{)((?:\\.|(?!\2)[^\\\n]){1,1024})\2""" % (_GROUP, _GROUP, _KWARG, _JWT_KW, _JWT_KW))
# A private key block: the header followed by a base64 body line (raw or \n-escaped).
PEM_BODY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[ \t]*(?:\r?\n|(?:\\r)?\\n)"
                         r"(?:[\w-]+:[^\n\\]*(?:\r?\n|(?:\\r)?\\n))*[ \t]*[A-Za-z0-9+/]{16,}")
CONFIG_SUFFIXES = {".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties", ".toml", ".sh", ".bash", ".zsh"}


def config_source(rel):
    """Files whose unquoted `key=value` / `KEY: value` (also `export K=v`, `ENV K=v`) is a literal."""
    name = Path(rel).name.lower()
    return (Path(rel).suffix.lower() in CONFIG_SUFFIXES or name in {".envrc", "dockerfile", "containerfile"}
            or name.startswith(("env.", "dockerfile.")) or name.endswith((".env", ".dockerfile")))


def secret_value(value):
    return len(value) >= 8 and not _NOT_SECRET.match(value) and not _PLAIN_VALUE.fullmatch(value)


def secret_in_source(rel, text):
    """True when a file would put a secret-looking value into shareable output."""
    if sensitive_path(rel) or PEM_BODY_RE.search(text) or TOKEN_RE.search(text) or JWT_RE.search(text):
        return True
    # A literal signing key is a secret even when it reads like a word ("supersecret").
    if any(m.group(3) and not _NOT_SECRET.match(m.group(3)) for m in JWT_KEY_LITERAL.finditer(text)):
        return True
    config = config_source(rel)
    for line in text.split("\n"):
        for run in _KEY_RUN.finditer(line):
            name = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", run.group())
            m = _SECRET_NAME.search(name) and _LITERAL_TAIL.match(line, run.end())
            if not m or m["comma"] and (not m["q"] or _FIELD_NAME.fullmatch(m["v"])):
                continue
            if m["q"] == "`" and (Path(rel).suffix.lower() not in TEMPLATE_SUFFIXES or "${" in m["v"]):
                continue  # a command substitution, or an interpolated template literal: an expression
            if secret_value(m["v"] if m["q"] else m["bare"] if config else ""):
                return True
        # Userinfo, including a password with '/', '?' or '#', a quoted or
        # percent-encoded one, and scheme-relative //user:pw@host URLs.
        if has_url_credentials(line):
            return True
    return False


_SECRETISH_RUN = re.compile(r"[A-Za-z0-9_+/-]{12,}={0,2}")
_QUOTED_LITERAL = re.compile(r"""(['"])([^'"\s]{8,1024})\1""")


def secrets_finding(finding):
    return str(finding.get("category", "")).lower() == "secrets"


def secret_candidate(text):
    """A value that may be an unrecognised secret: a long token mixing letters
    and digits (keys, hex, base64), an all-caps name-like token, or a quoted
    literal that is not a placeholder, version, path or URL. Over-matching only
    withholds an excerpt."""
    for m in _SECRETISH_RUN.finditer(text):
        token = m.group()
        if (re.search(r"\d", token) and re.search(r"[A-Za-z]", token)
                or "_" in token and token.upper() == token and re.search(r"[A-Z]", token)):
            return True
    return any(secret_value(m.group(2)) for m in _QUOTED_LITERAL.finditer(text) if "*" * 8 not in m.group(2))
