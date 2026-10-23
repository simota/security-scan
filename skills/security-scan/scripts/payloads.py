"""Literal attack strings shared by findings.py merges and verification_workflow.py submissions."""
import re


# Literal attack strings, not descriptions of them. Prose names the weakness
# and the parameter; the payload itself never belongs in the report.
PAYLOAD = re.compile(
    r"<script\b|<(?:svg|img|iframe|body|details|video|audio|input|object)\b[^>]*\bon[a-z]+\s*=|"
    r"\bon(?:error|load)\s*=|javascript:(?!\s|$)|"
    # SQL tautologies (' OR '1'='1, " or "a"="a, OR 1=1), not prose such as "'admin' or 'member'".
    r"\b(?:or|and)\s+(['\"]?)(\w+)\1\s*=\s*['\"]?\2\b|union\s+(?:all\s+)?select\b|"
    # Traversal: repeated ../ or ..\\, or any URL-encoded segment; a single "../" is prose.
    r"(?:\.\.[/\\]){2,}|\.\.(?:%2f|%5c)|%2e%2e(?:%2f|%5c|[/\\])|"
    r";\s*(?:rm|curl|wget|nc|bash|sh)\s|[;|]\s*(?:id|whoami)\s*(?:$|[;&`])|\$\(\s*(?:curl|wget|id|cat)\b|"
    # Template and expression probes.
    r"\{\{\s*\d+\s*\*\s*\d+\s*\}\}|[$#]\{\s*\d+\s*\*\s*\d+\s*\}|"
    r"\{\{\s*(?:config|self|request|settings|lipsum|cycler)\b|\$\{\s*(?:jndi|env|java|script):|"
    r"169\.254\.169\.254|/etc/(?:passwd|shadow)\b",
    re.IGNORECASE,
)
