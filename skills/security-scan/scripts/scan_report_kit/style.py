"""The shared visual system (docs/design.md) as strings ready to inline into a page."""

from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "assets"


def _asset(name):
    return (ASSETS / name).read_text(encoding="utf-8")


def css_string(text):
    """text as a double-quoted CSS string body, safe to inline in HTML.

    HTML parses a style element before CSS parses its strings, so a literal
    less-than sign must be escaped even inside a correctly quoted CSS string.
    Terminate hexadecimal escapes so following text cannot extend them.
    """
    return "".join(
        "\\" + char if char in ('"', "\\") else
        f"\\{ord(char):x} " if char == "<" or ord(char) < 32 or ord(char) == 127 else char
        for char in str(text)
    )


def document_css(running_footer):
    """Stylesheet for the printable document; running_footer is the fixed left page-footer text."""
    return _asset("document.css").replace("__RUNNING_FOOTER__", css_string(running_footer))


def dashboard_css():
    """Stylesheet for the interactive dashboard (light and dark themes)."""
    return _asset("dashboard.css")


def dashboard_js():
    """Runtime for the common-format dashboard built by report.render_dashboard."""
    return _asset("dashboard.js")
