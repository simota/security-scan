"""The shared visual system (docs/design.md) as strings ready to inline into a page."""

from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "assets"


def _asset(name):
    return (ASSETS / name).read_text(encoding="utf-8")


def css_string(text):
    """text as the body of a double-quoted CSS string."""
    return str(text).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def document_css(running_footer):
    """Stylesheet for the printable document; running_footer is the fixed left page-footer text."""
    return _asset("document.css").replace("__RUNNING_FOOTER__", css_string(running_footer))


def dashboard_css():
    """Stylesheet for the interactive dashboard (light and dark themes)."""
    return _asset("dashboard.css")


def dashboard_js():
    """Runtime for the common-format dashboard built by report.render_dashboard."""
    return _asset("dashboard.js")
