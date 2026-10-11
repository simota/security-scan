"""scan-report-kit: the shared dashboard, document and PDF format for *-scan skills.

Standard library only, so a skill can vendor this package (scripts/vendor.py)
and stay self-contained. Modules:

    style   the visual system (docs/design.md) as inline CSS / JS
    pdf     headless Chrome / WeasyPrint printing with diagnosable failures
    output  safe writes into a report directory
    report  validate and render the common report format (docs/format.md)
"""

__version__ = "0.1.0"
