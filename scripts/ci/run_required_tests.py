#!/usr/bin/env python3
"""Run the offline suite with mandatory browser/PDF coverage and zero skips."""
import os
from pathlib import Path
import sys
import unittest


REPO = Path(__file__).resolve().parents[2]
REQUIRED_TESTS = frozenset({
    "test_report_outputs.ReportOutputTests.test_browser_keyboard_filters_reset_excluded_categories_and_hash_navigation",
    "test_report_outputs.ReportOutputTests.test_browser_prototype_named_ids_have_no_phantom_workflows",
    "test_report_outputs.ReportOutputTests.test_browser_mobile_long_hostile_text_does_not_overflow_or_execute",
    "test_report_outputs.ReportOutputTests.test_browser_copies_finding_details_as_markdown",
    "test_report_outputs.ReportOutputTests.test_browser_copy_keeps_record_text_inert_focus_and_filters",
    "test_report_outputs.ReportOutputTests.test_browser_parts_split_cards_priority_and_register_filter",
    "test_review_hardening.ReviewHardeningTests.test_dashboard_draws_hostile_text_in_real_browser",
    "test_ci_report_artifacts.ReportArtifactTests.test_english_sample_pdf",
    "test_ci_report_artifacts.ReportArtifactTests.test_japanese_sample_pdf",
    "test_ci_report_artifacts.ReportArtifactTests.test_english_long_pdf_retains_every_evidence_paragraph",
    "test_ci_report_artifacts.ReportArtifactTests.test_japanese_long_pdf_retains_every_evidence_paragraph",
    "test_verification_reports.VerificationReportTests.test_browser_verification_records_both_languages_mobile",
    "test_verification_reports.VerificationPDFTests.test_english_verification_sample_pdf",
    "test_verification_reports.VerificationPDFTests.test_japanese_verification_sample_pdf",
    "test_workflow_reports.WorkflowReportTests.test_browser_workflow_handoffs_both_languages_mobile",
    "test_workflow_reports.WorkflowPDFTests.test_english_workflow_evidence_pdf",
    "test_workflow_reports.WorkflowPDFTests.test_japanese_workflow_evidence_pdf",
    "test_evidence_reports.EvidenceReportTests.test_browser_integrity_provenance_both_languages_mobile",
    "test_evidence_reports.EvidencePDFTests.test_english_integrity_pdf",
    "test_evidence_reports.EvidencePDFTests.test_japanese_integrity_pdf",
    "test_three_pass_reports.ThreePassReportTests.test_browser_three_pass_summary_both_languages_mobile",
    "test_three_pass_reports.ThreePassPDFTests.test_english_three_pass_pdf",
    "test_three_pass_reports.ThreePassPDFTests.test_japanese_three_pass_pdf",
    "test_render_round6.DashboardBrowserTests.test_browser_large_register_lazy_details_debounced_search_priority_and_copy_fallback",
    "test_render_round6.DashboardBrowserTests.test_browser_singular_summary_and_more_high_note",
})


def test_ids(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from test_ids(test)
        else:
            yield test.id()


def run_suite(suite, stream=None):
    stream = sys.stderr if stream is None else stream
    result = unittest.TextTestRunner(verbosity=2, stream=stream).run(suite)
    if result.skipped:
        print("Required CI coverage was skipped; refusing a successful result.", file=stream)
    if result.expectedFailures:
        print("Required CI coverage has expected failures; refusing a successful result.", file=stream)
    if not result.testsRun:
        print("No tests ran; refusing a successful result.", file=stream)
    complete = result.testsRun and not result.skipped and not result.expectedFailures
    return 0 if result.wasSuccessful() and complete else 1


def main():
    # Set before discovery because unittest decorators are evaluated on import.
    os.environ["SECURITY_SCAN_BROWSER_TEST"] = "1"
    suite = unittest.defaultTestLoader.discover(str(REPO / "tests"))
    missing = REQUIRED_TESTS - set(test_ids(suite))
    if missing:
        print("Missing required report tests: " + ", ".join(sorted(missing)), file=sys.stderr)
        return 1
    return run_suite(suite)


if __name__ == "__main__":
    sys.exit(main())
