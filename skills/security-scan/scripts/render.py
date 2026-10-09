#!/usr/bin/env python3
"""Render a security-scan findings.json into a dashboard and an assessment document.

    python3 render.py findings.json --out DIR [--lang ja|en] [--no-pdf]

Writes DIR/dashboard.html (self-contained), DIR/assessment.html and DIR/assessment.pdf
(PDF via headless Chrome, or WeasyPrint as a fallback; set CHROME to pick a binary).
Standard library only.
"""
import argparse
import html
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlsplit
from url_redaction import redact_urls
from verification import CLAIMS, derive_verification, validate_verification
from verification_workflow import derive_workflow, validate_workflows
from evidence_integrity import verify_evidence
from three_pass import derive_three_pass
from expert import derive_expert
from invariant_ledger import ledger_html, validate_ledger

SEVERITIES = ["High", "Medium", "Low", "Info"]
CONFIDENCES = ["Confirmed", "Environment-dependent", "Suspected"]
STATUSES = ["Open", "Fixed", "Accepted"]
VERDICTS = ["Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"]
EXCLUDED = {"FalsePositive", "NotApplicable"}
# Report parts: the application's own design, code and configuration, then the
# scanner-owned dependency and supply-chain records (D-*, reference/dependencies.md).
PARTS = ("code", "deps")
# ASCII digits only, no trailing newline: the number becomes part of a link.
CWE_RE = re.compile(r"CWE-[0-9]{1,5}")

LABELS = {
    "en": {
        "title": "Security Assessment Report",
        "dash_title": "Security Findings",
        "summary": "Executive summary",
        "scope": "Scope and method",
        "project": "System", "date": "Date", "assessor": "Assessor",
        "scope_l": "Scope", "method": "Method", "commit": "Revision",
        "overview": "Results overview",
        "by_sev": "By severity", "by_conf": "By confidence", "by_cat": "By category",
        "by_status": "By status",
        "details": "Findings",
        "location": "Location", "actor": "Actor", "request": "Request",
        "impact": "Impact", "fix": "Fix direction", "confidence": "Confidence",
        "category": "Category", "status": "Status", "severity": "Severity",
        "checked_ok": "Checked and sound",
        "decisions": "Decisions required",
        "limitations": "Limitations",
        "next_steps": "Recommended next steps",
        "none": "None.",
        "no_records": "No records in this view.",
        "total": "Total findings",
        "open_hm": "Open High/Medium",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "summary_line": "{total} findings: {counts}. {open_hm} High/Medium findings remain open.",
        "search": "Search", "all": "All",
        "count": "Count",
        "perspectives": "Coverage by perspective", "perspective": "Perspective",
        "result": "Result", "note": "Note", "title_col": "Title",
        "verdict": "Validation", "by_verdict": "By validation", "evidence": "Validation evidence",
        "references": "References", "snippet": "Source", "source_link": "View source",
        "snippet_truncated": "Excerpt shortened (at most 200 lines and 240 characters per line). Review the original source for full context.",
        "excluded": "Excluded findings (false positive / not applicable)",
        "excluded_line": "{n} findings were excluded after validation and are listed at the end.",
    },
    "ja": {
        "title": "セキュリティ診断書",
        "dash_title": "セキュリティ診断結果",
        "summary": "総括",
        "scope": "診断対象と方法",
        "project": "対象システム", "date": "診断日", "assessor": "診断者",
        "scope_l": "範囲", "method": "方法", "commit": "リビジョン",
        "overview": "結果概要",
        "by_sev": "重大度別", "by_conf": "確度別", "by_cat": "分類別",
        "by_status": "対応状況別",
        "details": "指摘事項",
        "location": "場所", "actor": "実行できる者", "request": "リクエスト",
        "impact": "影響", "fix": "対応方針", "confidence": "確度",
        "category": "分類", "status": "状況", "severity": "重大度",
        "checked_ok": "問題がなかった確認項目",
        "decisions": "判断が必要な事項",
        "limitations": "制約事項",
        "next_steps": "推奨する対応順",
        "none": "なし",
        "no_records": "この表示対象に該当する記録はありません。",
        "total": "指摘総数",
        "open_hm": "未対応の高・中",
        "open_summary": "未対応の指摘は {n} 件です。High / Medium は含まれていません。",
        "summary_line": "指摘は計{total}件（{counts}）。未対応の高・中リスクは{open_hm}件です。",
        "search": "検索", "all": "すべて",
        "count": "件数",
        "perspectives": "観点別の診断結果", "perspective": "観点",
        "result": "結果", "note": "備考", "title_col": "件名",
        "verdict": "妥当性", "by_verdict": "妥当性別", "evidence": "妥当性の根拠",
        "references": "参照", "snippet": "該当ソース", "source_link": "ソースを開く",
        "snippet_truncated": "抜粋を省略しています（最大200行・1行240文字）。全体の文脈は元のソースで確認してください。",
        "excluded": "除外した指摘（誤検知・対象外）",
        "excluded_line": "妥当性確認により{n}件を除外しました（末尾に記載）。",
    },
}

# Shared wording keeps the dashboard and the printable assessment consistent.
LABELS["en"].update({
    "part": "Source",
    "part_all": "All sources",
    "part_code": "Application: design, code and configuration",
    "part_deps": "Dependencies and supply chain",
    "part_short_code": "Application",
    "part_short_deps": "Dependencies",
    "part_note": "Application findings come from reviewing the system's own design, code and configuration. Dependency findings (D-*) come from the dependency and supply-chain scan: vulnerable or malicious packages, lockfiles, version pinning, registries and build pipelines.",
    "part_card_sub": "Open High/Medium: {open_hm} · Total: {total}",
    "part_none_open": "No open findings in this part.",
    "part_none": "No findings were recorded in this part.",
    "a_cap_parts": "Findings by source: the application's own code and its third-party dependencies are counted separately.",
    "a_part_total": "Total",
})
LABELS["ja"].update({
    "part": "区分",
    "part_all": "すべての区分",
    "part_code": "アプリケーション（設計・実装・設定）",
    "part_deps": "依存ライブラリ・サプライチェーン",
    "part_short_code": "アプリケーション",
    "part_short_deps": "依存ライブラリ",
    "part_note": "アプリケーションの指摘は、対象システム自身の設計・実装・設定のレビュー結果です。依存ライブラリの指摘（D-*）は依存関係とサプライチェーンのスキャン結果で、脆弱・悪性パッケージ、lockfile、バージョン固定、レジストリ、ビルドパイプラインを対象にしています。",
    "part_card_sub": "未対応の高・中: {open_hm} 件 · 計 {total} 件",
    "part_none_open": "この区分に未対応の指摘はありません。",
    "part_none": "この区分の指摘は記録されていません。",
    "a_cap_parts": "区分別の指摘件数。アプリケーション自身のコードと第三者の依存ライブラリを分けて集計しています。",
    "a_part_total": "計",
})

LABELS['en'].update({'eyebrow': 'SECURITY REVIEW',
 'report_note': 'Static review · read-only · offline report',
 'assessment_link': 'Print / assessment',
 'theme': 'Toggle color theme',
 'priority': 'Start here',
 'priority_note': 'Open findings, ordered by severity, then readiness to fix. Review applicability '
                  'before changing code.',
 'fix_now': 'Plan the fix',
 'verify_first': 'Validate first',
 'fix_now_note': 'Valid, Confirmed finding with sufficient structured verification. Use the recorded fix direction and verify '
                 'the secure outcome.',
 'verify_first_note': 'Confirm reachability, preconditions and impact; record evidence before deciding '
                      'on a fix.',
 'missing_fix': 'Fix direction not recorded. Define the remediation after reviewing the evidence.',
 'no_open': 'No open findings are recorded. This does not establish that the system is secure.',
 'no_findings': 'No included findings are recorded. Review the scope and limitations before drawing '
                'conclusions.',
 'included': 'Included findings',
 'excluded_short': 'Excluded',
 'open_count': 'Open findings',
 'needs_validation': 'Open, needs validation',
 'closed_count': 'Fix recorded / accepted',
 'unverified_line': '{n} included findings are Unverified, including {high} High.',
 'counts_note': 'Report-wide totals include Open, Fixed and Accepted. Excluded findings do not '
                'contribute to these totals.',
 'count_basis': 'Severity is potential impact; confidence is certainty. Validation records whether the '
                'finding applies.',
 'coverage_heading': 'Scope, coverage and limitations',
 'coverage_note': 'Coverage is recorded per perspective below. Missing perspectives or empty notes do '
                  'not mean they were checked. Zero findings is not a security guarantee.',
 'coverage_missing': 'No perspective coverage was recorded.',
 'not_recorded': 'Not recorded',
 'limitations_empty': 'No limitations were recorded. This is not evidence of complete coverage.',
 'limitations_count': 'Recorded limitations',
 'findings_note': 'Open a finding for impact, evidence and fix direction. Totals above remain '
                  'report-wide while filtering.',
 'record_set': 'Records',
 'included_set': 'Included (excludes ruled-out findings)',
 'excluded_set': 'Excluded only',
 'all_records': 'All records',
 'sort': 'Order',
 'priority_sort': 'Open first, then severity',
 'severity_sort': 'Severity',
 'reset': 'Clear filters',
 'showing': 'Showing {shown} of {total} records in this view',
 'no_matches': 'No findings match these filters. Clear filters to see more.',
 'expand': 'Show details',
 'collapse': 'Hide details',
 'permalink': 'Link to finding',
 'copy_llm': 'Copy for LLM',
 'copied': 'Copied',
 'copy_failed': 'Copy failed',
 'view_all': 'View all findings',
 'queue_more': 'Showing {shown} of {total} open findings.',
 'validation_method': 'Validation method',
 'fix_hint': 'Recorded fix direction',
 'previous_validation': 'Previous validation (historical; not the current verdict)',
 'history_note': 'Revalidate this evidence against the current code and configuration.',
 'excluded_note': 'Excluded findings are retained with their justification. They are not counted in '
                  'included totals.',
 'missing_evidence': 'No validation evidence recorded.',
 'source_note': 'Source excerpts are best-effort redacted. Inspect this report before sharing.',
 'no_script': 'Enable JavaScript to use the interactive dashboard, or open the assessment for the '
              'complete report.',
 'risk_summary': '{n} open High / Medium findings need attention.',
 'jump_findings': 'Jump to findings',
 'findings_register': 'Findings register',
 'all_verdicts': 'All validations'})
LABELS['ja'].update({'eyebrow': 'SECURITY REVIEW',
 'report_note': '静的レビュー · 読み取り専用 · オフラインレポート',
 'assessment_link': '印刷用の診断書',
 'theme': '配色を切り替え',
 'priority': 'まず取り組むこと',
 'priority_note': '未対応の指摘を重大度順、同じ重大度では修正判断の準備ができた順に表示します。適用条件を確認してから修正してください。',
 'fix_now': '修正を計画',
 'verify_first': 'まず妥当性を確認',
 'fix_now_note': 'Valid・Confirmed に加え、構造化された検証根拠がそろっています。記録された対応方針を基に修正し、安全な結果を確認してください。',
 'verify_first_note': '到達経路・成立条件・影響を確認し、根拠を記録してから修正要否を判断してください。',
 'missing_fix': '対応方針が未記録です。根拠を確認し、修正内容を具体化してください。',
 'no_open': '未対応の指摘は記録されていません。システムの安全性を保証するものではありません。',
 'no_findings': '集計対象の指摘はありません。診断範囲と制約を確認してから判断してください。',
 'included': '集計対象の指摘',
 'excluded_short': '除外',
 'open_count': '未対応の指摘',
 'needs_validation': '未対応・要検証',
 'closed_count': '修正の申告 / 受容',
 'unverified_line': '集計対象のうち {n} 件は未検証（Unverified）です。このうち High は {high} 件です。',
 'counts_note': '全体集計には Open・Fixed・Accepted を含みます。除外した指摘は含みません。',
 'count_basis': '重大度は想定される影響、確度は確かさ、妥当性はこの対象に指摘が成立するかを表します。',
 'coverage_heading': '診断範囲・確認状況・制約',
 'coverage_note': '観点ごとの確認状況を下に示します。観点や備考の記載がない場合、確認済みとは見なしません。指摘がゼロでも安全性の保証にはなりません。',
 'coverage_missing': '観点ごとの確認状況が記録されていません。',
 'not_recorded': '未記録',
 'limitations_empty': '制約事項が記録されていません。すべて確認済みであることを示すものではありません。',
 'limitations_count': '記録された制約',
 'findings_note': '指摘を開くと影響・根拠・対応方針を確認できます。絞り込んでも上部の全体集計は変わりません。',
 'record_set': '表示対象',
 'included_set': '集計対象（誤検知・対象外を除く）',
 'excluded_set': '除外した指摘のみ',
 'all_records': 'すべての記録',
 'sort': '表示順',
 'priority_sort': '未対応を先に、重大度順',
 'severity_sort': '重大度順',
 'reset': '絞り込みを解除',
 'showing': 'この表示対象 {total} 件中 {shown} 件を表示',
 'no_matches': '条件に一致する指摘はありません。絞り込みを解除すると、ほかの指摘を確認できます。',
 'expand': '詳細を開く',
 'collapse': '詳細を閉じる',
 'permalink': 'この指摘へのリンク',
 'copy_llm': 'LLM用にコピー',
 'copied': 'コピーしました',
 'copy_failed': 'コピーできませんでした',
 'view_all': '指摘一覧を見る',
 'queue_more': '未対応 {total} 件のうち {shown} 件を表示しています。',
 'validation_method': '検証方法',
 'fix_hint': '記録された対応方針',
 'previous_validation': '以前の判定（履歴。現在の判定ではありません）',
 'history_note': '現在のコード・設定に照らして再検証してください。',
 'excluded_note': '除外した指摘も、その根拠とともに保持します。集計対象の件数には含めません。',
 'missing_evidence': '妥当性の根拠が記録されていません。',
 'source_note': 'ソース抜粋の伏せ字は完全ではありません。共有前に内容を確認してください。',
 'no_script': '対話型ダッシュボードには JavaScript が必要です。診断書ではすべての記録を確認できます。',
 'risk_summary': '未対応の High / Medium が {n} 件あります。',
 'jump_findings': '指摘一覧へ移動',
 'findings_register': '指摘一覧',
 'all_verdicts': 'すべての妥当性'})


VERIFICATION_LABELS = {
    "en": {
        "v_title": "Verification record", "v_retest": "Remediation verification",
        "v_summary": "Recorded evidence: {static} static-supported, {runtime} locally reproduced, {pending} requiring further verification. {retested} fixes have complete retest records.",
        "v_note": "These labels check the supplied evidence record, not its truth. Local results do not establish deployed behavior. Counts exclude ruled-out findings.",
        "v_legacy": "Detailed verification evidence not recorded (legacy)",
        "v_incomplete": "Verification incomplete", "v_static_supported": "Supported by static evidence",
        "v_runtime_supported": "Reproduced in an isolated local environment",
        "v_environment_unverified": "Environment conditions unverified",
        "v_not_requested": "Retest not recorded", "v_fix_claimed": "Fix recorded; retest unverified",
        "v_verified": "Complete before/after and control retest records", "v_retest_incomplete": "Retest incomplete",
        "v_scope": "Evidence scope", "v_claims": "Claims and source trace", "v_falsification": "Checks for counterevidence",
        "v_reviews": "Independent review", "v_environment": "Environment conditions", "v_runs": "Local test records",
        "v_evidence": "Referenced evidence", "v_reachability": "Reachability", "v_preconditions": "Preconditions",
        "v_defenses": "Compensating defenses", "v_impact": "Impact", "v_refs": "Evidence IDs",
        "v_repository": "Repository", "v_commit": "Commit", "v_worktree": "Worktree", "v_case": "Case",
        "v_expected": "Expected", "v_observed": "Observed", "v_command": "Recorded command (not executed by this report)",
        "v_context": "Context", "v_time": "Recorded at", "v_exit": "Exit code", "v_failure": "Failure kind",
        "v_withheld": "Evidence text withheld for sensitive material; inspect the authorized original.",
        "v_reason": "Reason", "v_hash": "Declared artifact SHA-256", "v_location": "Evidence location",
        "v_author": "Original reviewer", "v_exclusion": "Exclusion basis", "v_remediation": "Retest target",
        "v_resolution": "Resolution of disagreement", "v_legacy_note": "Historical verification note (not structured evidence)",
        "v_environment_verified": "Environment conditions recorded as verified",
        "v_supported": "Supported", "v_contradicted": "Contradicted", "v_unknown": "Unknown",
        "v_clear": "Countercheck clear", "v_contradiction": "Counterevidence found", "v_unresolved": "Unresolved",
        "v_agree": "Evidence reviewed", "v_disagree": "Disagreement", "v_not_required": "Not required for this scoped claim",
        "v_pass": "Pass", "v_fail": "Fail", "v_skip": "Skipped", "v_not_run": "Not run", "v_blocked": "Blocked",
        "v_unsupported": "Unsupported", "v_error": "Error", "v_security": "Security assertion",
        "v_positive_control": "Positive control", "v_regression": "Regression", "v_missing": "Not recorded",
    },
    "ja": {
        "v_title": "検証記録", "v_retest": "修正の再検査",
        "v_summary": "検証根拠：静的根拠で成立 {static} 件、ローカル再現 {runtime} 件、追加検証が必要 {pending} 件。修正前後と対照条件の再検査記録がそろった指摘は {retested} 件です。",
        "v_note": "表示は提出された記録の整合性を確認したものです。証拠の真実性や本番環境での成立を保証しません。件数は除外した指摘を含みません。",
        "v_legacy": "詳細な検証根拠なし（従来形式）", "v_incomplete": "検証未完了",
        "v_static_supported": "静的根拠で成立", "v_runtime_supported": "隔離されたローカル環境で再現",
        "v_environment_unverified": "環境条件が未確認", "v_not_requested": "再検査記録なし",
        "v_fix_claimed": "修正の申告あり・再検査は未確認", "v_verified": "修正前後・対照条件の再検査記録あり",
        "v_retest_incomplete": "再検査未完了", "v_scope": "根拠の対象範囲", "v_claims": "成立条件とソースの追跡",
        "v_falsification": "指摘を否定する根拠の確認", "v_reviews": "別の確認者による再読", "v_environment": "環境条件",
        "v_runs": "ローカルテストの記録", "v_evidence": "参照した根拠", "v_reachability": "到達可能性",
        "v_preconditions": "成立の前提", "v_defenses": "ほかの層の防御策", "v_impact": "影響",
        "v_refs": "根拠ID", "v_repository": "リポジトリ", "v_commit": "コミット", "v_worktree": "作業ツリー",
        "v_case": "ケース", "v_expected": "期待結果", "v_observed": "観測結果", "v_command": "記録されたコマンド（帳票では実行しません）",
        "v_context": "実行条件", "v_time": "記録日時", "v_exit": "終了コード", "v_failure": "失敗の種類",
        "v_withheld": "機微な内容のため根拠本文を表示しません。許可された原本を確認してください。",
        "v_reason": "理由", "v_hash": "申告された根拠ファイルのSHA-256", "v_location": "根拠の場所",
        "v_author": "最初の確認者", "v_exclusion": "除外の根拠", "v_remediation": "再検査の対象",
        "v_resolution": "見解の相違を解決した根拠", "v_legacy_note": "以前の検証メモ（構造化された根拠ではありません）",
        "v_environment_verified": "環境条件の確認記録あり",
        "v_supported": "成立を支持", "v_contradicted": "反証あり", "v_unknown": "不明",
        "v_clear": "反証なしと記録", "v_contradiction": "反証を発見", "v_unresolved": "未解決",
        "v_agree": "根拠を再読", "v_disagree": "見解が不一致", "v_not_required": "この主張の範囲では不要",
        "v_pass": "成功", "v_fail": "失敗", "v_skip": "省略", "v_not_run": "未実施", "v_blocked": "実施不可",
        "v_unsupported": "非対応", "v_error": "エラー", "v_security": "安全条件の検査",
        "v_positive_control": "正常系の対照検査", "v_regression": "回帰検査", "v_missing": "未記録",
    },
}
for _lang, _labels in VERIFICATION_LABELS.items():
    LABELS[_lang].update(_labels)


INTEGRITY_LABELS = {
    "en": {
        "i_title": "Evidence-file integrity",
        "i_summary": "Evidence-file checks: {checked} findings checked, {incomplete} incomplete, {declared} with declared references only. Counts exclude ruled-out findings.",
        "i_checked": "Current evidence bytes checked",
        "i_declared": "Declared references only; evidence files not checked",
        "i_incomplete": "Evidence-file checks incomplete",
        "i_counts": "SHA-256 matched: {bytes_checked}/{evidence_total} referenced files. Commit/path blobs matched: {sources_checked}.",
        "i_note": "A byte match confirms only that the file matches its declared SHA-256. A source match binds those bytes to a blob at the recorded commit and path. Neither proves authenticity, test execution, the truth of recorded results, or deployed behavior.",
        "i_bytes": "File bytes", "i_source": "Source binding",
        "i_source_path": "Recorded path within the commit",
        "i_bytes_matched": "SHA-256 matched", "i_bytes_mismatch": "SHA-256 mismatch",
        "i_bytes_unavailable": "Unavailable", "i_bytes_unsupported": "Unsupported",
        "i_bytes_declared": "Declared; not checked", "i_bytes_not_checked": "Not checked",
        "i_source_matched": "Blob matched at the recorded commit/path",
        "i_source_mismatch": "Bytes differ from the recorded commit/path blob",
        "i_source_declared": "Commit reference declared only",
        "i_source_unavailable": "Commit/path binding unavailable",
        "i_source_unsupported": "Commit/path binding unsupported",
        "i_source_not_checked": "Commit/path binding not checked",
        "i_reason_unknown": "The evidence-file check could not be completed.",
        "v_gap_evidence_integrity_incomplete": "Fresh evidence-file checks are missing or incomplete.",
        "v_gap_evidence_integrity_unchecked": "Required fresh evidence-file checks have not been performed.",
        "v_gap_evidence_integrity_failed": "Fresh evidence-file checks did not establish matching bytes and required source bindings.",
    },
    "ja": {
        "i_title": "根拠ファイルの整合性",
        "i_summary": "根拠ファイルの確認：確認済みの指摘 {checked} 件、未完了 {incomplete} 件、参照の申告のみ {declared} 件。件数は除外した指摘を含みません。",
        "i_checked": "今回、根拠ファイルのバイト列を確認済み",
        "i_declared": "参照の申告のみ・根拠ファイルは未確認",
        "i_incomplete": "根拠ファイルの確認が未完了",
        "i_counts": "SHA-256 一致：参照ファイル {evidence_total} 件中 {bytes_checked} 件。コミット・パスの blob 一致：{sources_checked} 件。",
        "i_note": "バイト列の一致は、ファイルが申告された SHA-256 と一致することだけを示します。ソースの一致は、記録されたコミット・パスの blob との対応を示します。真正性、テストの実行、記録された結果の真実性、本番環境での動作は証明しません。",
        "i_bytes": "ファイルのバイト列", "i_source": "ソースとの対応",
        "i_source_path": "コミット内の記録されたパス",
        "i_bytes_matched": "SHA-256 一致", "i_bytes_mismatch": "SHA-256 不一致",
        "i_bytes_unavailable": "確認不可", "i_bytes_unsupported": "非対応",
        "i_bytes_declared": "申告のみ・未確認", "i_bytes_not_checked": "未確認",
        "i_source_matched": "記録されたコミット・パスの blob と一致",
        "i_source_mismatch": "記録されたコミット・パスの blob とバイト列が不一致",
        "i_source_declared": "コミットの参照は申告のみ",
        "i_source_unavailable": "コミット・パスとの対応を確認不可",
        "i_source_unsupported": "コミット・パスとの対応は非対応",
        "i_source_not_checked": "コミット・パスとの対応は未確認",
        "i_reason_unknown": "根拠ファイルの確認を完了できませんでした。",
        "v_gap_evidence_integrity_incomplete": "今回の根拠ファイルの確認が未実施、または未完了です。",
        "v_gap_evidence_integrity_unchecked": "必須の根拠ファイルの確認が、今回まだ実施されていません。",
        "v_gap_evidence_integrity_failed": "今回の根拠ファイルの確認では、バイト列の一致と必要なソースとの対応を確認できませんでした。",
    },
}
for _lang, _labels in INTEGRITY_LABELS.items():
    LABELS[_lang].update(_labels)


_INTEGRITY_REASONS = {
    "context_stale": ("Declarations changed after the file check; check them again.", "ファイルの確認後に申告内容が変わりました。再確認してください。"),
    "recorded_receipt_only": ("A saved receipt is historical; fresh checks are required.", "保存された確認記録は履歴です。今回のファイル確認が必要です。"),
    "evidence_not_checked": ("This referenced evidence file was not selected for checking.", "この参照ファイルは今回の確認対象に含まれていません。"),
    "file_missing": ("The evidence file is missing.", "根拠ファイルが見つかりません。"),
    "sha256_mismatch": ("The file differs from its declared SHA-256.", "ファイルが申告された SHA-256 と一致しません。"),
    "source_path_required": ("The source record needs an explicit path within the commit.", "ソースの記録には、コミット内のパスの明示が必要です。"),
    "repository_required": ("A local repository was not explicitly supplied for source binding.", "ソースとの対応確認に必要なローカルリポジトリが明示されていません。"),
    "git_source_path_missing": ("The recorded path is absent from the commit.", "記録されたパスがコミット内にありません。"),
    "git_source_bytes_mismatch": ("The file bytes differ from the blob at the recorded commit/path.", "ファイルのバイト列が、記録されたコミット・パスの blob と一致しません。"),
    "dirty_source_unsupported": ("Dirty-worktree source binding is unsupported.", "未コミットの変更を含むソースとの対応確認は非対応です。"),
    "unsafe_path": ("The evidence path is outside the supported safe path format.", "根拠のパスが安全に確認できる形式ではありません。"),
    "unsafe_root": ("The explicit evidence root could not be opened safely.", "明示された根拠ファイルのルートを安全に開けませんでした。"),
    "file_changed": ("The evidence file changed during checking.", "確認中に根拠ファイルが変更されました。"),
    "path_changed": ("A checked filesystem path changed during checking.", "確認中にファイルシステムのパスが変更されました。"),
    "not_regular_file": ("The evidence is not a supported regular file.", "根拠が対応可能な通常のファイルではありません。"),
    "hardlinked_file": ("Hard-linked evidence files are unsupported.", "ハードリンクされた根拠ファイルは非対応です。"),
    "size_limit": ("The evidence exceeds the bounded file-size limit.", "根拠ファイルが確認可能なサイズの上限を超えています。"),
    "total_read_limit": ("The total read budget was exhausted, including final rechecks.", "最終再確認を含む読み取り総量が上限に達しました。"),
    "time_limit": ("The bounded check reached its time limit.", "確認時間が上限に達しました。"),
    "git_object_unavailable": ("The required local Git object is unavailable.", "必要なローカル Git オブジェクトを確認できません。"),
    "git_commit_invalid": ("The recorded commit could not be verified locally.", "記録されたコミットをローカルで確認できませんでした。"),
}
for _code, (_en, _ja) in _INTEGRITY_REASONS.items():
    LABELS["en"]["i_reason_" + _code] = _en
    LABELS["ja"]["i_reason_" + _code] = _ja


WORKFLOW_LABELS = {
    "en": {
        "w_title": "Staged verification handoff", "w_status": "Workflow state",
        "w_next": "Next manual stage", "w_none": "No further stage recorded",
        "w_note": "Manual sequence: check conditions, independently seek counterevidence, then decide from the evidence. These records do not run AI agents or commands, authenticate artifacts, or verify reviewer identities.",
        "w_conditions": "1. Check conditions", "w_falsification": "2. Independent falsification",
        "w_decision": "3. Evidence-based decision", "w_stages": "Stage submissions",
        "w_history": "Recorded workflow history", "w_gaps": "Gaps and hold reasons",
        "w_lineage": "Evidence lineage", "w_input_digest": "Bound input SHA-256",
        "w_not_started": "Not started", "w_ready": "Ready for manual handoff",
        "w_held": "Held for more evidence", "w_error": "Invalid or failed stage",
        "w_unknown": "Unknown outcome", "w_conflict": "Conflicting evidence",
        "w_stale": "Stale inputs; restart verification", "w_complete": "Sequence complete (record checks only)",
        "w_pending": "Pending", "w_stage_complete": "Stage complete (record checks only)", "w_pass": "Recorded as passed", "w_fail": "Recorded as failed",
        "w_reviewer": "Recorded reviewer", "w_reason": "Reason", "w_recorded_at": "Recorded at",
        "w_evidence_ids": "Evidence IDs", "w_run_ids": "Test run IDs", "w_review_ids": "Review IDs",
        "w_submission_id": "Submission ID", "w_parent_submission_id": "Previous submission ID",
        "w_result": "Result", "w_event": "Event", "w_stage": "Stage",
        "w_actor": "Recorded actor", "w_summary": "Stage summary", "w_output_digest": "Resulting input SHA-256",
        "w_initialize": "Initialized", "w_submit": "Stage submitted", "w_resume": "Resumed", "w_invalidate": "Invalidated",
        "w_no_stages": "No stage submission has been recorded.",
        "w_no_history": "No workflow history has been recorded.",
        "w_safety": "Workflow completion is not a security guarantee or a verified fix.",
    },
    "ja": {
        "w_title": "段階的な検証の引き継ぎ", "w_status": "検証フローの状態",
        "w_next": "次に手動で行う段階", "w_none": "次の段階の記録なし",
        "w_note": "手動で成立条件の確認、独立した反証、証拠による判定の順に進めます。この記録は AI やコマンドを実行せず、証拠ファイルの真正性や確認者の本人性も証明しません。",
        "w_conditions": "1. 成立条件の確認", "w_falsification": "2. 独立した反証",
        "w_decision": "3. 証拠による判定", "w_stages": "各段階の提出記録",
        "w_history": "検証フローの履歴", "w_gaps": "不足する根拠・保留理由",
        "w_lineage": "根拠のつながり", "w_input_digest": "紐づく入力の SHA-256",
        "w_not_started": "未開始", "w_ready": "手動で次の段階へ引き継ぎ可能",
        "w_held": "根拠が不足しているため保留", "w_error": "無効な記録または段階の失敗",
        "w_unknown": "結果不明", "w_conflict": "根拠が矛盾", "w_stale": "入力が変更済み・検証を再開してください",
        "w_complete": "手順完了（記録の確認のみ）", "w_pending": "未完了", "w_stage_complete": "段階完了（記録の確認のみ）",
        "w_pass": "成功と記録", "w_fail": "失敗と記録", "w_reviewer": "記録上の確認者",
        "w_reason": "理由", "w_recorded_at": "記録日時", "w_evidence_ids": "根拠 ID",
        "w_run_ids": "テスト実行 ID", "w_review_ids": "再読 ID", "w_submission_id": "提出 ID",
        "w_parent_submission_id": "前の提出 ID", "w_result": "結果", "w_event": "イベント", "w_stage": "段階",
        "w_actor": "記録上の実施者", "w_summary": "段階の要約", "w_output_digest": "提出後の入力 SHA-256",
        "w_initialize": "開始", "w_submit": "段階の提出", "w_resume": "再開", "w_invalidate": "無効化",
        "w_no_stages": "各段階の提出記録はありません。", "w_no_history": "検証フローの履歴はありません。",
        "w_safety": "手順の完了は、安全性の保証や修正結果の検証を意味しません。",
    },
}
for _lang, _labels in WORKFLOW_LABELS.items():
    LABELS[_lang].update(_labels)


_WORKFLOW_GAPS = {
    "not_started": ("Initialize the manual verification sequence.", "手動で検証の手順を開始してください。"),
    "awaiting_submission": ("The next stage needs a manually supplied result.", "次の段階の結果を手動で提出してください。"),
    "stages_complete": ("All required stage records are complete.", "必要な段階の記録がそろっています。"),
    "input_changed": ("The input differs from the recorded handoff. Restart from conditions.", "入力が引き継ぎ時の記録と異なります。成立条件の確認から再開してください。"),
    "manually_invalidated": ("The workflow was explicitly invalidated. Restart from conditions.", "検証フローは明示的に無効化されました。成立条件の確認から再開してください。"),
    "stage_held": ("The stage was held; supply the missing evidence before resuming.", "段階は保留中です。足りない根拠を補ってから再開してください。"),
    "stage_error": ("The stage recorded an error and cannot advance.", "段階にエラーが記録されているため、先へ進めません。"),
    "stage_unknown": ("The stage outcome is unknown and cannot advance.", "段階の結果が不明なため、先へ進めません。"),
    "stage_conflict": ("The stage recorded conflicting evidence that needs review.", "根拠の矛盾が記録されています。内容を再確認してください。"),
    "verification_incomplete": ("The supplied evidence does not support a definitive decision.", "提出された根拠では最終判定に進めません。"),
}
for _code, (_en, _ja) in _WORKFLOW_GAPS.items():
    LABELS["en"]["w_gap_" + _code] = _en
    LABELS["ja"]["w_gap_" + _code] = _ja
LABELS["en"].update(w_init="Initialized", w_scope="Frozen handoff scope", w_current_digest="Current input SHA-256", w_event_digest="Journal event SHA-256",
                    w_previous_event_digest="Previous journal event SHA-256", w_recorded_digest="Recorded workflow tip SHA-256",
                    w_restart="Restarted from conditions; earlier stage records are historical",
                    w_continue="Resumed the held stage with unchanged inputs")
LABELS["ja"].update(w_init="開始", w_scope="引き継ぎ時に固定した範囲", w_current_digest="現在の入力 SHA-256", w_event_digest="履歴イベントの SHA-256",
                    w_previous_event_digest="前の履歴イベントの SHA-256", w_recorded_digest="記録されたフロー末尾の SHA-256",
                    w_restart="成立条件の確認から再開。以前の段階は履歴として保持",
                    w_continue="入力を変更せず、保留した段階を再開")


THREE_PASS_LABELS = {
    "en": {
        "p_history": "Historical discovery (not current proof)",
        "p_claim": "Claim challenged", "p_scope_checks": "Recorded scope challenges",
        "p_title": "Three-pass assurance review", "p_status": "Assessment state",
        "p_complete": "Three passes complete (declared scope and records only)",
        "p_held": "Held: review gaps remain", "p_not_started": "Not started",
        "p_discovery": "1. Discovery and scope coverage",
        "p_conditions": "2. Finding conditions",
        "p_challenge": "3. Independent challenge and decision",
        "p_pass_complete": "Complete (record checks only)",
        "p_count_cells": "{completed}/{total} planned scope cells accounted for",
        "p_count_findings": "{completed}/{total} findings complete",
        "p_challenge_count": "Scope challenge: {completed}/{total} planned cells reviewed",
        "p_note": "Three ordered passes: record discovery across the planned scope, verify each finding's conditions, then independently challenge the evidence and record a decision. Actor labels are declarations, not authenticated identities.",
        "p_safety": "Completeness covers the declared scope and supplied records only. It is not an accuracy percentage, proof that all vulnerabilities were found, a security guarantee, or verification of a fix. No AI provider or application test is run by this report.",
        "p_gaps": "Outstanding gaps", "p_discovery_record": "Recorded discovery coverage",
        "p_finding_states": "Current finding handoffs", "p_missing_coverage": "Missing discovery coverage IDs",
        "p_missing_challenge": "Missing scope-challenge IDs", "p_untracked_findings": "Findings missing discovery mapping",
        "p_checked": "Checked", "p_not_applicable": "Not applicable (evidence required)",
        "p_not_checked": "Not checked", "p_target": "Target", "p_coverage_id": "Coverage ID",
        "p_finding_ids": "Finding IDs", "p_summary": "Discovery summary",
        "p_gap_unknown": "Required review records are incomplete; inspect the current handoff.",
    },
    "ja": {
        "p_history": "過去の発見記録（現在の根拠ではありません）",
        "p_claim": "反証した成立条件", "p_scope_checks": "対象範囲の反証記録",
        "p_title": "3パスの確認", "p_status": "診断全体の状態",
        "p_complete": "3パス完了（申告された範囲と記録のみ）",
        "p_held": "保留：確認の不足あり", "p_not_started": "未開始",
        "p_discovery": "1. 候補の発見と対象範囲の確認", "p_conditions": "2. 指摘の成立条件の確認",
        "p_challenge": "3. 独立した反証と判定", "p_pass_complete": "完了（記録の確認のみ）",
        "p_count_cells": "計画した対象 {total} 件中 {completed} 件を確認",
        "p_count_findings": "指摘 {total} 件中 {completed} 件が完了",
        "p_challenge_count": "対象範囲の再確認：計画した対象 {total} 件中 {completed} 件",
        "p_note": "計画した対象範囲の発見記録、各指摘の成立条件、独立した反証と判定の順に進めます。実施者の名前は申告であり、本人確認済みの身元ではありません。",
        "p_safety": "完了は申告された範囲と提出された記録のみを対象とします。精度の割合、すべての脆弱性の発見、安全性の保証、修正結果の検証を意味しません。このレポートは AI サービスやアプリのテストを実行しません。",
        "p_gaps": "未完了の確認事項", "p_discovery_record": "対象範囲ごとの発見記録",
        "p_finding_states": "各指摘の現在の引き継ぎ", "p_missing_coverage": "発見記録が不足する対象 ID",
        "p_missing_challenge": "反証の確認が不足する対象 ID", "p_untracked_findings": "発見記録と対応していない指摘",
        "p_checked": "確認済み", "p_not_applicable": "対象外（根拠が必要）", "p_not_checked": "未確認",
        "p_target": "対象", "p_coverage_id": "対象 ID", "p_finding_ids": "指摘 ID",
        "p_summary": "発見の要約", "p_gap_unknown": "必要な確認記録が不足しています。現在の引き継ぎを確認してください。",
    },
}
for _lang, _labels in THREE_PASS_LABELS.items():
    LABELS[_lang].update(_labels)

_THREE_PASS_GAPS = {
    "coverage_incomplete": ("Discovery has not accounted for every planned cell.", "計画したすべての対象について、発見時の確認記録がそろっていません。"),
    "findings_untracked": ("Some findings are not mapped to discovery coverage.", "発見時の確認対象に対応していない指摘があります。"),
    "discovery_incomplete": ("Complete the discovery records before advancing.", "先へ進む前に発見時の記録を完成させてください。"),
    "workflows_incomplete": ("Some findings still need current, complete handoffs.", "現在の入力に対応した引き継ぎが未完了の指摘があります。"),
    "no_findings": ("No candidates are recorded. Zero findings does not establish security or complete this assurance profile.", "指摘候補が記録されていません。指摘がゼロでも、安全性の確認やこの確認手順の完了にはなりません。"),
    "coverage_challenge_incomplete": ("Independent challenge does not cover the full declared scope.", "独立した反証が申告された対象範囲全体をカバーしていません。"),
    "coverage_challenge_unresolved": ("Scope challenge contains unresolved or contradictory evidence.", "対象範囲の再確認に未解決または矛盾する根拠があります。"),
    "actors_not_independent": ("Discovery, conditions and challenge require distinct declared actors.", "発見・成立条件・反証には、それぞれ異なる実施者の申告が必要です。"),
    "falsification_claims_incomplete": ("Independent negative checks must address all four claims.", "独立した反証では、4つの成立条件すべての確認が必要です。"),
    "review_incomplete": ("An independent reviewer must cover all claim evidence at every severity.", "すべての重大度で、成立条件の全根拠を独立した確認者が再読する必要があります。"),
}
for _code, (_en, _ja) in _THREE_PASS_GAPS.items():
    LABELS["en"]["p_gap_" + _code] = _en
    LABELS["ja"]["p_gap_" + _code] = _ja
for _code, _source in {
    "three_pass_discovery_incomplete": "coverage_incomplete",
    "three_pass_candidates_untracked": "findings_untracked",
    "three_pass_independence_missing": "actors_not_independent",
    "three_pass_negative_checks_incomplete": "falsification_claims_incomplete",
    "three_pass_review_coverage_incomplete": "review_incomplete",
    "three_pass_scope_challenge_incomplete": "coverage_challenge_incomplete",
    "three_pass_scope_contradiction": "coverage_challenge_unresolved",
    "three_pass_workflow_missing": "workflows_incomplete",
    "three_pass_no_candidates": "no_findings",
    "three_pass_workflows_incomplete": "workflows_incomplete",
}.items():
    for _lang in ("en", "ja"):
        LABELS[_lang]["p_gap_" + _code] = LABELS[_lang]["p_gap_" + _source]
        LABELS[_lang]["w_gap_" + _code] = LABELS[_lang]["p_gap_" + _source]

EXPERT_LABELS = {
    "en": {
        "e_title": "Assessment method and assurance", "e_status": "Expert record gate state", "cwe": "CWE",
        "e_complete": "Declared expert record gates met; final audit not established here",
        "e_held": "Held: declared expert record gates remain open",
        "e_degraded": "Degraded: single-agent run, independent checks unavailable",
        "e_mode": "Mode", "e_full": "full (declared worker roles)", "e_single": "single agent (declared)",
        "e_engines": "Engines", "e_cross": "cross-engine", "e_mono": "single engine (declared)",
        "e_workers": "Recorded workers: {spawns}; declared approved ceiling: {ceiling}",
        "e_recon": "Recon records: {recon_actors} actors; {routes} reconciled entry points; {recon_disagreements} disagreements",
        "e_discovery": "Discovery records: {redundant_cells}/{cells} scope cells meet redundancy checks; {discovery_passes} passes, {raw_candidates} raw candidates, {findings} findings",
        "e_variants": "Variant records: {variant_hits} similar locations; {variant_findings} added findings",
        "e_omission": "Omission challenge records: {omission_passes} pass(es) looking for a missing vulnerability class",
        "e_panels": "Refutation panel records: {panels} findings; survived {skeptic_survived}, refuted {skeptic_refuted}, unproven {skeptic_unproven}",
        "e_severity": "Severity records: {raters_calibrated}/{raters} raters meet calibration checks; {rated}/{active} findings have two ratings, {severity_agreed} without adjudication",
        "e_reception": "Reception records: {personas}/3 personas (executive, engineer, auditor)",
        "e_qa": "Recorded QA result: {qa}",
        "e_gaps": "Open gates",
        "e_note": "The status and counts describe declared records for discovery, condition tracing, refutation and severity review. They do not establish whether the final audit of run files and report outputs passed.",
        "e_safety": "Worker labels and records are declarations; their number does not certify independence or correctness, and no detection rate or guarantee that all vulnerabilities were found follows from them.",
        "e_gap": "Gate not met",
    },
    "ja": {
        "e_title": "診断の方法と品質保証", "e_status": "エキスパート宣言レコードのゲート状態", "cwe": "CWE",
        "e_complete": "宣言レコードのゲートを充足：最終監査の合否はこの表示では未検証",
        "e_held": "保留：宣言レコードに未充足のゲートあり",
        "e_degraded": "縮退：単一エージェント実行のため独立確認なし",
        "e_mode": "実行形態", "e_full": "フル（ワーカーの役割を申告）", "e_single": "単一エージェント（申告）",
        "e_engines": "エンジン", "e_cross": "複数エンジン", "e_mono": "単一エンジン（申告）",
        "e_workers": "ワーカーの記録：{spawns} 件、申告された承認上限 {ceiling}",
        "e_recon": "攻撃面調査の記録：実施者 {recon_actors} 名、統合後の入口 {routes} 件、食い違い {recon_disagreements} 件",
        "e_discovery": "発見の記録：対象 {cells} 件中 {redundant_cells} 件が重複確認の条件を充足。{discovery_passes} パス、候補 {raw_candidates} 件、指摘 {findings} 件",
        "e_variants": "類似箇所調査の記録：{variant_hits} 箇所、追加指摘 {variant_findings} 件",
        "e_omission": "見落とし検証の記録：脆弱性の分類漏れを探すパス {omission_passes} 件",
        "e_panels": "反証パネルの記録：指摘 {panels} 件。耐えた {skeptic_survived}・反証 {skeptic_refuted}・未証明 {skeptic_unproven}",
        "e_severity": "重大度の記録：評価者 {raters} 名中 {raters_calibrated} 名が較正条件を充足。指摘 {active} 件中 {rated} 件に2件の評価、{severity_agreed} 件は調停なしで一致",
        "e_reception": "受け手確認の記録：経営層・開発者・監査人の役割 {personas}/3",
        "e_qa": "記録された QA の結果：{qa}",
        "e_gaps": "未充足のゲート",
        "e_note": "状態と数値は、発見・成立条件の追跡・反証・重大度評価についての申告記録を示します。実行記録ファイルとレポート出力を対象とする最終監査の合格を示すものではありません。",
        "e_safety": "ワーカー名と記録は申告です。人数は独立性や正しさを保証せず、検出率やすべての脆弱性の発見を意味しません。",
        "e_gap": "未充足",
    },
}
for _lang, _labels in EXPERT_LABELS.items():
    LABELS[_lang].update(_labels)

_GAP_LABELS = {
    "legacy_details_missing": ("Detailed verification evidence was not recorded.", "詳細な検証根拠が記録されていません。"),
    "verdict_unresolved": ("The finding verdict has not been settled.", "指摘の妥当性判定がまだ確定していません。"),
    "claims_incomplete": ("One or more required claims lack support.", "必要な成立条件の根拠が不足しています。"),
    "falsification_incomplete": ("Counterevidence checks are incomplete or unresolved.", "反証の確認が未完了、または未解決です。"),
    "review_missing": ("An independent evidence review is missing.", "別の確認者による根拠の再読がありません。"),
    "review_disagreement": ("Reviewer disagreement remains unresolved.", "確認者間の見解の相違が未解決です。"),
    "environment_unknown": ("Required environment conditions have not been verified.", "必要な環境条件が未確認です。"),
    "runtime_incomplete": ("A runtime attempt is incomplete; it is not reproduction evidence.", "実行検証は未完了で、再現の根拠にはなりません。"),
    "runtime_contradiction": ("A completed security test contradicts the claimed violation; reconcile the evidence.", "実行済みの安全条件テストが指摘の成立と矛盾しています。根拠を再確認してください。"),
    "runtime_boundary_unverified": ("The security boundary was not verified through the real implementation.", "検証対象の実装を通した境界確認ができていません。"),
    "retest_missing": ("The recorded fix has no complete retest record.", "修正の申告に対応する再検査記録がありません。"),
    "retest_before_unverified": ("The vulnerable version lacks a qualifying assertion failure.", "修正前の版で安全条件が失敗した根拠が不足しています。"),
    "retest_after_unverified": ("The fixed version lacks a successful security retest.", "修正後の版で安全条件を再検査した成功記録がありません。"),
    "retest_case_mismatch": ("Before and after runs do not test the same case.", "修正前後で検査ケースが一致していません。"),
    "retest_context_mismatch": ("Before and after execution conditions do not match.", "修正前後の実行条件が一致していません。"),
    "retest_version_mismatch": ("A retest does not match its intended source version.", "再検査の対象版が指定された版と一致していません。"),
    "retest_control_missing": ("Positive-control evidence is missing.", "正常系の対照検査がありません。"),
    "retest_control_failed": ("A positive control did not pass under the required conditions.", "正常系の対照検査が必要な条件で成功していません。"),
    "retest_regression_missing": ("Regression evidence is missing.", "回帰検査の根拠がありません。"),
    "retest_regression_failed": ("A regression test did not pass under the required conditions.", "回帰検査が必要な条件で成功していません。"),
    "retest_verification_incomplete": ("The original finding lacks sufficient verification.", "元の指摘を確かめる検証根拠が不足しています。"),
}
for _code, (_en, _ja) in _GAP_LABELS.items():
    LABELS["en"]["v_gap_" + _code] = _en
    LABELS["ja"]["v_gap_" + _code] = _ja


class SchemaError(Exception):
    pass


def http_url(value, field="url"):
    """Validate every href, not just its HTML escaping."""
    if not isinstance(value, str) or not value or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value) or "\\" in value:
        raise SchemaError(f"{field}: must be an absolute http(s) URL without whitespace or controls")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme.lower() not in ("http", "https") or not parsed.hostname
                or parsed.username is not None or parsed.password is not None):
            raise ValueError("unsafe URL")
        parsed.port  # Reject malformed/out-of-range ports too.
    except ValueError:
        raise SchemaError(f"{field}: must be an absolute http(s) URL without credentials") from None
    return value


def text_field(obj, key, where, *, required=False, default=""):
    """Validate before coercion, hashing, sorting, or rendering can hide bad input."""
    value = obj.get(key, default)
    field = f"{where}.{key}" if where else key
    if not isinstance(value, str):
        raise SchemaError(f"{field}: must be a string")
    if required and not value.strip():
        raise SchemaError(f"{field}: required nonblank string")
    return value


def validate_json_values(data):
    """Reject values that UTF-8 HTML or the dashboard's JSON parser cannot read."""
    pending = [("", data)]
    while pending:
        where, value = pending.pop()
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise SchemaError(f"{where or 'top level'}: must contain valid Unicode text") from None
        elif isinstance(value, float) and not math.isfinite(value):
            raise SchemaError(f"{where or 'top level'}: number must be finite")
        elif isinstance(value, list):
            pending.extend((f"{where}[{i}]", entry) for i, entry in enumerate(value))
        elif isinstance(value, dict):
            for key, entry in value.items():
                # Validate the key before using it in an error message.
                try:
                    key.encode("utf-8")
                except UnicodeEncodeError:
                    raise SchemaError(f"{where or 'top level'}: invalid Unicode object key") from None
                pending.append((f"{where}.{key}" if where else key, entry))


def load(path):
    def invalid_constant(value):
        raise SchemaError(f"{path}: invalid JSON constant {value}")

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=invalid_constant)
    except json.JSONDecodeError as e:
        raise SchemaError(f"{path}: invalid JSON: {e}")
    except UnicodeError:
        raise SchemaError(f"{path}: must be UTF-8 text") from None
    except ValueError:
        raise SchemaError(f"{path}: invalid JSON numeric value") from None
    except RecursionError:
        raise SchemaError(f"{path}: JSON nesting is too deep") from None
    return validate_data(data)


def validate_data(data):
    """Validate and normalize a parsed report using the same contract as the CLI."""
    validate_json_values(data)
    if not isinstance(data, dict):
        raise SchemaError("top level must be an object")
    # Fresh verification is an explicit in-memory argument, never input JSON.
    data.pop("_evidence_integrity", None)
    meta = data.get("meta")
    if not isinstance(meta, dict):
        raise SchemaError("meta: required object")
    for k in ("project", "date"):
        text_field(meta, k, "meta", required=True)
    for k in ("assessor", "scope", "method", "commit"):
        text_field(meta, k, "meta")
    if meta.get("source_url") not in (None, ""):
        meta["source_url"] = http_url(meta["source_url"], "meta.source_url")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise SchemaError("findings: required list")
    seen = set()
    for i, f in enumerate(findings):
        where = f"findings[{i}]"
        if not isinstance(f, dict):
            raise SchemaError(f"{where}: must be an object")
        # These are derived output fields, never trusted JSON input.
        f.pop("source_link", None)
        f.pop("snippet", None)
        f.pop("_evidence_integrity", None)
        for k in ("id", "title", "severity", "confidence", "location"):
            text_field(f, k, where, required=True)
        if any(ord(char) < 32 or ord(char) == 127 for char in f["location"]):
            raise SchemaError(f"{where}.location: must not contain control characters")
        match = LOC_RE.match(f["location"].strip())
        if match:
            try:
                int(match.group("start"))
                int(match.group("end") or match.group("start"))
            except ValueError:
                raise SchemaError(f"{where}.location: line numbers cannot be parsed") from None
        if f["id"] in seen:
            raise SchemaError(f"{where}.id: duplicate {f['id']}")
        seen.add(f["id"])
        if f["severity"] not in SEVERITIES:
            raise SchemaError(f"{where}.severity: one of {SEVERITIES}")
        if f["confidence"] not in CONFIDENCES:
            raise SchemaError(f"{where}.confidence: one of {CONFIDENCES}")
        f["status"] = text_field(f, "status", where, default="Open")
        if f["status"] not in STATUSES:
            raise SchemaError(f"{where}.status: one of {STATUSES}")
        for k in ("category", "actor", "request", "impact", "fix"):
            f[k] = text_field(f, k, where)
        if "cwe" in f:
            # Optional text fields may be an empty string (findings-schema.md).
            if not text_field(f, "cwe", where):
                del f["cwe"]
            elif not CWE_RE.fullmatch(f["cwe"]):
                raise SchemaError(f"{where}.cwe: CWE-<number>")
        if not f["category"]:
            f["category"] = "Uncategorized"
        val = f.get("validation", {})
        if not isinstance(val, dict):
            raise SchemaError(f"{where}.validation: must be an object")
        val["verdict"] = text_field(val, "verdict", f"{where}.validation", default="Unverified")
        if val["verdict"] not in VERDICTS:
            raise SchemaError(f"{where}.validation.verdict: one of {VERDICTS}")
        evidence = text_field(val, "evidence", f"{where}.validation")
        text_field(val, "method", f"{where}.validation")
        if val["verdict"] in ("Valid", "FalsePositive", "NotApplicable") and not evidence.strip():
            raise SchemaError(f"{where}.validation.evidence: required when verdict is {val['verdict']}")
        val["evidence"] = evidence
        f["validation"] = val
        f["verdict"] = val["verdict"]
        if "previous_validation" in f:
            previous = f["previous_validation"]
            if not isinstance(previous, dict):
                raise SchemaError(f"{where}.previous_validation: must be an object")
            for k in ("verdict", "evidence", "method"):
                text_field(previous, k, f"{where}.previous_validation")
        refs = f.get("references", [])
        if not isinstance(refs, list):
            raise SchemaError(f"{where}.references: must be a list")
        clean = []
        for j, r in enumerate(refs):
            if isinstance(r, str):
                r = {"url": r}
            if not isinstance(r, dict):
                raise SchemaError(f"{where}.references[{j}]: must be an object or URL")
            ref_where = f"{where}.references[{j}]"
            http_url(r.get("url"), f"{ref_where}.url")
            clean.append({"type": text_field(r, "type", ref_where) or "web", "url": r["url"],
                          "title": text_field(r, "title", ref_where)})
        f["references"] = clean
    for k in ("checked_ok", "decisions", "limitations", "next_steps"):
        v = data.get(k, [])
        if not isinstance(v, list):
            raise SchemaError(f"{k}: must be a list")
        for j, entry in enumerate(v):
            if not isinstance(entry, str):
                raise SchemaError(f"{k}[{j}]: must be a string")
        data[k] = v
    lens = data.get("perspectives", [])
    if not isinstance(lens, list):
        raise SchemaError("perspectives: must be a list")
    for j, perspective in enumerate(lens):
        where = f"perspectives[{j}]"
        if not isinstance(perspective, dict):
            raise SchemaError(f"{where}: must be an object")
        text_field(perspective, "name", where, required=True)
        for k in ("result", "note"):
            text_field(perspective, k, where)
    data["perspectives"] = lens
    validate_verification(data, SchemaError)
    validate_workflows(data, SchemaError)
    validate_ledger(data, SchemaError)
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    # code findings before dependency advisories (D-*) at the same severity
    findings.sort(key=lambda f: (rank[f["severity"]], str(f["id"]).startswith("D-"), f["id"]))
    return data


def active(data):
    return [f for f in data["findings"] if f["verdict"] not in EXCLUDED]


def stats(data):
    fs = active(data)
    return {
        "verdict": Counter(f["verdict"] for f in data["findings"]),
        "excluded": len(data["findings"]) - len(fs),
        "severity": Counter(f["severity"] for f in fs),
        "confidence": Counter(f["confidence"] for f in fs),
        "category": Counter(f["category"] for f in fs),
        "status": Counter(f["status"] for f in fs),
        "open_hm": sum(1 for f in fs if f["status"] == "Open" and f["severity"] in ("High", "Medium")),
    }


def finding_part(finding):
    return "deps" if str(finding["id"]).startswith("D-") else "code"


def finding_anchor(data, finding):
    """Generated anchors never interpret finding IDs as HTML or CSS."""
    return "finding-" + str(next(i for i, f in enumerate(data["findings"], 1) if f is finding))


def action_kind(finding, verification=None, workflow=None):
    # A severity alone is not evidence that a finding applies to this project.
    # Derived state must come from the complete record, never an input flag.
    return ("fix_now" if finding["status"] == "Open" and finding["verdict"] == "Valid"
            and finding["confidence"] == "Confirmed"
            and (verification or {}).get("level") in ("static_supported", "runtime_supported")
            and (("verification_workflow" not in finding and workflow is None)
                 or (workflow or {}).get("status") == "complete")
            else "verify_first")


def public_verification_state(state):
    """Private trace IDs are rendered through the redacted view, not serialized raw."""
    return {key: state[key] for key in ("level", "retest", "gaps")}


def display_finding(finding, state):
    """Only curated verification details enter the report's embedded payload."""
    public = {key: finding[key] for key in (
        "id", "title", "severity", "confidence", "location", "status", "category",
        "actor", "request", "impact", "fix", "validation", "verdict", "previous_validation",
        "references", "source_link", "snippet", "cwe") if key in finding}
    public["part"] = finding_part(finding)
    public["_verification"] = public_verification_state(state)
    return public


def workflow_states(data, integrity=None):
    """Only schema-2 opt-in records affect the staged workflow display."""
    return {f["id"]: derive_workflow(data, f, SchemaError, integrity=integrity) for f in data["findings"]
            if data.get("schema_version") == 2 and ("verification_workflow" in f or "three_pass" in data)}


def report_model(data, integrity=None):
    """One report-wide action model shared by both outputs; never mutates verdicts."""
    fs = active(data)
    verification = derive_verification(data, SchemaError, integrity=integrity)
    workflows = workflow_states(data, integrity=integrity)
    profile = derive_three_pass(data, SchemaError, integrity=integrity)
    queue = [{"finding": display_finding(f, verification[f["id"]]),
              "action": action_kind(f, verification[f["id"]], workflows.get(f["id"])), "anchor": finding_anchor(data, f)}
             for f in fs if f["status"] == "Open"]
    queue.sort(key=lambda item: (SEVERITIES.index(item["finding"]["severity"]),
                                item["action"] != "fix_now", item["finding"]["part"] == "deps",
                                str(item["finding"]["id"])))
    return {
        **({"three_pass": {"status": profile["status"],
                          "passes": [{key: item[key] for key in ("id", "status", "completed", "total")}
                                     for item in profile["passes"]]}} if profile["opted_in"] else {}),
        **({"workflows": {key: {"status": state["status"], "next_stage": state["next_stage"]}
                           for key, state in workflows.items()}} if workflows else {}),
        "open_count": len(queue),
        "fix_now": sum(item["action"] == "fix_now" for item in queue),
        "verify_first": sum(item["action"] == "verify_first" for item in queue),
        "fixed": sum(f["status"] == "Fixed" for f in fs),
        "accepted": sum(f["status"] == "Accepted" for f in fs),
        "excluded": len(data["findings"]) - len(fs),
        "unverified": sum(f["verdict"] == "Unverified" for f in fs),
        "unverified_high": sum(f["verdict"] == "Unverified" and f["severity"] == "High" for f in fs),
        "verification": {key: public_verification_state(state) for key, state in verification.items()},
        "verification_counts": {
            "static": sum(verification[f["id"]]["level"] == "static_supported" for f in fs),
            "runtime": sum(verification[f["id"]]["level"] == "runtime_supported" for f in fs),
            "pending": sum(verification[f["id"]]["level"] not in
                           ("static_supported", "runtime_supported") for f in fs),
            "retested": sum(verification[f["id"]]["retest"] == "verified" for f in fs),
        },
        "parts": {part: {
            "total": sum(finding_part(f) == part for f in fs),
            "open_count": sum(item["finding"]["part"] == part for item in queue),
            "fix_now": sum(item["finding"]["part"] == part and item["action"] == "fix_now" for item in queue),
            "verify_first": sum(item["finding"]["part"] == part and item["action"] == "verify_first" for item in queue),
            "open_hm": sum(item["finding"]["part"] == part and item["finding"]["severity"] in ("High", "Medium")
                           for item in queue),
        } for part in PARTS},
        "queue": queue,
    }


def esc(s):
    return html.escape(str(s or ""))


ASSESSMENT_LABELS = {
    "en": {
        "a_kicker": "Security review",
        "a_open": "Open findings",
        "a_fix_now": "Plan the fix",
        "a_verify_first": "Verify first",
        "a_summary": "{unverified_high} High findings remain Unverified. {open_count} findings are open: {fix_now} ready for remediation and {verify_first} needing validation first.",
        "a_accounting": "{total} non-excluded findings in total: {open_count} Open, {fixed} Fixed and {accepted} Accepted. {excluded} excluded findings are retained separately. {unverified} non-excluded findings remain Unverified across all statuses.",
        "a_status_note": "Status is the recorded workflow state; Fixed and Accepted do not establish that remediation was independently verified.",
        "a_uncertainty": "Coverage is limited to the recorded scope and checks. Missing coverage is unknown, and no open findings does not establish that the system is secure.",
        "a_limits": "Assessment limits",
        "a_limits_empty": "No limitations were recorded. Coverage completeness has not been established.",
        "a_queue": "Priority queue",
        "a_cap_metrics": "Open findings by next action.",
        "a_cap_queue": "Open findings in order of severity and readiness to fix; the full entry for each follows in the finding details.",
        "a_cap_coverage": "Review perspectives with the recorded result and note for each.",
        "a_cap_index": "All non-excluded findings with their recorded state and evidence basis.",
        "a_queue_note": "Open, non-excluded findings only. Ordered by severity, then ready-to-fix findings before findings needing validation, then ID. Planning a fix requires Valid, Confirmed and sufficient structured verification; legacy or incomplete evidence requires validation first.",
        "a_queue_empty": "No open, non-excluded findings are recorded. Review the coverage and limitations before drawing conclusions.",
        "a_finding": "Finding",
        "a_next_action": "Next action",
        "a_verify_action": "Confirm reachability, preconditions and impact; record the evidence and update the verdict.",
        "a_fix_missing": "A remediation direction has not been recorded. Define it before implementation.",
        "a_fix_proposal": "Recorded fix direction",
        "a_coverage": "Recorded coverage",
        "a_coverage_note": "Perspective results and successful checks describe only what was recorded. They are not a completeness measure or a guarantee.",
        "a_coverage_empty": "No perspective coverage was recorded.",
        "a_checks": "Recorded successful checks",
        "a_checks_empty": "No successful checks were recorded.",
        "a_register": "Finding register",
        "a_register_note": "Links lead to the complete finding records below. Excluded findings are listed separately and do not contribute to active counts.",
        "a_register_empty": "No non-excluded findings were recorded.",
        "a_evidence_state": "Evidence state",
        "a_method": "Validation method",
        "a_not_recorded": "Not recorded",
        "a_evidence_missing": "Validation evidence has not been recorded.",
        "a_back_to_register": "Back to finding register",
        "a_excluded_note": "These findings are retained for traceability, but excluded from the priority queue and all non-excluded totals. Their verdict and evidence explain why they were ruled out.",
        "a_no_decisions": "No decisions were recorded.",
        "a_no_next_steps": "No additional next steps were recorded.",
    },
    "ja": {
        "a_kicker": "セキュリティレビュー",
        "a_open": "未対応の指摘",
        "a_fix_now": "修正を計画",
        "a_verify_first": "先に検証する",
        "a_summary": "重大度 High のうち{unverified_high}件が Unverified（未検証）です。未対応は{open_count}件で、{fix_now}件は修正に進める指摘、{verify_first}件は先に検証が必要な指摘です。",
        "a_accounting": "除外対象を除く指摘は計{total}件（Open {open_count}件、Fixed {fixed}件、Accepted {accepted}件）。除外した{excluded}件は別記しています。全対応状況を通じ、除外対象を除く Unverified（未検証）は{unverified}件です。",
        "a_status_note": "対応状況は記録された状態です。Fixed や Accepted は、修正結果を独立して再検証済みであることを示すものではありません。",
        "a_uncertainty": "診断結果は記録された範囲と確認内容に限られます。記載のない範囲は未確認であり、未対応の指摘がないこともシステム全体の安全性の保証にはなりません。",
        "a_limits": "診断の制約",
        "a_limits_empty": "制約事項の記載はありません。診断範囲の網羅性は確認されていません。",
        "a_queue": "優先対応一覧",
        "a_cap_metrics": "次の対応別の未解決指摘数。",
        "a_cap_queue": "重大度と修正準備の順に並べた未解決指摘。各指摘の全文は指摘の詳細に続きます。",
        "a_cap_coverage": "診断観点ごとの記録された結果と注記。",
        "a_cap_index": "除外を除くすべての指摘と、記録された状態および根拠。",
        "a_queue_note": "未対応かつ除外されていない指摘のみを掲載しています。重大度、修正に進めるか検証が必要か、ID の順に並べています。修正に進む対象は Valid・Confirmed に加え構造化された検証根拠がそろった指摘です。従来形式や根拠不足の指摘は先に検証が必要です。",
        "a_queue_empty": "未対応かつ除外されていない指摘は記録されていません。結論を出す前に、診断範囲と制約を確認してください。",
        "a_finding": "指摘事項",
        "a_next_action": "次の対応",
        "a_verify_action": "到達可能性、前提条件、影響を確認し、根拠を記録して妥当性の判定を更新してください。",
        "a_fix_missing": "対応方針が記録されていません。実装前に修正方針を決めてください。",
        "a_fix_proposal": "記録された対応方針",
        "a_coverage": "記録された確認範囲",
        "a_coverage_note": "観点別の結果と問題がなかった確認項目は、記録された確認内容のみを示します。網羅率や安全性を保証するものではありません。",
        "a_coverage_empty": "観点別の確認範囲は記録されていません。",
        "a_checks": "問題がなかった確認項目",
        "a_checks_empty": "問題がなかった確認項目は記録されていません。",
        "a_register": "指摘事項の索引",
        "a_register_note": "各リンクから詳細に移動できます。除外した指摘は別記し、除外対象を除く件数には含めていません。",
        "a_register_empty": "除外対象を除く指摘は記録されていません。",
        "a_evidence_state": "根拠の状態",
        "a_method": "検証方法",
        "a_not_recorded": "記載なし",
        "a_evidence_missing": "妥当性の根拠は記録されていません。",
        "a_back_to_register": "指摘事項の索引に戻る",
        "a_excluded_note": "経緯を追跡できるよう記録を残していますが、優先対応一覧と除外対象を除く集計には含めていません。除外した理由は妥当性の判定と根拠に記載しています。",
        "a_no_decisions": "判断が必要な事項は記録されていません。",
        "a_no_next_steps": "追加の対応手順は記録されていません。",
    },
}


ASSESSMENT_CSS = """
@page{
  size:A4;margin:22mm 22mm 24mm;
  @bottom-left{content:"SECURITY ASSESSMENT";font:7.5pt "Hiragino Sans","Noto Sans CJK JP",sans-serif;color:#5a5a5a}
  @bottom-right{content:counter(page) " / " counter(pages);font:7.5pt "Hiragino Sans","Noto Sans CJK JP",sans-serif;color:#5a5a5a}
}
:root{--ink:#1b1b1b;--muted:#5a5a5a;--rule:#1b1b1b;--hair:#dcd9d2;--high:#8a1c1c;--medium:#7a4800;--low:#24476e;--link:#1f3f66;--mark:#f3ecd6;
  --serif:"Hiragino Mincho ProN","Noto Serif CJK JP","Yu Mincho",Georgia,serif;
  --sans:"Hiragino Sans","Noto Sans CJK JP","Noto Sans JP","Yu Gothic",Arial,sans-serif;
  --mono:"DejaVu Sans Mono",Menlo,Consolas,monospace}
*{box-sizing:border-box}
html{background:#fff}
body{margin:0;color:var(--ink);background:#fff;font:10pt/1.65 var(--serif);font-variant-numeric:lining-nums tabular-nums;overflow-wrap:anywhere;word-wrap:break-word;counter-reset:section table listing;hanging-punctuation:allow-end}
h1,h2,h3,h4,h5{color:var(--ink);font-family:var(--serif);font-weight:700;break-after:avoid;page-break-after:avoid}
h1{font-size:20pt;line-height:1.25;margin:0 0 2mm;letter-spacing:-.1pt}
h2{font-size:13pt;line-height:1.3;margin:9mm 0 3mm}
h3{font-size:11pt;line-height:1.4;margin:5mm 0 2mm}
h4{font:700 7.8pt/1.4 var(--sans);letter-spacing:.08em;color:var(--muted);margin:3.5mm 0 1mm}
h5{font-size:9.5pt;margin:3mm 0 1mm}
main>section>h2{counter-increment:section}
main>section>h2::before{content:counter(section);display:inline-block;min-width:8mm;font-weight:400}
p{margin:0 0 2.5mm;orphans:3;widows:3}
ul,ol{margin:1.5mm 0 3mm;padding-left:5mm}
li{margin:0 0 1mm;orphans:2;widows:2}
a{color:var(--link);text-decoration:underline;text-decoration-thickness:.4pt;text-underline-offset:2px;overflow-wrap:anywhere;word-wrap:break-word}
code{font:8.4pt/1.45 var(--mono);overflow-wrap:anywhere;word-wrap:break-word;word-break:break-all}
.report-header{margin:0 0 8mm;padding:0 0 4mm;border-bottom:.6pt solid var(--rule)}
.kicker{font:700 7.8pt/1.4 var(--sans);letter-spacing:.18em;color:var(--muted);margin:0 0 5mm;padding-bottom:2mm;border-bottom:1.2pt solid var(--rule)}
.project{font-size:13pt;line-height:1.35;font-style:italic;color:var(--ink);margin:0 0 5mm}
.meta-line{display:grid;grid-template-columns:30mm minmax(0,1fr);gap:0 4mm;font:8.6pt/1.5 var(--sans);color:var(--ink);margin:0;padding:1.1mm 0;border-top:.3pt solid var(--hair)}
.meta-line strong{font-weight:600;color:var(--muted);letter-spacing:.04em}
.lead{font-size:10.5pt;line-height:1.65;margin:2mm 6mm 4mm;padding:3mm 0;border-top:.6pt solid var(--rule);border-bottom:.6pt solid var(--rule)}
.small,.section-note{font-size:8.5pt;line-height:1.55;color:var(--muted)}
.section-note{margin-bottom:3mm}
.summary-section>h2{margin-top:0}
.limit-heading{margin-top:5mm}
.limits{margin-top:0;font-size:9.2pt}
table{width:100%;border-collapse:collapse;margin:2mm 0 5mm;table-layout:fixed;font:8.6pt/1.5 var(--serif);border-top:1.2pt solid var(--rule);border-bottom:1.2pt solid var(--rule)}
caption{caption-side:top;text-align:left;font:8.6pt/1.45 var(--serif);color:var(--ink);margin:0 0 1.6mm}
caption::before{counter-increment:table;content:"Table " counter(table) ". ";font-weight:700}
html[lang="ja"] caption::before{content:"表" counter(table) "　"}
thead{display:table-header-group}
tfoot{display:table-footer-group}
th,td{border:0;padding:1.8mm 2.2mm;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-wrap:break-word}
th{background:none;color:var(--ink);font:700 7.6pt/1.4 var(--sans);letter-spacing:.06em;border-bottom:.6pt solid var(--rule)}
tbody tr+tr td{border-top:.3pt solid var(--hair)}
tr{break-inside:avoid;page-break-inside:avoid}
.metrics{margin:3mm 0 3mm}
.metrics td{font:400 18pt/1.2 var(--serif);padding:2mm 2.2mm 1.5mm}
.metrics tbody th,.metrics td{vertical-align:baseline}.metrics tbody th{border-bottom:0}.metrics tbody tr+tr th{border-top:.3pt solid var(--hair)}
.metrics .metric-urgent{color:var(--high)}
.queue .ref-col{width:17%}.queue .finding-col{width:43%}.queue .action-col{width:40%}
.queue td:first-child{font:8.2pt/1.5 var(--mono)}
.queue-title{font-weight:700;margin-bottom:.8mm}
.queue-location,.queue-location code{font-size:7.4pt;color:var(--muted)}
.queue-action{font-size:8.4pt}
.queue-action strong{display:block;margin-bottom:.6mm;font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em}
.queue-legend{font-size:8.6pt;margin:0 0 2mm}.queue-legend strong{font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em;margin-right:1.5mm}
.badge{display:inline-block;font:700 7.2pt/1.5 var(--sans);letter-spacing:.1em;padding:0;margin:.6mm 0;border:0;background:none;color:var(--muted);white-space:nowrap}
.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--muted)}
.coverage .perspective-col{width:28%}.coverage .result-col{width:26%}.coverage .note-col{width:46%}
.index .finding-col{width:43%}.index .severity-col{width:12%}.index .status-col{width:14%}.index .evidence-col{width:31%}
.index-title{display:block;font-weight:700;text-decoration:none;color:var(--ink)}
.index-id{font:7.6pt/1.4 var(--mono);color:var(--muted)}
.evidence-cell{font-size:8pt}
.evidence-cell div+div{margin-top:.8mm}
.evidence-cell span{color:var(--muted)}
#finding-details,.excluded-section{counter-reset:finding}
.finding{counter-increment:finding;margin:7mm 0 0;padding:0 0 0 4mm;border-left:.6pt solid var(--hair);break-inside:auto;page-break-inside:auto}
.finding.sev-High{border-left:2.4pt solid var(--high)}.finding.sev-Medium{border-left:1.2pt solid var(--medium)}.finding.sev-Low{border-left:.6pt solid var(--low)}
.finding.excluded{border-left:.6pt dashed var(--hair)}.finding.excluded .badge{color:var(--muted)}
.finding-header{break-inside:avoid;page-break-inside:avoid;break-after:avoid;page-break-after:avoid}
.finding h3{font-size:11.5pt;line-height:1.4;margin:0 0 2.5mm}
.finding-id{display:block;font:400 8pt/1.4 var(--mono);color:var(--muted);margin-bottom:1mm}
#finding-details .finding-id::before{content:counter(section) "." counter(finding);margin-right:2.5mm;font-family:var(--serif);color:var(--ink)}
.finding-state{margin:0 0 2.5mm;border-top:.6pt solid var(--rule);border-bottom:.6pt solid var(--rule)}
.finding-state th{width:25%;padding:1mm 2mm;border-bottom:.3pt solid var(--hair)}
.finding-state td{font-size:8.5pt;padding:1.1mm 2mm}
.finding-state .badge{margin:0}
.finding-context{font-size:8.8pt;margin-bottom:1.4mm}
.finding-context strong{font:600 7.6pt/1.4 var(--sans);letter-spacing:.05em;color:var(--muted);margin-right:1.5mm}
.finding-field{margin:0 0 3mm;break-inside:auto;page-break-inside:auto;orphans:3;widows:3}
.finding-field h4{margin-bottom:1mm}
.prose{white-space:pre-wrap;overflow-wrap:anywhere;word-wrap:break-word}
.empty-value{color:var(--muted);font-style:italic}
.snippet{counter-increment:listing;margin:1mm 0 3.5mm;padding:2mm 0 2mm 3mm;border:0;border-left:.6pt solid var(--rule);background:none;color:var(--ink);font:7.6pt/1.55 var(--mono);white-space:pre-wrap;overflow:visible;overflow-wrap:anywhere;word-wrap:break-word;word-break:break-all;max-width:100%;break-inside:auto;page-break-inside:auto}
.snippet::before{content:"Listing " counter(listing);display:block;font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin-bottom:1.2mm}
html[lang="ja"] .snippet::before{content:"コード " counter(listing);letter-spacing:.02em}
.snippet span{display:block;white-space:pre-wrap;overflow-wrap:anywhere;word-wrap:break-word;break-inside:avoid;page-break-inside:avoid}
.snippet .hit{background:var(--mark)}.snippet b{color:var(--muted);font-weight:400}
.refs{padding-left:5mm;margin:1mm 0 3mm;font-size:8.4pt;line-height:1.5}
.refs li,.refs a{overflow-wrap:anywhere;word-wrap:break-word;word-break:break-all}
.rt{display:inline-block;min-width:15mm;font:7.2pt/1.4 var(--sans);letter-spacing:.05em;color:var(--muted)}
.record-footer{break-before:avoid;page-break-before:avoid;font:7.4pt/1.4 var(--sans);margin:2mm 0 0;color:var(--muted)}
.record-footer a{color:var(--muted)}
.excluded-section{margin-top:9mm}
.excluded-section>.section-note{break-inside:avoid;page-break-inside:avoid;break-after:avoid;page-break-after:avoid}
.expert-summary,.three-pass-summary,.integrity-summary{margin:5mm 0;padding:0 0 0 4mm;border-left:.6pt solid var(--rule);overflow-wrap:anywhere;break-inside:auto!important;page-break-inside:auto}
.expert-summary h3,.three-pass-summary h3{margin-top:0}
.expert-lines{padding-left:4mm;font-size:9pt}
.three-pass-summary .prose{white-space:pre-wrap;overflow-wrap:anywhere}.three-pass-summary h4{margin:3mm 0 1mm}.three-pass-stage{break-inside:avoid}
.verification-record,.workflow-record{margin:3mm 0;padding:0 0 0 3mm;border:0;border-left:.3pt solid var(--hair);break-inside:auto;page-break-inside:auto}
.verification-record h5,.workflow-record h5{font-size:9pt;margin:3mm 0 1mm;break-after:avoid}
.verification-record p,.workflow-record p,.verification-gaps,.workflow-gaps{font-size:8.3pt;overflow-wrap:anywhere}.verification-gaps{color:var(--muted)}
.verification-level{font-weight:700}
.verification-record section,.workflow-record section{break-inside:auto;page-break-inside:auto}
.validation-method{break-before:avoid;page-break-before:avoid}
@media screen{
  html{background:#efede7}
  body{max-width:210mm;margin:10mm auto;padding:22mm 22mm 24mm;border:1px solid #dcd9d2}
}
@media screen and (max-width:600px){
  body{margin:0;padding:8mm 5mm;border:0}
  .meta-line{grid-template-columns:24mm minmax(0,1fr)}
  .lead{margin:2mm 0 4mm}
  .index,.index tbody,.index tr,.index td{display:block;width:100%}
  .index colgroup,.index thead{display:none}
  .index tr{margin:0 0 3mm;border-top:.6pt solid var(--rule)}
  .index td{border:0!important;padding:1.5mm 0}
  .index td::before{content:attr(data-label);display:block;font:600 7.6pt/1.4 var(--sans);letter-spacing:.05em;color:var(--muted);margin-bottom:.6mm}
}
@media print{
  *{-webkit-print-color-adjust:exact;print-color-adjust:exact}
  body{width:auto;max-width:none}
}
"""


LOC_RE = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")
SECRET_RE = re.compile(
    r"(?i)((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|credential)"
    r"[\w.-]*['\"]?\s*(?:=>|:=|[:=])\s*['\"]?)"
    r"(?!\$|[A-Za-z_][\w.]*\(|process\.env|os\.environ|null\b|None\b|true\b|false\b)([^'\"\s,;)]{4,})")


SENSITIVE_NAMES = {".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc", ".netrc", ".git-credentials",
                   "auth.json", "credentials", "credentials.json", "secrets.json", "secrets.yaml", "secrets.yml",
                   "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
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
            or any(part.lower() in {".ssh", ".aws", ".kube", "secrets"} for part in path.parts))


def redact(line):
    line = redact_urls(line)
    line = QUOTED_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "********" + m.group(2), line)
    return SECRET_RE.sub(lambda m: m.group(1) + "********", line)


def attach_sources(data, repo, context=3):
    """Attach safe links and best-effort redacted excerpts; omit sensitive sources."""
    base = data["meta"].get("source_url") or ""
    if base:
        base = http_url(base, "meta.source_url").rstrip("/")
    root = Path(repo).resolve() if repo else None
    for f in data["findings"]:
        f.pop("source_link", None)
        f.pop("snippet", None)
        m = LOC_RE.match(f["location"].strip())
        if not m:
            continue
        rel, start = m.group("path").replace("\\", "/"), int(m.group("start"))
        end = int(m.group("end") or start)
        if PurePosixPath(rel).is_absolute() or ".." in PurePosixPath(rel).parts or start < 1 or end < start:
            continue
        if base:
            link = f"{base}/{quote(rel, safe='/')}#L{start}" + (f"-L{end}" if end != start else "")
            f["source_link"] = http_url(link, "source_link")
        if not root or sensitive_path(rel) or str(f.get("category", "")).lower() == "secrets":
            continue
        path = (root / rel).resolve()
        if root not in path.parents or not path.is_file() or sensitive_path(path.relative_to(root)):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Do not show even a middle line of a multiline private key.
        if PRIVATE_KEY_RE.search(text):
            continue
        # Number lines as Git and editors do: str.splitlines() also breaks on
        # form feeds, U+2028 and other separators and would shift every line.
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        lines = [line[:-1] if line.endswith("\r") else line for line in lines]
        if start > len(lines):
            continue  # The location is past the end of this file: no excerpt.
        lo, hi = max(1, start - max(0, context)), min(len(lines), end + max(0, context))
        requested_hi = hi
        hi = min(hi, lo + 199)
        redacted = [redact(lines[i - 1]) for i in range(lo, hi + 1)]
        f["snippet"] = {"start": lo, "hit": [start, end],
                        "lines": [line[:240] for line in redacted],
                        "truncated": requested_hi > hi or any(len(line) > 240 for line in redacted)}


def snippet_html(f, L=None):
    sn = f.get("snippet")
    if not sn:
        return ""
    rows = []
    for n, text in enumerate(sn["lines"], sn["start"]):
        hit = " class='hit'" if sn["hit"][0] <= n <= sn["hit"][1] else ""
        rows.append(f"<span{hit}><b>{n:>5}</b> {esc(text)}</span>")
    note = (f"<p class='small snippet-note'>{esc((L or LABELS['en'])['snippet_truncated'])}</p>"
            if sn.get("truncated") else "")
    return "<pre class='snippet'>" + "".join(rows) + "</pre>" + note


def refs_html(f):
    items = []
    if f.get("source_link"):
        items.append(("source", http_url(f["source_link"], "source_link"), ""))
    items += [(r["type"], http_url(r["url"], "references.url"), r["title"]) for r in f.get("references", [])]
    if not items:
        return ""
    lis = "".join(f"<li><span class='rt'>{esc(t)}</span> <a href='{esc(u)}'>{esc(title or u)}</a></li>"
                  for t, u, title in items)
    return f"<ul class='refs'>{lis}</ul>"


def verification_view(data, finding, state, lang):
    """A curated, redacted view shared by HTML, dashboard and PDF."""
    L = LABELS[lang]

    def text(value):
        value = str(value if value is not None else "")
        return L["v_withheld"] if PRIVATE_KEY_RE.search(value) else redact(value)

    def label(value):
        return L.get("v_" + str(value), str(value))

    def refs(record):
        ids = record.get("evidence_ids", [])
        return L["v_refs"] + ": " + ", ".join(text(i) for i in ids) if ids else ""

    def join(*parts):
        return "\n".join(str(part) for part in parts if part != "" and part is not None)

    sections = []

    def section(key, items):
        if items:
            sections.append({"title": L[key], "items": items})

    provenance = state.get("integrity", {})
    integrity_status = provenance.get("status", "declared")
    # Only local result codes and counters are projected. A saved receipt is
    # never consulted here, and artifact bytes/absolute roots are never copied.
    if state["level"] != "legacy":
        section("i_title", [
            L.get("i_" + integrity_status, L["i_incomplete"]),
            L["i_counts"].format(bytes_checked=provenance.get("bytes_checked", 0),
                                 sources_checked=provenance.get("sources_checked", 0),
                                 evidence_total=provenance.get("evidence_total", len(state.get("evidence_ids", [])))),
            L["i_note"],
        ])
    if state["level"] != "legacy" and integrity_status == "incomplete":
        section("v_reason", list(dict.fromkeys(L.get("i_reason_" + code, L["i_reason_unknown"])
                                              for code in provenance.get("reasons", []))))
    integrity_records = {item["evidence_id"]: item for item in provenance.get("records", [])}
    raw_verification = finding.get("verification")
    verification = raw_verification if isinstance(raw_verification, dict) and state["level"] != "legacy" else {}
    if isinstance(raw_verification, str) and raw_verification:
        section("v_legacy_note", [text(raw_verification)])
    if verification:
        assessment = data["assessment"]
        section("v_scope", [join(*(L["v_" + key] + ": " + text(assessment.get(key))
                                  for key in ("repository", "commit", "worktree")),
                                 "diff_sha256: " + text(assessment["diff_sha256"])
                                 if assessment.get("diff_sha256") else "")])
        section("v_claims", [L["v_author"] + ": " + text(verification.get("reviewer"))] +
                            [join(label(key) + ": " + label(record["status"]),
                                  text(record.get("reason")), refs(record))
                              for key in CLAIMS for record in (verification["claims"][key],)])
        section("v_falsification", [join(text(record.get("check")), label(record.get("result")),
                                         L["p_claim"] + ": " + label(record["claim"])
                                         if "three_pass" in data and record.get("claim") in CLAIMS else "",
                                         text(record.get("reason")), refs(record))
                                    for record in verification.get("falsification", [])])
        section("v_reviews", [join(text(record.get("reviewer")), label(record.get("conclusion")),
                                    text(record.get("reason")), refs(record),
                                    join(L["v_resolution"] + ": " + text(record["resolution"].get("reviewer")),
                                         text(record["resolution"].get("reason")), refs(record["resolution"]))
                                    if record.get("resolution") else "")
                               for record in verification.get("reviews", [])])
        environment = verification.get("environment") or {}
        if environment:
            section("v_environment", [join(L["v_environment_verified"] if environment.get("status") == "verified"
                                            else label(environment.get("status")),
                                            text(environment.get("reason")), refs(environment))])
        if verification.get("exclusion"):
            exclusion = verification["exclusion"]
            section("v_exclusion", [join(text(exclusion["basis"]), text(exclusion["reason"]), refs(exclusion))])
        if finding.get("remediation"):
            remediation = finding["remediation"]
            section("v_remediation", [join(L["v_commit"] + ": " + text(remediation["commit"]),
                                           "diff_sha256: " + text(remediation["diff_sha256"])
                                           if remediation.get("diff_sha256") else "",
                                           *(key + ": " + text(remediation[key]) for key in ("before_run_id", "after_run_id")
                                             if key in remediation))])
    run_index = {record["id"]: record for record in data.get("test_runs", [])} if verification else {}
    run_items = []
    for run_id in state.get("run_ids", []):
        run = run_index[run_id]
        # Separate context fields keep version identifiers off a long wrapped
        # sentence, where PDF text extractors can remove a line-ending hyphen.
        context = "\n".join(key + "=" + text(run.get("context", {}).get(key, ""))
                            for key in ("environment", "configuration", "fixture", "test_version", "boundary"))
        run_items.append(join(text(run_id) + " · " + label(run["role"]) + " · " + label(run["result"]),
                              L["v_case"] + ": " + text(run["case_id"]),
                              L["v_commit"] + ": " + text(run["commit"]),
                              "diff_sha256: " + text(run["diff_sha256"]) if run.get("diff_sha256") else "",
                              L["v_context"] + ":\n" + context,
                              L["v_expected"] + ": " + text(run.get("expected")),
                              L["v_observed"] + ": " + text(run.get("observed")),
                              L["v_failure"] + ": " + text(run.get("failure_kind")),
                              L["v_exit"] + ": " + text(run.get("exit_code")),
                              L["v_time"] + ": " + text(run.get("recorded_at")),
                              L["v_command"] + ": " + text(run.get("command")), refs(run)))
    section("v_runs", run_items)
    evidence_index = {record["id"]: record for record in data.get("evidence", [])} if verification else {}
    evidence_items = []
    for evidence_id in state.get("evidence_ids", []):
        record = evidence_index[evidence_id]
        checked = integrity_records.get(evidence_id, {})
        normalized_location = record["location"].replace("\\", "/")
        match = LOC_RE.match(normalized_location)
        path = match.group("path") if match else normalized_location
        withheld = (sensitive_path(path) or sensitive_path(record.get("source_path", ""))
                    or finding.get("category", "").lower() == "secrets")
        evidence_items.append(join(text(evidence_id) + " · " + text(record["kind"]),
                                   L["v_location"] + ": " + text(record["location"]),
                                   L["v_commit"] + ": " + text(record["commit"]),
                                   L["i_source_path"] + ": " + text(record["source_path"]) if record.get("source_path") else "",
                                   "diff_sha256: " + text(record["diff_sha256"]) if record.get("diff_sha256") else "",
                                   L["v_hash"] + ": " + text(record["sha256"]),
                                   L["i_bytes"] + ": " + L.get("i_bytes_" + checked.get("bytes", "declared"), L["i_bytes_unavailable"]),
                                   L["i_source"] + ": " + L.get("i_source_" + checked.get("source", "declared"), L["i_source_unavailable"]),
                                   L["v_reason"] + ": " + L.get("i_reason_" + checked["reason"], L["i_reason_unknown"])
                                   if checked.get("reason") not in (None, "not_checked", "bytes_matched_revision_declared", "source_bytes_and_commit_matched") else "",
                                   L["v_withheld"] if withheld else text(record.get("summary"))))
    section("v_evidence", evidence_items)
    return {
        "level": label(state["level"]),
        "retest": L["v_retest_incomplete"] if state["retest"] == "incomplete" else label(state["retest"]),
        "gaps": [L.get("v_gap_" + code, code.replace("_", " ")) for code in state.get("gaps", [])],
        "sections": sections,
    }



def workflow_view(data, finding, state, lang):
    """Display only named, redacted lineage fields; never embed raw stage patches."""
    L = LABELS[lang]

    def text(value):
        value = str(value if value is not None else "")
        return L["v_withheld"] if PRIVATE_KEY_RE.search(value) else redact(value)

    def label(value):
        return L.get("w_" + str(value), text(value))

    def reason(value):
        return L.get("w_gap_" + str(value), L.get("v_gap_" + str(value), text(value)))

    def record_text(record):
        # Event bodies can contain untrusted extensions or full historical proofs.
        # Keep the known metadata, and redact even identifiers and digest labels.
        lines = []
        if isinstance(record.get("submission"), dict):
            submission = record["submission"]
            record = {**{key: submission[key] for key in ("stage", "summary", "evidence_ids", "run_ids") if key in submission}, **record}
        for key in ("action", "event", "stage", "status", "actor", "summary", "reason", "recorded_at",
                    "input_digest", "output_digest", "previous_event_digest", "event_digest"):
            if key in record and isinstance(record[key], str):
                name = "w_result" if key == "status" else "w_event" if key == "action" else "w_" + key
                value = label(record[key]) if key in ("action", "event", "stage", "status") else text(record[key])
                if key == "status" and record[key] == "complete":
                    value = L["w_stage_complete"]
                lines.append(L.get(name, key) + ": " + value)
        for key in ("evidence_ids", "run_ids"):
            if isinstance(record.get(key), list) and record[key]:
                lines.append(L["w_" + key] + ": " + ", ".join(text(item) for item in record[key]
                                                                           if isinstance(item, str)))
        scope = record.get("scope")
        if isinstance(scope, dict):
            for key in ("evidence_ids", "run_ids"):
                if isinstance(scope.get(key), list):
                    lines.append(L["w_scope"] + " · " + L["w_" + key] + ": " + ", ".join(
                        text(item) for item in scope[key] if isinstance(item, str)))
        if isinstance(record.get("restart"), bool):
            lines.append(L["w_restart"] if record["restart"] else L["w_continue"])
        if isinstance(record.get("reasons"), list):
            lines.extend(reason(item) for item in record["reasons"] if isinstance(item, str))
        return "\n".join(lines)

    submitted = state.get("stages", [])
    sections = []
    for stage in ("conditions", "falsification", "decision"):
        records = [record for record in submitted if isinstance(record, dict) and record.get("stage") == stage]
        sections.append({"title": L["w_" + stage],
                         "items": [record_text(record) for record in records] or [L["w_pending"]]})
    if state.get("input_digest"):
        sections.append({"title": L["w_lineage"], "items": [L["w_current_digest"] + ": " + text(state["input_digest"]),
                                                                          L["w_recorded_digest"] + ": " + text(finding.get("verification_workflow", {}).get("input_digest", L["not_recorded"]))]})
    history = [record_text(record) for record in state.get("history", []) if isinstance(record, dict)]
    sections.append({"title": L["w_history"], "items": [entry for entry in history if entry] or [L["w_no_history"]]})
    gaps = [reason(item) for item in state.get("reasons", []) if isinstance(item, str)] if state["status"] != "complete" else []
    if not gaps and state.get("reason") and state["status"] != "complete":
        gaps = [reason(state["reason"])]
    return {"status": label(state["status"]), "next_stage": label(state["next_stage"]) if state.get("next_stage") else L["w_none"],
            "gaps": gaps, "sections": sections}


def three_pass_view(data, lang, integrity=None):
    """Curated profile projection; arbitrary extensions and raw records stay private."""
    state = derive_three_pass(data, SchemaError, integrity=integrity)
    if not state["opted_in"]:
        return None
    L = LABELS[lang]

    def text(value):
        value = str(value if value is not None else "")
        return L["v_withheld"] if PRIVATE_KEY_RE.search(value) else redact(value)

    def gap(code):
        # Reason codes are derived, but keep a safe localized fallback, never raw data.
        return L.get("p_gap_" + str(code), L.get("w_gap_" + str(code),
                     L.get("v_gap_" + str(code), L["p_gap_unknown"])))

    def gaps(codes):
        return list(dict.fromkeys(gap(code) for code in codes))

    discovery = state.get("discovery", {})
    challenge = state.get("coverage_challenge", {})
    overall_gaps = gaps(state.get("reasons", []))
    sections = []

    def discovery_items(profile):
        # Historical snapshots are untrusted journal bodies, not current schema.
        record = profile.get("discovery", {})
        record = record if isinstance(record, dict) else {}
        overview = [L[label] + ": " + text(record[key]) for key, label in
                    (("actor", "w_actor"), ("summary", "p_summary")) if isinstance(record.get(key), str)]
        rows = record.get("checks", [])
        rows = rows if isinstance(rows, list) else []
        checks = {item["coverage_id"]: item for item in rows
                  if isinstance(item, dict) and isinstance(item.get("coverage_id"), str)}
        cells = profile.get("coverage", [])
        for cell in cells if isinstance(cells, list) else []:
            if not isinstance(cell, dict) or not all(isinstance(cell.get(key), str) for key in ("id", "perspective", "target")):
                continue
            check = checks.get(cell["id"], {})
            status = check.get("status")
            status = status if status in ("checked", "not_applicable", "not_checked") else "not_checked"
            lines = [L["p_coverage_id"] + ": " + text(cell["id"]),
                     L["perspective"] + ": " + text(cell["perspective"]),
                     L["p_target"] + ": " + text(cell["target"]),
                     L["status"] + ": " + L["p_" + status]]
            if isinstance(check.get("reason"), str):
                lines.append(L["w_reason"] + ": " + text(check["reason"]))
            for key, label in (("evidence_ids", "w_evidence_ids"), ("finding_ids", "p_finding_ids")):
                if isinstance(check.get(key), list):
                    refs = [text(value) for value in check[key] if isinstance(value, str)]
                    if refs:
                        lines.append(L[label] + ": " + ", ".join(refs))
            overview.append("\n".join(lines))
        return overview

    overview = discovery_items(data["three_pass"])
    sections.append({"title": L["p_discovery_record"], "items": overview})
    seen_discoveries = {tuple(overview)}
    for workflow in state.get("findings", {}).values():
        for event in workflow.get("history", []):
            snapshot = event.get("three_pass_snapshot")
            if not isinstance(snapshot, dict):
                continue
            items = discovery_items(snapshot)
            if items and tuple(items) not in seen_discoveries:
                seen_discoveries.add(tuple(items))
                sections.append({"title": L["p_history"], "items": items})
    pass_views = []
    findings = state.get("findings", {})
    for item in state["passes"]:
        pass_gaps = []
        if item["id"] == "discovery":
            pass_gaps = gaps(discovery.get("reasons", []))
            for key, label in (("missing_coverage_ids", "p_missing_coverage"), ("untracked_finding_ids", "p_untracked_findings")):
                if discovery.get(key):
                    pass_gaps.append(L[label] + ": " + ", ".join(text(value) for value in discovery[key]))
        else:
            for finding_id, workflow in findings.items():
                conditions_done = workflow.get("status") != "stale" and any(
                    stage.get("stage") == "conditions" and stage.get("status") == "complete"
                    for stage in workflow.get("stages", []))
                pending = (not conditions_done if item["id"] == "conditions" else workflow.get("status") != "complete")
                if pending:
                    # Name each incomplete finding without serializing workflow internals.
                    pass_gaps.append(text(finding_id) + ": " + L.get("w_" + str(workflow.get("status")), L["p_not_started"]))
            if item["id"] == "challenge":
                pass_gaps.extend(gaps(challenge.get("reasons", [])))
                if challenge.get("missing_coverage_ids"):
                    pass_gaps.append(L["p_missing_challenge"] + ": " + ", ".join(text(value) for value in challenge["missing_coverage_ids"]))
        # A completed pass must not show later-stage gaps.
        if item["status"] == "complete":
            pass_gaps = []
        pass_views.append({"id": item["id"], "title": L["p_" + item["id"]],
                           "status": L["p_pass_complete"] if item["status"] == "complete" else L.get("p_" + item["status"], L["p_held"]),
                           "count": L["p_count_cells" if item["id"] == "discovery" else "p_count_findings"].format(**item),
                           "gaps": list(dict.fromkeys(pass_gaps))})
    if challenge:
        sections.append({"title": L["p_challenge"], "items": [L["p_challenge_count"].format(**challenge)]})
    for finding in data["findings"]:
        proof = finding.get("verification")
        scope_checks = proof.get("coverage_checks", []) if isinstance(proof, dict) else []
        items = []
        for check in scope_checks:
            items.append("\n".join([
                L["p_coverage_id"] + ": " + text(check["coverage_id"]),
                L["w_result"] + ": " + L.get("v_" + check["result"], text(check["result"])),
                L["w_reason"] + ": " + text(check["reason"]),
                L["w_evidence_ids"] + ": " + ", ".join(text(value) for value in check["evidence_ids"]),
            ]))
        if items:
            workflow_status = findings.get(finding["id"], {}).get("status", "not_started")
            sections.append({"title": L["p_scope_checks"] + " · " + text(finding["id"]) + " · " +
                                      L.get("w_" + workflow_status, L["p_not_started"]), "items": items})
    return {"status": L["p_" + state["status"]], "note": L["p_note"], "safety": L["p_safety"],
            "gaps": overall_gaps, "passes": pass_views, "sections": sections}


def three_pass_html(view, L):
    """One escaped HTML summary shared by the interactive and printable reports."""
    if view is None:
        return ""

    def gaps(items):
        return ("<ul class='three-pass-gaps'>" + "".join(f"<li>{esc(item)}</li>" for item in items) + "</ul>") if items else ""

    passes = "".join(f"<section class='three-pass-stage' data-three-pass='{esc(item['id'])}'>"
                     f"<h4>{esc(item['title'])}</h4><p>{esc(item['status'])} · {esc(item['count'])}</p>"
                     + gaps(item["gaps"]) + "</section>" for item in view["passes"])
    details = "".join(f"<section><h4>{esc(section['title'])}</h4>" +
                      "".join(f"<p class='prose'>{esc(item)}</p>" for item in section["items"]) + "</section>"
                      for section in view["sections"])
    return (f"<section class='three-pass-summary panel' id='three-pass-summary'>"
            f"<h3>{esc(L['p_title'])}</h3><p class='three-pass-status'><strong>{esc(L['p_status'])}:</strong> {esc(view['status'])}</p>"
            f"<p>{esc(view['note'])}</p>{passes}"
            + (f"<h4>{esc(L['p_gaps'])}</h4>" + gaps(view["gaps"]) if view["gaps"] else "")
            + details + f"<p class='small'>{esc(view['safety'])}</p></section>")


def expert_view(data, lang, integrity=None):
    """Declared expert record gates; the final run-file audit is a separate check."""
    state = derive_expert(data, SchemaError, integrity=integrity)
    if not state["opted_in"]:
        return None
    L = LABELS[lang]
    counts = state["counts"]
    lines = [L["e_mode"] + ": " + (L["e_full"] if state["mode"] == "full" else L["e_single"]),
             L["e_engines"] + ": " + (L["e_cross"] if state["cross_engine"] else L["e_mono"]) +
             (" (" + ", ".join(redact(e) for e in state["engines"]) + ")" if state["engines"] else "")]
    lines += [L[key].format(**counts) for key in ("e_workers", "e_recon", "e_discovery", "e_variants",
                                                  "e_omission", "e_panels", "e_severity", "e_reception", "e_qa")]
    gaps = [L["e_gap"] + ": " + redact(code) for code in state["gaps"]]
    return {"status": L["e_" + state["status"]], "lines": lines, "gaps": gaps,
            "note": L["e_note"], "safety": L["e_safety"]}


def expert_html(view, L):
    """One escaped HTML summary shared by the interactive and printable reports."""
    if view is None:
        return ""
    lines = "".join(f"<li>{esc(line)}</li>" for line in view["lines"])
    gaps = (f"<h4>{esc(L['e_gaps'])}</h4><ul class='expert-gaps'>" +
            "".join(f"<li>{esc(g)}</li>" for g in view["gaps"]) + "</ul>") if view["gaps"] else ""
    return (f"<section class='expert-summary panel' id='expert-summary'><h3>{esc(L['e_title'])}</h3>"
            f"<p class='expert-status'><strong>{esc(L['e_status'])}:</strong> {esc(view['status'])}</p>"
            f"<p>{esc(view['note'])}</p><ul class='expert-lines'>{lines}</ul>{gaps}"
            f"<p class='small'>{esc(view['safety'])}</p></section>")


def workflow_html(view, L):
    if view is None:
        return ""
    gaps = ("<h5>" + esc(L["w_gaps"]) + "</h5><ul class='workflow-gaps'>" +
            "".join(f"<li>{esc(gap)}</li>" for gap in view["gaps"]) + "</ul>" if view["gaps"] else "")
    sections = "".join(f"<section><h5>{esc(section['title'])}</h5>" +
                       "".join(f"<p class='prose'>{esc(item)}</p>" for item in section["items"]) + "</section>"
                       for section in view["sections"])
    return (f"<div class='workflow-record'><h4>{esc(L['w_title'])}</h4>"
            f"<p class='workflow-status'><strong>{esc(L['w_status'])}:</strong> {esc(view['status'])}</p>"
            f"<p class='workflow-next'><strong>{esc(L['w_next'])}:</strong> {esc(view['next_stage'])}</p>"
            f"<p class='small'>{esc(L['w_note'])}</p>{gaps}{sections}<p class='small'>{esc(L['w_safety'])}</p></div>")


def verification_html(view, L):
    gaps = ("<ul class='verification-gaps'>" + "".join(f"<li>{esc(gap)}</li>" for gap in view["gaps"]) + "</ul>"
            if view["gaps"] else "")
    sections = "".join(f"<section><h5>{esc(section['title'])}</h5>" +
                       "".join(f"<p class='prose'>{esc(item)}</p>" for item in section["items"]) + "</section>"
                       for section in view["sections"])
    return (f"<div class='verification-record'><h4>{esc(L['v_title'])}</h4>"
            f"<p class='verification-level'>{esc(view['level'])}</p>"
            f"<p><strong>{esc(L['v_retest'])}:</strong> {esc(view['retest'])}</p>{gaps}{sections}</div>")


def verification_summary_parts(model, L):
    counts = model["verification_counts"]
    return [{"key": part, "count": counts[part]} if part in counts else {"text": part}
            for part in re.split(r"\{(static|runtime|pending|retested)\}", L["v_summary"])]


def integrity_summary_view(states, findings, L):
    counts = Counter(states[f["id"]].get("integrity", {}).get("status", "declared") for f in findings)
    return {"text": L["i_summary"].format(**{key: counts[key] for key in ("checked", "incomplete", "declared")}),
            "note": L["i_note"],
            "counts": {key: counts[key] for key in ("checked", "incomplete", "declared")}}


def verification_summary_html(model, L, integrity_summary=None):
    parts = verification_summary_parts(model, L)
    sentence = "".join(f"<strong data-verification-count='{part['key']}'>{part['count']}</strong>"
                       if "count" in part else esc(part["text"]) for part in parts)
    provenance = (f"<div class='integrity-summary'><h3>{esc(L['i_title'])}</h3>"
                  f"<p>{esc(integrity_summary['text'])}</p>"
                  f"<p class='small'>{esc(integrity_summary['note'])}</p></div>" if integrity_summary else "")
    return (f"<div id='verification-summary'><p>{sentence}</p>"
            f"<p class='small'>{esc(L['v_note'])}</p>{provenance}</div>")


def render_assessment_html(data, L, lang, integrity=None):
    L = {**ASSESSMENT_LABELS.get(lang, ASSESSMENT_LABELS["en"]), **L}
    m, st, fs = data["meta"], stats(data), active(data)
    model = report_model(data, integrity=integrity)
    verification_states = derive_verification(data, SchemaError, integrity=integrity)
    verification_views = {f["id"]: verification_view(data, f, verification_states[f["id"]], lang)
                          for f in data["findings"]}
    workflows = workflow_states(data, integrity=integrity)
    workflow_views = {f["id"]: workflow_view(data, f, workflows[f["id"]], lang)
                      for f in data["findings"] if f["id"] in workflows}
    excluded = [f for f in data["findings"] if f["verdict"] in EXCLUDED]
    summary = L["a_summary"].format(**model)
    accounting = L["a_accounting"].format(total=len(fs), **model)

    def value(text):
        return esc(text) if str(text or "").strip() else f"<span class='empty-value'>{esc(L['a_not_recorded'])}</span>"

    def prose(text, fallback="a_not_recorded"):
        if str(text or "").strip():
            return f"<p class='prose'>{esc(text)}</p>"
        return f"<p class='empty-value'>{esc(L[fallback])}</p>"

    def bullets(items, empty_label):
        return ("<ul>" + "".join(f"<li class='prose'>{esc(x)}</li>" for x in items) + "</ul>"
                if items else f"<p class='small'>{esc(L[empty_label])}</p>")

    def field(label, markup):
        return f"<div class='finding-field'><h4>{esc(L[label])}</h4>{markup}</div>"

    def badge(f):
        return f"<span class='badge {esc(f['severity'])}'>{esc(f['severity'])}</span>"

    meta_top = "".join(
        f"<p class='meta-line'><strong>{esc(L[label])}</strong> {esc(m[key])}</p>"
        for label, key in (("date", "date"), ("assessor", "assessor"), ("commit", "commit")) if m.get(key))
    scope_lines = "".join(
        f"<p class='meta-line'><strong>{esc(L[label])}</strong> {value(m.get(key))}</p>"
        for label, key in (("scope_l", "scope"), ("method", "method")))

    metrics = (("a_open", model["open_count"], ""),
               ("a_fix_now", model["fix_now"], "metric-urgent"),
               ("a_verify_first", model["verify_first"], ""),
               ("open_hm", st["open_hm"], "metric-urgent"))
    metrics_html = (f"<table class='metrics'><caption>{esc(L['a_cap_metrics'])}</caption><thead><tr>" +
                    "".join(f"<th scope='col'>{esc(L[label])}</th>" for label, _, _ in metrics) +
                    "</tr></thead><tbody><tr>" +
                    "".join(f"<td class='{cls if number else ''}' data-report-count='{key}'>{number}</td>"
                            for key, (_, number, cls) in zip(("open_count", "fix_now", "verify_first", "open_hm"), metrics)) +
                    "</tr></tbody></table>")
    part_columns = (("a_open", "open_count"), ("a_fix_now", "fix_now"), ("a_verify_first", "verify_first"),
                    ("open_hm", "open_hm"), ("a_part_total", "total"))
    parts_html = (f"<table class='metrics parts'><caption>{esc(L['a_cap_parts'])}</caption><thead><tr>"
                  f"<th scope='col'>{esc(L['part'])}</th>" +
                  "".join(f"<th scope='col'>{esc(L[label])}</th>" for label, _ in part_columns) + "</tr></thead><tbody>" +
                  "".join(f"<tr data-part='{part}'><th scope='row'>{esc(L['part_short_' + part])}</th>" +
                          "".join(f"<td data-part-count='{key}'>{model['parts'][part][key]}</td>" for _, key in part_columns) +
                          "</tr>" for part in PARTS) +
                  f"</tbody></table><p class='small'>{esc(L['part_note'])}</p>")

    def queue_table(items):
        queue_rows = []
        for item in items:
            f, action = item["finding"], item["action"]
            if action == "fix_now":
                action_text = f.get("fix") or L["a_fix_missing"]
            else:
                action_text = ""
            # Queue is a navigation aid; the complete unabridged fix remains below.
            action_preview = action_text if len(action_text) <= 220 else action_text[:217].rstrip() + "..."
            queue_rows.append(
                f"<tr><td><a href='#{esc(item['anchor'])}'>{esc(f['id'])}</a><br>{badge(f)}</td>"
                f"<td><div class='queue-title'>{esc(f['title'])}</div>"
                f"<div class='queue-location'><code>{esc(f['location'])}</code></div></td>"
                f"<td class='queue-action'><strong>{esc(L['a_' + action])}</strong>{esc(action_preview)}</td></tr>")
        return (f"<table class='queue'><caption>{esc(L['a_cap_queue'])}</caption><colgroup><col class='ref-col'><col class='finding-col'><col class='action-col'></colgroup>"
                f"<thead><tr><th scope='col'>ID / {esc(L['severity'])}</th><th scope='col'>{esc(L['a_finding'])}</th>"
                f"<th scope='col'>{esc(L['a_next_action'])}</th></tr></thead><tbody>{''.join(queue_rows)}</tbody></table>")

    verify_legend = (f"<p class='queue-legend'><strong>{esc(L['a_verify_first'])}</strong> {esc(L['a_verify_action'])}</p>"
                     if any(item["action"] != "fix_now" for item in model["queue"]) else "")
    part_queues = {part: [item for item in model["queue"] if item["finding"]["part"] == part] for part in PARTS}
    queue_html = ("".join(
        f"<h3 id='priority-queue-{part}'>{esc(L['part_' + part])}</h3>" +
        (queue_table(part_queues[part]) if part_queues[part] else f"<p class='small'>{esc(L['part_none_open'])}</p>")
        for part in PARTS)
        if model["queue"] else f"<p>{esc(L['a_queue_empty'])}</p>")

    lens = data.get("perspectives", [])
    lens_rows = "".join(
        f"<tr><td>{esc(p.get('name'))}</td><td>{value(p.get('result'))}</td><td>{value(p.get('note'))}</td></tr>"
        for p in lens)
    coverage_html = (f"<table class='coverage'><caption>{esc(L['a_cap_coverage'])}</caption><colgroup><col class='perspective-col'><col class='result-col'><col class='note-col'></colgroup>"
                     f"<thead><tr><th scope='col'>{esc(L['perspective'])}</th><th scope='col'>{esc(L['result'])}</th>"
                     f"<th scope='col'>{esc(L['note'])}</th></tr></thead><tbody>{lens_rows}</tbody></table>"
                     if lens else f"<p class='small'>{esc(L['a_coverage_empty'])}</p>")

    def index_table(part_fs):
        index_rows = "".join(
            f"<tr><td data-label='{esc(L['a_finding'])}'><a class='index-title' href='#{esc(finding_anchor(data, f))}'>{esc(f['title'])}</a>"
            f"<span class='index-id'>{esc(f['id'])}</span></td><td data-label='{esc(L['severity'])}'>{badge(f)}</td>"
            f"<td data-label='{esc(L['status'])}'>{esc(f['status'])}</td>"
            f"<td class='evidence-cell' data-label='{esc(L['a_evidence_state'])}'><div><span>{esc(L['confidence'])}:</span> {esc(f['confidence'])}</div>"
            f"<div><span>{esc(L['verdict'])}:</span> {esc(f['verdict'])}</div>"
            f"<div>{esc(verification_views[f['id']]['level'])}</div>"
            + (f"<div class='workflow-status'>{esc(workflow_views[f['id']]['status'])}</div>"
               if f["id"] in workflow_views else "") + "</td></tr>" for f in part_fs)
        return (f"<table class='index'><caption>{esc(L['a_cap_index'])}</caption><colgroup><col class='finding-col'><col class='severity-col'><col class='status-col'><col class='evidence-col'></colgroup>"
                f"<thead><tr><th scope='col'>{esc(L['a_finding'])}</th><th scope='col'>{esc(L['severity'])}</th>"
                f"<th scope='col'>{esc(L['status'])}</th><th scope='col'>{esc(L['a_evidence_state'])}</th></tr></thead>"
                f"<tbody>{index_rows}</tbody></table>")

    part_findings = {part: [f for f in fs if finding_part(f) == part] for part in PARTS}
    index_html = ("".join(
        f"<h3 id='finding-register-{part}'>{esc(L['part_' + part])}</h3>" +
        (index_table(part_findings[part]) if part_findings[part] else f"<p class='small'>{esc(L['part_none'])}</p>")
        for part in PARTS)
        if fs else f"<p>{esc(L['a_register_empty'])}</p>")

    def card(f, is_excluded=False):
        state_keys = ("severity", "status", "confidence", "verdict")
        state_header = "".join(f"<th scope='col'>{esc(L[k])}</th>" for k in state_keys)
        state_values = "".join(f"<td>{badge(f) if k == 'severity' else esc(f[k])}</td>" for k in state_keys)
        state = f"<table class='finding-state'><thead><tr>{state_header}</tr></thead><tbody><tr>{state_values}</tr></tbody></table>"
        action = ""
        if f["status"] == "Open" and not is_excluded:
            action = f"<p class='finding-context'><strong>{esc(L['a_next_action'])}:</strong> {esc(L['a_' + action_kind(f, model['verification'][f['id']], model.get('workflows', {}).get(f['id']))])}</p>"
        context = (f"<p class='finding-context'><strong>{esc(L['location'])}:</strong> <code>{esc(f['location'])}</code></p>"
                   f"<p class='finding-context'><strong>{esc(L['category'])}:</strong> {value(f.get('category'))}</p>")
        if f.get("cwe"):
            number = f["cwe"].split("-", 1)[1]
            context += (f"<p class='finding-context'><strong>{esc(L['cwe'])}:</strong> "
                        f"<a href='https://cwe.mitre.org/data/definitions/{esc(number)}.html'>{esc(f['cwe'])}</a></p>")
        # Keep source statements in full. Long prose and source blocks may split
        # across pages; only headings and individual snippet lines stay together.
        content = field("impact", prose(f.get("impact")))
        content += field("fix", prose(f.get("fix"), "a_fix_missing" if f["status"] == "Open" and not is_excluded else "a_not_recorded"))
        validation = f.get("validation", {})
        evidence = prose(validation.get("evidence"), "a_evidence_missing")
        if validation.get("method"):
            evidence += f"<p class='small validation-method'><strong>{esc(L['a_method'])}:</strong> {esc(validation['method'])}</p>"
        content += field("evidence", evidence)
        content += workflow_html(workflow_views.get(f["id"]), L)
        content += verification_html(verification_views[f["id"]], L)
        for key in ("actor", "request"):
            if f.get(key):
                content += field(key, prose(f[key]))
        if f.get("snippet"):
            content += field("snippet", snippet_html(f, L))
        if f.get("references") or f.get("source_link"):
            content += field("references", refs_html(f))
        previous = f.get("previous_validation")
        if isinstance(previous, dict):
            historical = prose(L["history_note"])
            for key, label in (("verdict", "verdict"), ("evidence", "evidence"), ("method", "a_method")):
                if isinstance(previous.get(key), str) and previous[key]:
                    historical += f"<p class='finding-context prose'><strong>{esc(L[label])}:</strong> {esc(previous[key])}</p>"
            content += field("previous_validation", historical)
        excluded_class = " excluded" if is_excluded else ""
        return (f"<article class='finding sev-{esc(f['severity'])}{excluded_class}' id='{esc(finding_anchor(data, f))}'>"
                f"<div class='finding-header'><h3><span class='finding-id'>{esc(f['id'])}</span>{esc(f['title'])}</h3>"
                f"{state}{action}{context}</div>{content}"
                f"<p class='record-footer'><a href='#finding-register'>{esc(L['a_back_to_register'])}</a></p></article>")

    decisions_html = (f"<section><h2>{esc(L['decisions'])}</h2>{bullets(data.get('decisions', []), 'a_no_decisions')}</section>"
                      if data.get("decisions") else "")
    next_steps_html = (f"<section><h2>{esc(L['next_steps'])}</h2>{bullets(data.get('next_steps', []), 'a_no_next_steps')}</section>"
                       if data.get("next_steps") else "")
    excluded_html = (f"<section class='excluded-section' id='excluded-findings'><h2>{esc(L['excluded'])}</h2>"
                     f"<p class='section-note'>{esc(L['a_excluded_note'])}</p>" +
                     "".join(card(f, True) for f in excluded) + "</section>" if excluded else "")

    return f"""<!doctype html>
<html lang="{esc(lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(L['title'])} - {esc(m['project'])}</title><style>{ASSESSMENT_CSS}</style></head><body>
<header class="report-header"><p class="kicker">{esc(L['a_kicker'])}</p><h1>{esc(L['title'])}</h1>
<p class="project">{esc(m['project'])}</p>{meta_top}{scope_lines}</header>
<main>
<section class="summary-section" id="executive-summary"><h2>{esc(L['summary'])}</h2>
<p class="lead">{esc(summary)}</p>{metrics_html}<p class="small">{esc(accounting)}</p>
{parts_html}
<p class="small">{esc(L['a_status_note'])}</p>
{verification_summary_html(model, L, integrity_summary_view(verification_states, fs, L))}
{expert_html(expert_view(data, lang, integrity=integrity), L)}
{three_pass_html(three_pass_view(data, lang, integrity=integrity), L)}
<h3 class="limit-heading">{esc(L['a_limits'])}</h3><p class="small">{esc(L['a_uncertainty'])}</p>
<div class="limits">{bullets(data.get('limitations', []), 'a_limits_empty')}</div></section>
<section id="priority-queue"><h2>{esc(L['a_queue'])}</h2><p class="section-note">{esc(L['a_queue_note'])}</p>{verify_legend}{queue_html}</section>
{decisions_html}{next_steps_html}
<section id="recorded-coverage"><h2>{esc(L['a_coverage'])}</h2><p class="section-note">{esc(L['a_coverage_note'])}</p>
{coverage_html}{ledger_html(data, lang)}<h3>{esc(L['a_checks'])}</h3>{bullets(data.get('checked_ok', []), 'a_checks_empty')}</section>
<section class="finding-register" id="finding-register"><h2>{esc(L['a_register'])}</h2>
<p class="section-note">{esc(L['a_register_note'])}</p>{index_html}</section>
{(f'<section id="finding-details"><h2>{esc(L["details"])}</h2>' + "".join(
    f"<h3 class='part-heading' id='finding-details-{part}'>{esc(L['part_' + part])}</h3>" + "".join(card(f) for f in part_findings[part])
    for part in PARTS if part_findings[part]) + "</section>") if fs else ""}
{excluded_html}
</main></body></html>
"""


CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
]


def to_pdf(html_path, pdf_path):
    """Print html_path to pdf_path with headless Chrome, else WeasyPrint. Returns the engine used or None."""
    # A previous run's PDF must never survive next to newer HTML.
    Path(pdf_path).unlink(missing_ok=True)
    chrome = os.environ.get("CHROME")
    cands = [chrome] if chrome else CHROME_CANDIDATES
    for c in cands:
        exe = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if not exe:
            continue
        pdf = Path(pdf_path)
        pdf.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory() as profile:
            proc = subprocess.Popen(
                [exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                 f"--user-data-dir={profile}", f"--print-to-pdf={pdf}", Path(html_path).resolve().as_uri()],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Chrome on some platforms keeps running after the PDF is written:
            # wait for the file to appear and stop growing, then stop the process.
            last, deadline = -1, time.monotonic() + 120
            while time.monotonic() < deadline:
                size = pdf.stat().st_size if pdf.exists() else -1
                if proc.poll() is not None and size <= 0 and (size < 0 or size == last):
                    break  # Exited without writing (or left an empty file): try the next engine.
                if size > 0 and size == last:
                    break
                last = size
                time.sleep(0.5)
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        if pdf.exists() and pdf.stat().st_size > 0:
            return "chrome"
    wp = shutil.which("weasyprint")
    if wp:
        try:
            r = subprocess.run([wp, str(html_path), str(pdf_path)], capture_output=True, text=True, timeout=120)
        except (subprocess.TimeoutExpired, OSError):
            return None
        if r.returncode == 0 and Path(pdf_path).exists():
            return "weasyprint"
    return None


DASHBOARD = r"""<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{color-scheme:light;--bg:#f6f5f1;--panel:#fff;--text:#1b1b1b;--muted:#5a5a5a;--line:#dcd9d2;--soft:#ecebe5;--high:#8a1c1c;--medium:#7a4800;--low:#24476e;--info:#5a5a5a;--accent:#1f3f66;--tint:#efede6;--warn:#f6f5f1;--warn-line:#1b1b1b;--serif:"Hiragino Mincho ProN","Noto Serif CJK JP","Yu Mincho",Georgia,serif;--sans:system-ui,-apple-system,"Hiragino Sans","Noto Sans CJK JP","Noto Sans JP",sans-serif}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#17171a;--panel:#1f1f23;--text:#ece9e2;--muted:#b3aea4;--line:#3a3936;--soft:#2a2a2e;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b3aea4;--accent:#a9c3e6;--tint:#26252a;--warn:#17171a;--warn-line:#ece9e2}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#17171a;--panel:#1f1f23;--text:#ece9e2;--muted:#b3aea4;--line:#3a3936;--soft:#2a2a2e;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b3aea4;--accent:#a9c3e6;--tint:#26252a;--warn:#17171a;--warn-line:#ece9e2}
*{box-sizing:border-box}[hidden]{display:none!important}html{scroll-behavior:smooth;scroll-padding-top:20px}body{margin:0;overflow-wrap:anywhere;background:var(--bg);color:var(--text);font:14px/1.65 system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif}main{max-width:1320px;margin:auto;padding:32px 28px 48px}a{color:var(--accent);text-underline-offset:3px}button,input,select{font:inherit}button,a,input,select,summary{-webkit-tap-highlight-color:transparent}:focus-visible{outline:3px solid var(--accent);outline-offset:3px}button{cursor:pointer}button,.button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px 12px;text-decoration:none}button:hover,.button:hover{background:var(--soft)}.skip{position:absolute;left:20px;top:-100px}.skip:focus{top:8px;z-index:2}.masthead{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:26px}.brand{font-size:12px;font-weight:750;letter-spacing:.15em;color:var(--accent)}.tools{display:flex;gap:8px;flex-wrap:wrap}.hero{display:flex;justify-content:space-between;gap:24px;margin-bottom:20px}.hero h1{font-size:clamp(25px,3.5vw,38px);line-height:1.25;letter-spacing:-.04em;margin:3px 0 9px;overflow-wrap:anywhere}.eyebrow,.meta,.muted{color:var(--muted)}.eyebrow{font-size:13px}.meta{max-width:820px;overflow-wrap:anywhere}.hero-aside{align-self:flex-end;font-size:12px;text-align:right;max-width:280px}.summary-banner{padding:16px 20px;background:var(--tint);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;margin-bottom:16px}.summary-banner strong{display:block;font-size:18px}.summary-banner p{margin:5px 0 0}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:16px 0}.cards.part-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.part-heading{margin:18px 0 8px}.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;text-align:left}.card .n{font-size:32px;line-height:1.25;font-weight:750;letter-spacing:-.03em}.card .l{font-size:12px;color:var(--muted);display:block;margin-bottom:8px}.card .sub{font-size:12px;color:var(--muted);margin-top:6px}.card.urgent .n{color:var(--high)}.card.review .n{color:var(--medium)}.report-note{font-size:12px;color:var(--muted);margin:8px 0 22px}.section-head{display:flex;justify-content:space-between;gap:16px;align-items:baseline;margin:26px 0 12px}h2{font-size:19px;letter-spacing:-.02em;margin:0}h3{font-size:15px;margin:0 0 6px}.section-head p{margin:4px 0 0;color:var(--muted)}.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:20px}.priority-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,330px),1fr));gap:12px}.hero>div,.priority-item,.panel{min-width:0}.priority-item h3{overflow-wrap:anywhere}.priority-item{border-top:3px solid var(--line)}.priority-item.sev-High{border-top-color:var(--high)}.priority-item.sev-Medium{border-top-color:var(--medium)}.priority-top{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:10px}.priority-item h3 a{text-decoration:none;color:var(--text)}.priority-item h3 a:hover{text-decoration:underline}.priority-item p{margin:8px 0;overflow-wrap:anywhere}.priority-item .action-label{font-size:12px;font-weight:700;color:var(--accent)}.priority-item .impact{color:var(--muted)}.priority-item .action{padding-top:10px;border-top:1px solid var(--line)}.priority-item .location{font-size:12px;color:var(--muted)}.badge{display:inline-block;border:1px solid currentColor;border-radius:5px;padding:1px 7px;font-size:11px;line-height:1.7;font-weight:750;white-space:nowrap}.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--info)}.verdict{font-size:12px;color:var(--muted)}.section-note{font-size:12px;color:var(--muted);margin:10px 0}.coverage{margin:20px 0;background:var(--warn);border-color:var(--warn-line)}summary{cursor:pointer;font-weight:700}summary .small{font-weight:400;color:var(--muted);margin-left:10px}.coverage p{margin:10px 0}.scope-meta{display:grid;grid-template-columns:max-content minmax(0,1fr);gap:5px 16px;margin:16px 0}.scope-meta dt{font-size:12px;color:var(--muted)}.scope-meta dd{margin:0;overflow-wrap:anywhere}.coverage-columns{display:grid;grid-template-columns:1fr 1fr;gap:24px}.coverage ul{margin:6px 0;padding-left:20px}.perspective{border-bottom:1px solid var(--warn-line);padding:9px 0}.perspective:last-child{border:0}.perspective strong{display:block}.perspective p{margin:3px 0;font-size:13px}.chart-section{margin:20px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:16px}.grid .panel{padding:16px}.grid h3{font-size:13px}.bar{display:grid;grid-template-columns:minmax(85px,46%) 1fr 26px;gap:8px;align-items:center;margin:7px 0;font-size:12px}.bar .t{overflow-wrap:anywhere}.bar .track{height:7px;background:var(--soft);border-radius:4px;overflow:hidden}.bar .fill{height:100%;background:var(--accent)}.bar .v{text-align:right;font-variant-numeric:tabular-nums}.filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.filters label{display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--muted)}.filters select,.filters input{width:100%;min-width:0;background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:9px;font-size:13px}.filters .search{grid-column:span 2}.filter-bottom{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:14px}.result-count{font-size:12px;color:var(--muted);margin:0}.tablewrap{overflow-x:auto;background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-top:12px}table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}th{font-size:11px;color:var(--muted);font-weight:700;background:var(--soft)}th:nth-child(1){width:9%}th:nth-child(2){width:9%}th:nth-child(3){width:14%}th:nth-child(4){width:9%}th:nth-child(5){width:11%}th:nth-child(6){width:30%}th:nth-child(7){width:18%}tr.row{cursor:pointer}tr.row:hover{background:var(--tint)}.finding-toggle{border:0;border-radius:3px;padding:0;background:transparent;text-align:left;font-weight:650;color:var(--text);width:100%}.finding-toggle:hover{background:transparent;color:var(--accent)}.finding-toggle .toggle-label{font-size:11px;display:block;font-weight:400;color:var(--accent);margin-top:4px}.location{display:block;overflow-wrap:anywhere;margin-top:4px;font-size:11px;color:var(--muted)}tr.detail>td{background:var(--tint);padding:18px 24px}tr.detail dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px 18px;margin:12px 0}tr.detail dt{font-size:12px;color:var(--muted)}tr.detail dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.detail-actions{display:flex;justify-content:space-between;gap:12px;align-items:center}.detail-links{display:flex;gap:12px;align-items:center;flex-wrap:wrap;flex-shrink:0}.action-guidance{border-left:3px solid var(--accent);padding:8px 12px;background:var(--panel)}.action-guidance strong{display:block}.action-guidance p{margin:4px 0}.three-pass-summary{margin:16px 0;overflow-wrap:anywhere;break-inside:auto!important;page-break-inside:auto}.three-pass-summary .prose{white-space:pre-wrap;overflow-wrap:anywhere}.three-pass-summary h4{margin:12px 0 4px}.three-pass-stage{break-inside:avoid}.verification-record,.workflow-record{margin:16px 0;padding:16px;border:1px solid var(--line);border-radius:6px;min-width:0}.verification-record h4,.workflow-record h4{font-size:15px;margin:0 0 8px}.verification-record h5,.workflow-record h5{font-size:13px;margin:18px 0 6px}.verification-record .prose,.workflow-record .prose{white-space:pre-wrap;overflow-wrap:anywhere}.verification-level,.workflow-status,.workflow-next{display:block;font-size:12px;font-weight:600;margin-top:7px}.history{border:1px dashed var(--line);padding:12px;margin-top:16px}.history p{margin:5px 0;white-space:pre-wrap}.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:12px;margin-top:24px}.lists h2{font-size:16px}.lists ul{margin:10px 0 0;padding-left:18px}.empty{color:var(--muted);padding:20px}.snippet{margin:0;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--panel);overflow-x:auto;font:12px/1.6 ui-monospace,Menlo,monospace;white-space:pre}.snippet span{display:block}.snippet .hit{background:var(--warn)}.snippet b{color:var(--muted);font-weight:400}.refs{margin:0;padding-left:18px}.refs li{overflow-wrap:anywhere}.rt{display:inline-block;min-width:60px;color:var(--muted);font-size:12px}.footer{font-size:12px;color:var(--muted);border-top:1px solid var(--line);margin-top:32px;padding-top:16px}code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
/* Academic layer (docs/report-design.md): serif argument, sans apparatus, booktabs rules, no boxes. */
body{font-family:var(--serif);font-size:15px;line-height:1.7;font-variant-numeric:lining-nums tabular-nums}
h1,h2,h3,h4{font-family:var(--serif);font-weight:700;letter-spacing:0}
button,input,select,label,th,.badge,.brand,.eyebrow,.tools,.filters,.result-count,.card .l,.card .sub,.verdict,.location,.finding-toggle .toggle-label,.priority-item .action-label,.rt,tr.detail dt,.scope-meta dt,.bar,summary .small{font-family:var(--sans)}
.brand{color:var(--muted);letter-spacing:.2em;font-size:11px}
.masthead{border-bottom:1.5px solid var(--text)}
.hero h1{font-size:clamp(26px,3.2vw,36px);letter-spacing:-.01em}
.summary-banner{background:transparent;border:0;border-top:1px solid var(--text);border-bottom:1px solid var(--text);border-radius:0;padding:14px 4px}
.summary-banner strong{font-size:17px}
.cards{gap:28px}
.card{background:transparent;border:0;border-top:1.5px solid var(--text);border-radius:0;padding:12px 2px 6px}
.card .l{letter-spacing:.08em;font-size:11px}
.card .n{font-family:var(--serif);font-weight:400;font-size:34px;letter-spacing:0}
.panel{background:transparent;border:0;border-top:1px solid var(--line);border-radius:0;padding:18px 0}
.priority-item{border-top-width:2px}
.coverage{background:transparent;border:0;border-left:1px solid var(--text);border-radius:0;padding:4px 0 4px 18px}
.coverage-columns{grid-template-columns:1fr;gap:8px}#perspectives{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));column-gap:32px}.perspective,.perspective:last-child{border:0;border-top:1px solid var(--line)}
.bar .fill{background:var(--text)}.bar .track{border-radius:0;height:5px}
.tablewrap{background:transparent;border:0;border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text);border-radius:0}
th{background:transparent;color:var(--text);letter-spacing:.06em;font-size:11px;border-bottom:1px solid var(--text)}
.badge{border:0;padding:0;border-radius:0;letter-spacing:.1em;font-size:11px}
button,.button,.filters select,.filters input{border-radius:2px}
.action-guidance{background:transparent}
.snippet{border:0;border-left:1px solid var(--text);border-radius:0;background:transparent}
.verification-record,.workflow-record{border:0;border-left:1px solid var(--line);border-radius:0;padding:4px 0 4px 16px}
.expert-summary h3,.three-pass-summary h3{margin-top:0}
.footer{border-top:1.5px solid var(--text)}
.priority-item .impact{color:var(--text)}
.finding-toggle{font-family:var(--serif);font-weight:700}
#verification-summary h2,#decisions-section h2{margin-bottom:8px}#decisions-section ul{margin:0;padding-left:20px}
.verify-legend{margin:0 0 14px;color:var(--muted)}.verify-legend .action-label{font-family:var(--sans);font-size:12px;font-weight:700;color:var(--accent)}
.card .n .pair{display:inline-block;white-space:nowrap;margin-right:18px}.card .n .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
td .verification-level{font-family:var(--sans);font-size:11px;font-weight:400;color:var(--muted);margin-top:4px}
.snippet .hit{background:var(--tint)}
@media(max-width:850px){main{padding:22px 18px}.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{display:block}.hero-aside{text-align:left;max-width:none;margin-top:12px}.coverage-columns{grid-template-columns:1fr}.filters{grid-template-columns:repeat(2,minmax(0,1fr))}table,tbody,tr,td{display:block}thead{display:none}tr.row{padding:14px;border-bottom:1px solid var(--line);display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}tr.row td{border:0;padding:0;font-size:12px}tr.row td:before{content:attr(data-label);display:block;color:var(--muted);font-size:10px;margin-bottom:3px}tr.row td:nth-child(6){grid-column:1/-1;grid-row:1}.finding-toggle{font-size:15px}tr.row td:nth-child(7){grid-column:span 2}.detail-actions{align-items:flex-start}tr.detail>td{padding:16px}tr.detail dl{grid-template-columns:1fr;gap:3px}tr.detail dd{margin-bottom:10px}}
@media(max-width:480px){main{padding:16px 12px}.masthead{align-items:flex-start;flex-direction:column;gap:12px}.tools{width:100%}.tools .button{flex:1}.card{padding:14px}.card .n{font-size:28px}.panel{padding:16px}.section-head{display:block}.filters{grid-template-columns:1fr 1fr;gap:10px}.filters label:first-child,.filters .search{grid-column:1/-1}.filter-bottom{align-items:flex-start;flex-direction:column}.scope-meta{grid-template-columns:1fr;gap:2px}.scope-meta dd{margin-bottom:8px}.priority-top{flex-wrap:wrap}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
@media print{body{background:white}.tools,.filters-panel,.chart-section,.skip{display:none}main{padding:0;max-width:none}.panel,.card{break-inside:avoid}.tablewrap{overflow:visible}.footer{margin-top:16px}}
</style>
</head>
<body>
<a class="skip" href="#findings" data-l="jump_findings"></a>
<main>
<header class="masthead"><span class="brand" data-l="eyebrow"></span><div class="tools"><a class="button" href="assessment.html" data-l="assessment_link"></a><button id="theme" type="button" data-l="theme"></button></div></header>
<div class="hero"><div><div class="eyebrow" data-l="dash_title"></div><h1 id="h"></h1><div class="meta" id="meta"></div></div><div class="hero-aside" data-l="report_note"></div></div>
<div class="summary-banner" id="summary"></div>
<div class="cards" id="cards"></div><p class="report-note" data-l="counts_note"></p>
<div class="cards part-cards" id="part-cards"></div><p class="report-note" data-l="part_note"></p>
<section aria-labelledby="priority-heading"><div class="section-head"><div><h2 id="priority-heading" data-l="priority"></h2><p data-l="priority_note"></p></div><a href="#findings" data-l="view_all"></a></div><p class="verify-legend" id="verify-legend" hidden></p><div id="priority"></div><p class="section-note" id="queue-note"></p></section>
<section class="panel" id="decisions-section" aria-labelledby="decisions-heading"><h2 id="decisions-heading" data-l="decisions"></h2><div id="decisions"></div></section>
<section class="panel" id="verification-summary"></section>
__EXPERT__
__THREE_PASS__
<details class="panel coverage" id="coverage" open><summary><span data-l="coverage_heading"></span><span class="small" id="coverage-count"></span></summary><p data-l="coverage_note"></p><dl class="scope-meta" id="scope-meta"></dl><div class="coverage-columns"><section><h3 data-l="limitations"></h3><div id="limitations"></div></section><section><h3 data-l="perspectives"></h3><div id="perspectives"></div></section></div></details>
<details class="chart-section"><summary data-l="overview"></summary><p class="section-note" data-l="count_basis"></p><div class="grid"><div class="panel"><h3 data-l="by_sev"></h3><div id="c-sev"></div></div><div class="panel"><h3 data-l="by_conf"></h3><div id="c-conf"></div></div><div class="panel"><h3 data-l="by_cat"></h3><div id="c-cat"></div></div><div class="panel"><h3 data-l="by_status"></h3><div id="c-status"></div></div><div class="panel"><h3 data-l="by_verdict"></h3><div id="c-verdict"></div><p class="section-note" data-l="excluded_note"></p></div></div></details>
<section id="findings" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading" data-l="findings_register"></h2><p data-l="findings_note"></p></div></div>
<div class="panel filters-panel"><div class="filters">
<label><span data-l="record_set"></span><select id="f-scope"></select></label><label><span data-l="part"></span><select id="f-part"></select></label><label><span data-l="severity"></span><select id="f-sev"></select></label><label><span data-l="confidence"></span><select id="f-conf"></select></label><label><span data-l="category"></span><select id="f-cat"></select></label><label><span data-l="status"></span><select id="f-status"></select></label><label><span data-l="verdict"></span><select id="f-verdict"></select></label><label><span data-l="sort"></span><select id="f-sort"></select></label><label class="search"><span data-l="search"></span><input id="f-q" type="search"></label></div><div class="filter-bottom"><p class="result-count" id="result-count" role="status" aria-live="polite"></p><button type="button" id="reset" data-l="reset"></button></div></div>
<div class="tablewrap"><table><thead><tr><th scope="col">ID</th><th scope="col" data-l="severity"></th><th scope="col" data-l="confidence"></th><th scope="col" data-l="status"></th><th scope="col" data-l="verdict"></th><th scope="col" data-l="title_col"></th><th scope="col" data-l="category"></th></tr></thead><tbody id="rows"></tbody></table></div></section>
<div class="lists" id="lists"></div><footer class="footer" data-l="source_note"></footer>
<noscript><p>__NOSCRIPT__ <a href="assessment.html">__ASSESSMENT__</a></p></noscript>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
'use strict';
var D=JSON.parse(document.getElementById('data').textContent),L=D.labels,ALL=D.findings,R=D.report;
var F=ALL.filter(function(f){return D.excluded_verdicts.indexOf(f.verdict)<0;}),SEV=D.order.severity,CONF=D.order.confidence,ST=D.order.status;
var expanded=new Set();
function el(t,a,txt){var e=document.createElement(t);if(a)Object.keys(a).forEach(function(k){e.setAttribute(k,a[k]);});if(txt!=null)e.textContent=txt;return e;}
function byId(id){return document.getElementById(id);}
function fmt(text,values){return text.replace(/\{(\w+)\}/g,function(_,key){return values[key];});}
function badge(f){return el('span',{'class':'badge '+f.severity},f.severity);}
function excluded(f){return D.excluded_verdicts.indexOf(f.verdict)>=0;}
function ownValue(map,key){return map&&Object.prototype.hasOwnProperty.call(map,key)?map[key]:undefined;}
function action(f){var proof=R.verification[f.id],workflow=ownValue(R.workflows,f.id);return f.status==='Open'&&f.verdict==='Valid'&&f.confidence==='Confirmed'&&proof&&['static_supported','runtime_supported'].indexOf(proof.level)>=0&&(!workflow||workflow.status==='complete')?'fix_now':'verify_first';}
function count(fs,key){var c=Object.create(null);fs.forEach(function(f){c[f[key]]=(c[f[key]]||0)+1;});return c;}
function listInto(box,items,empty){if(!items.length){box.appendChild(el('p',{'class':'muted'},empty));return;}var ul=el('ul');items.forEach(function(x){ul.appendChild(el('li',null,x));});box.appendChild(ul);}
document.title=L.dash_title+' - '+D.meta.project;byId('h').textContent=D.meta.project;
byId('meta').textContent=[D.meta.date,D.meta.assessor].filter(Boolean).join(' · ');
document.querySelectorAll('[data-l]').forEach(function(e){e.textContent=L[e.getAttribute('data-l')];});
byId('theme').onclick=function(){var root=document.documentElement,dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;root.dataset.theme=dark?'light':'dark';};
var summary=byId('summary');
summary.appendChild(el('strong',null,fmt(L.unverified_line,{n:R.unverified,high:R.unverified_high})));
summary.appendChild(el('p',null,F.length?(D.open_hm?fmt(L.risk_summary,{n:D.open_hm}):(R.open_count?fmt(L.open_summary,{n:R.open_count}):L.no_open)):L.no_findings));
var verificationSummary=byId('verification-summary'),verificationSentence=el('p');verificationSummary.setAttribute('aria-labelledby','verification-heading');verificationSummary.appendChild(el('h2',{id:'verification-heading'},L.v_title));D.verification_summary.forEach(function(part){verificationSentence.appendChild(part.key?el('strong',{'data-verification-count':part.key},part.count):document.createTextNode(part.text));});verificationSummary.appendChild(verificationSentence);verificationSummary.appendChild(el('p',{'class':'muted'},L.v_note));
var integritySummary=el('div',{'class':'integrity-summary'});integritySummary.appendChild(el('h3',null,L.i_title));integritySummary.appendChild(el('p',null,D.integrity_summary.text));integritySummary.appendChild(el('p',{'class':'muted'},D.integrity_summary.note));verificationSummary.appendChild(integritySummary);
function workflowNode(f){var view=ownValue(D.workflow_views,f.id);if(!view)return null;var box=el('div',{'class':'workflow-record'});box.appendChild(el('h4',null,L.w_title));box.appendChild(el('p',{'class':'workflow-status'},L.w_status+': '+view.status));box.appendChild(el('p',{'class':'workflow-next'},L.w_next+': '+view.next_stage));box.appendChild(el('p',{'class':'muted'},L.w_note));if(view.gaps.length){box.appendChild(el('h5',null,L.w_gaps));var ul=el('ul',{'class':'workflow-gaps'});view.gaps.forEach(function(gap){ul.appendChild(el('li',null,gap));});box.appendChild(ul);}view.sections.forEach(function(section){var group=el('section');group.appendChild(el('h5',null,section.title));section.items.forEach(function(item){group.appendChild(el('p',{'class':'prose'},item));});box.appendChild(group);});box.appendChild(el('p',{'class':'muted'},L.w_safety));return box;}
function verificationNode(f){var view=D.verification_views[f.id],box=el('div',{'class':'verification-record'});box.appendChild(el('h4',null,L.v_title));box.appendChild(el('p',{'class':'verification-level'},view.level));box.appendChild(el('p',null,L.v_retest+': '+view.retest));if(view.gaps.length){var ul=el('ul',{'class':'verification-gaps'});view.gaps.forEach(function(gap){ul.appendChild(el('li',null,gap));});box.appendChild(ul);}view.sections.forEach(function(section){var group=el('section');group.appendChild(el('h5',null,section.title));section.items.forEach(function(item){group.appendChild(el('p',{'class':'prose'},item));});box.appendChild(group);});return box;}

[[L.open_hm,D.open_hm,'urgent',L.open_count+': '+R.open_count],[L.needs_validation,R.verify_first,'review',L.fix_now+': '+R.fix_now],[L.closed_count,[[R.fixed,'Fixed'],[R.accepted,'Accepted']],'',L.included+': '+F.length],[L.excluded_short,R.excluded,'',L.all_records+': '+ALL.length]].forEach(function(c){var d=el('div',{'class':'card '+c[2]});d.appendChild(el('span',{'class':'l'},c[0]));var n=el('div',{'class':'n'});if(Array.isArray(c[1]))c[1].forEach(function(x){var pair=el('span',{'class':'pair'},x[0]);pair.appendChild(el('span',{'class':'u'},x[1]));n.appendChild(pair);});else n.textContent=c[1];d.appendChild(n);d.appendChild(el('div',{'class':'sub'},c[3]));byId('cards').appendChild(d);});
D.parts.forEach(function(part){var c=R.parts[part],d=el('div',{'class':'card','data-part':part});d.appendChild(el('span',{'class':'l'},L['part_'+part]+' · '+L.open_count));d.appendChild(el('div',{'class':'n'},c.open_count));d.appendChild(el('div',{'class':'sub'},fmt(L.part_card_sub,c)));byId('part-cards').appendChild(d);});
var shownTop=0;D.parts.forEach(function(part){var top=R.queue.filter(function(item){return item.finding.part===part;}).slice(0,4);shownTop+=top.length;if(!R.queue.length)return;byId('priority').appendChild(el('h3',{'class':'part-heading',id:'priority-'+part},L['part_'+part]));var list=el('div',{'class':'priority-list'});byId('priority').appendChild(list);if(!top.length)list.appendChild(el('div',{'class':'panel muted'},L.part_none_open));top.forEach(function(item){var f=item.finding,p=el('article',{'class':'panel priority-item sev-'+f.severity}),head=el('div',{'class':'priority-top'});head.appendChild(badge(f));head.appendChild(el('span',{'class':'action-label'},L[item.action]));p.appendChild(head);var h=el('h3');h.appendChild(el('a',{href:'#'+item.anchor},f.id+' · '+f.title));p.appendChild(h);p.appendChild(el('div',{'class':'verdict'},f.confidence+' · '+f.verdict));p.appendChild(el('code',{'class':'location'},f.location));var workflowView=ownValue(D.workflow_views,f.id);if(workflowView)p.appendChild(el('p',{'class':'workflow-next'},L.w_next+': '+workflowView.next_stage));if(f.impact)p.appendChild(el('p',{'class':'impact'},f.impact));if(item.action==='fix_now')p.appendChild(el('p',{'class':'action'},f.fix||L.missing_fix));list.appendChild(p);});});
if(R.queue.some(function(item){return item.action==='verify_first';})){var legend=byId('verify-legend');legend.appendChild(el('span',{'class':'action-label'},L.verify_first));legend.appendChild(document.createTextNode(' '+L.verify_first_note));legend.hidden=false;}
if(!R.queue.length)byId('priority').appendChild(el('div',{'class':'panel muted'},L.no_open));byId('queue-note').textContent=shownTop<R.open_count?fmt(L.queue_more,{shown:shownTop,total:R.open_count}):'';
['scope','method','commit'].forEach(function(k){byId('scope-meta').appendChild(el('dt',null,L[k==='scope'?'scope_l':k]));byId('scope-meta').appendChild(el('dd',null,D.meta[k]||L.not_recorded));});
byId('coverage-count').textContent=L.limitations_count+': '+D.limitations.length;listInto(byId('limitations'),D.limitations,L.limitations_empty);
if(!D.perspectives.length)byId('perspectives').appendChild(el('p',{'class':'muted'},L.coverage_missing));
D.perspectives.forEach(function(p){var box=el('div',{'class':'perspective'});box.appendChild(el('strong',null,p.name));box.appendChild(el('p',null,p.result||L.not_recorded));if(p.note)box.appendChild(el('p',{'class':'muted'},p.note));byId('perspectives').appendChild(box);});
function bars(id,key,order,colored,fs){var c=count(fs||F,key),keys=order||Object.keys(c).sort(function(a,b){return c[b]-c[a]||a.localeCompare(b);});var max=Math.max.apply(null,keys.map(function(k){return c[k]||0;}).concat([1]));keys.forEach(function(k){var r=el('div',{'class':'bar'});r.appendChild(el('span',{'class':'t'},k));var t=el('div',{'class':'track'}),fill=el('div',{'class':'fill'});fill.style.width=((c[k]||0)/max*100)+'%';if(colored)fill.style.background='var(--'+k.toLowerCase()+')';t.appendChild(fill);r.appendChild(t);r.appendChild(el('span',{'class':'v'},c[k]||0));byId(id).appendChild(r);});}
bars('c-sev','severity',SEV,true);bars('c-conf','confidence',CONF);bars('c-cat','category');bars('c-status','status',ST);bars('c-verdict','verdict',D.order.verdict,false,ALL);
function opts(id,vals,first){var s=byId(id);if(first)s.appendChild(el('option',{value:''},first));vals.forEach(function(v){var pair=Array.isArray(v)?v:[v,v];s.appendChild(el('option',{value:pair[0]},pair[1]));});s.onchange=function(){if(id==='f-verdict'&&D.excluded_verdicts.indexOf(s.value)>=0)byId('f-scope').value='all';draw();};}
opts('f-scope',[['included',L.included_set],['excluded',L.excluded_set],['all',L.all_records]]);opts('f-part',D.parts.map(function(part){return [part,L['part_short_'+part]];}),L.part_all);opts('f-sort',[['priority',L.priority_sort],['severity',L.severity_sort]]);
opts('f-sev',SEV,L.all);opts('f-conf',CONF,L.all);opts('f-cat',Object.keys(count(ALL,'category')).sort(),L.all);opts('f-status',ST,L.all);opts('f-verdict',D.order.verdict,L.all_verdicts);
var q=byId('f-q');q.placeholder=L.search;q.oninput=draw;
function v(id){return byId(id).value;}
function reset(){['f-part','f-sev','f-conf','f-cat','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
byId('reset').onclick=function(){reset();draw();};
function fence(text){var runs=String(text).match(/`+/g)||[],n=Math.max.apply(null,runs.map(function(r){return r.length;}).concat([2]))+1;return Array(n+1).join('`');}
function findingMarkdown(f){var out=['## '+f.id+' · '+f.title,''],p=function(label,value){if(value)out.push('- '+label+': '+value);},block=function(label,value){if(value)out.push('','### '+label,'',value);};
p(L.severity,f.severity);p(L.confidence,f.confidence);p(L.status,f.status);p(L.verdict,f.verdict);p(L.category,f.category);p(L.part,L['part_short_'+f.part]);p(L.location,f.location);p(L.cwe,f.cwe);
if(f.status==='Open'&&!excluded(f)){var a=action(f);block(L[a],L[a+'_note']);}['actor','request','impact'].forEach(function(k){block(L[k],f[k]);});block(L.fix,f.fix);block(L.evidence,f.validation.evidence);block(L.validation_method,f.validation.method);
if(f.snippet){var lines=f.snippet.lines.map(function(text,i){var n=f.snippet.start+i;return (n>=f.snippet.hit[0]&&n<=f.snippet.hit[1]?'>':' ')+String(n).padStart(5,' ')+' '+text;}).join('\n'),fc=fence(lines);block(L.snippet,fc+'\n'+lines+'\n'+fc);}
var refs=(f.source_link?[{type:'source',url:f.source_link,title:L.source_link}]:[]).concat(f.references||[]);if(refs.length)block(L.references,refs.map(function(r){return '- ['+r.type+'] '+(r.title&&r.title!==r.url?r.title+' — ':'')+r.url;}).join('\n'));
[ownValue(D.workflow_views,f.id),D.verification_views[f.id]].forEach(function(view,i){if(!view)return;var body=i?[view.level,L.v_retest+': '+view.retest]:[L.w_status+': '+view.status,L.w_next+': '+view.next_stage];view.gaps.forEach(function(gap){body.push('- '+gap);});view.sections.forEach(function(section){body.push('','#### '+section.title,'');section.items.forEach(function(item){body.push(item);});});block(i?L.v_title:L.w_title,body.join('\n'));});
return out.join('\n')+'\n';}
function copyText(text){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(text);return new Promise(function(resolve,reject){var t=el('textarea',{readonly:'','aria-hidden':'true',style:'position:fixed;top:0;left:-9999px'});t.value=text;document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(e){}t.remove();if(ok)resolve();else reject(new Error('copy'));});}
function copyButton(f){var b=el('button',{type:'button','class':'copy-finding','aria-live':'polite'},L.copy_llm),timer;b.onclick=function(e){e.stopPropagation();var done=function(label){b.textContent=label;clearTimeout(timer);timer=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(findingMarkdown(f)).then(function(){done(L.copied);},function(){done(L.copy_failed);});};return b;}
function details(f,anchor){var dt=el('tr',{'class':'detail',id:anchor+'-detail'});dt.hidden=!expanded.has(anchor);var td=el('td',{colspan:7}),dl=el('dl');
var head=el('div',{'class':'detail-actions'});head.appendChild(el('strong',null,f.id+' · '+f.title));var links=el('span',{'class':'detail-links'});links.appendChild(copyButton(f));links.appendChild(el('a',{href:'#'+anchor},L.permalink));head.appendChild(links);td.appendChild(head);
if(f.status==='Open'&&!excluded(f)){var a=action(f),guidance=el('div',{'class':'action-guidance'});guidance.appendChild(el('strong',null,L[a]));guidance.appendChild(el('p',null,L[a+'_note']));td.appendChild(guidance);}else if(excluded(f)){td.appendChild(el('p',{'class':'muted'},L.excluded_note));}
function field(label,value){dl.appendChild(el('dt',null,label));var dd=el('dd');if(value instanceof Node)dd.appendChild(value);else dd.textContent=value;dl.appendChild(dd);}
field(L.location,f.location);if(f.cwe)field(L.cwe,f.cwe);['actor','request','impact'].forEach(function(k){if(f[k])field(L[k],f[k]);});field(L.fix,f.fix||(f.status==='Open'&&!excluded(f)?L.missing_fix:L.not_recorded));field(L.evidence,f.validation.evidence||L.missing_evidence);if(f.validation.method)field(L.validation_method,f.validation.method);
if(f.snippet){var pre=el('pre',{'class':'snippet'});f.snippet.lines.forEach(function(text,i){var n=f.snippet.start+i,ln=el('span',{'class':n>=f.snippet.hit[0]&&n<=f.snippet.hit[1]?'hit':''});ln.appendChild(el('b',null,String(n).padStart(5,' ')+' '));ln.appendChild(document.createTextNode(text));pre.appendChild(ln);});field(L.snippet,pre);if(f.snippet.truncated)field(L.note,L.snippet_truncated);}
var refs=(f.source_link?[{type:'source',url:f.source_link,title:L.source_link}]:[]).concat(f.references||[]);if(refs.length){var ul=el('ul',{'class':'refs'});refs.forEach(function(r){var li=el('li');li.appendChild(el('span',{'class':'rt'},r.type));li.appendChild(el('a',{href:r.url,target:'_blank',rel:'noopener noreferrer'},r.title||r.url));ul.appendChild(li);});field(L.references,ul);}td.appendChild(dl);var workflow=workflowNode(f);if(workflow)td.appendChild(workflow);td.appendChild(verificationNode(f));
if(f.previous_validation&&typeof f.previous_validation==='object'){var history=el('aside',{'class':'history'});history.appendChild(el('strong',null,L.previous_validation));history.appendChild(el('p',null,L.history_note));['verdict','evidence','method'].forEach(function(k){if(typeof f.previous_validation[k]==='string')history.appendChild(el('p',null,f.previous_validation[k]));});td.appendChild(history);}dt.appendChild(td);return dt;}
function searchText(f){var val=f.validation||{};return [f.id,f.title,f.location,f.category,f.actor,f.request,f.impact,f.fix,f.cwe,f.status,f.severity,f.confidence,f.verdict,val.evidence,val.method].filter(Boolean).join('\n').toLowerCase();}
function draw(){var tb=byId('rows');tb.textContent='';var term=q.value.trim().toLowerCase(),scope=v('f-scope');var pool=scope==='all'?ALL:ALL.filter(function(f){return scope==='excluded'?excluded(f):!excluded(f);});var shown=pool.filter(function(f){return (!v('f-part')||f.part===v('f-part'))&&(!v('f-sev')||f.severity===v('f-sev'))&&(!v('f-conf')||f.confidence===v('f-conf'))&&(!v('f-cat')||f.category===v('f-cat'))&&(!v('f-status')||f.status===v('f-status'))&&(!v('f-verdict')||f.verdict===v('f-verdict'))&&(!term||searchText(f).indexOf(term)>=0);});
shown.sort(function(a,b){var status=v('f-sort')==='priority'?Number(a.status!=='Open')-Number(b.status!=='Open'):0;return status||SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||(v('f-sort')==='priority'?Number(action(a)!=='fix_now')-Number(action(b)!=='fix_now'):0)||Number(a.part==='deps')-Number(b.part==='deps')||String(a.id).localeCompare(String(b.id));});
byId('result-count').textContent=fmt(L.showing,{shown:shown.length,total:pool.length});
if(!shown.length){var empty=el('tr'),td=el('td',{colspan:7,'class':'empty'},pool.length?L.no_matches:L.no_records);empty.appendChild(td);tb.appendChild(empty);return;}
shown.forEach(function(f){var anchor=D.anchors[f.id],tr=el('tr',{'class':'row',id:anchor}),dt=details(f,anchor);var labels=['ID',L.severity,L.confidence,L.status,L.verdict,L.title_col,L.category];var values=[f.id,null,f.confidence,f.status,f.verdict,null,f.category],button;
values.forEach(function(value,i){var cell=el('td',{'data-label':labels[i]},value);if(i===1)cell.appendChild(badge(f));if(i===5){button=el('button',{type:'button','class':'finding-toggle','aria-expanded':String(!dt.hidden),'aria-controls':dt.id},f.title);button.appendChild(el('span',{'class':'toggle-label'},dt.hidden?L.expand:L.collapse));cell.appendChild(button);cell.appendChild(el('code',{'class':'location'},f.location));cell.appendChild(el('span',{'class':'verification-level'},D.verification_views[f.id].level));var workflowView=ownValue(D.workflow_views,f.id);if(workflowView){cell.appendChild(el('span',{'class':'workflow-status'},workflowView.status));cell.appendChild(el('span',{'class':'workflow-next'},L.w_next+': '+workflowView.next_stage));}}tr.appendChild(cell);});
function toggle(){dt.hidden=!dt.hidden;if(dt.hidden)expanded.delete(anchor);else expanded.add(anchor);button.setAttribute('aria-expanded',String(!dt.hidden));button.querySelector('.toggle-label').textContent=dt.hidden?L.expand:L.collapse;}
button.onclick=function(e){e.stopPropagation();toggle();};tr.onclick=function(e){if(!e.target.closest('a,button'))toggle();};tb.appendChild(tr);tb.appendChild(dt);});}
function openHash(){var anchor=window.location.hash.slice(1),f=ALL.find(function(x){return D.anchors[x.id]===anchor;});if(!f)return;reset();if(excluded(f))byId('f-scope').value='all';expanded.add(anchor);draw();var row=byId(anchor);row.scrollIntoView({block:'start'});row.querySelector('button').focus({preventScroll:true});}
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===window.location.hash){e.preventDefault();openHash();}});
window.addEventListener('hashchange',openHash);draw();if(window.location.hash)openHash();
listInto(byId('decisions'),D.decisions,L.not_recorded);
['next_steps','checked_ok'].forEach(function(k){var p=el('section',{'class':'panel'});p.appendChild(el('h2',null,L[k]));listInto(p,D[k],L.not_recorded);byId('lists').appendChild(p);});
})();
</script>
</body>
</html>
"""


def render_dashboard(data, L, lang, integrity=None):
    for f in data["findings"]:
        if f.get("source_link"):
            http_url(f["source_link"], "source_link")
        for ref in f.get("references", []):
            http_url(ref["url"], "references.url")
    model = report_model(data, integrity=integrity)
    verification_states = derive_verification(data, SchemaError, integrity=integrity)
    workflows = workflow_states(data, integrity=integrity)
    payload = {
        "meta": {key: data["meta"][key] for key in ("project", "date", "assessor", "scope", "method", "commit", "source_url")
                 if key in data["meta"]},
        **({"three_pass_view": three_pass_view(data, lang, integrity=integrity)} if "three_pass" in model else {}),
        **({"expert_view": expert_view(data, lang, integrity=integrity)} if "expert" in data else {}),
        "workflow_views": {f["id"]: workflow_view(data, f, workflows[f["id"]], lang)
                           for f in data["findings"] if f["id"] in workflows},
        "findings": [display_finding(f, model["verification"][f["id"]]) for f in data["findings"]],
        "labels": L, "open_hm": stats(data)["open_hm"], "report": model,
        "verification_views": {f["id"]: verification_view(data, f, verification_states[f["id"]], lang)
                               for f in data["findings"]},
        "verification_summary": verification_summary_parts(model, L),
        "integrity_summary": integrity_summary_view(verification_states, active(data), L),
        "anchors": {str(f["id"]): finding_anchor(data, f) for f in data["findings"]},
        "parts": list(PARTS),
        "order": {"severity": SEVERITIES, "confidence": CONFIDENCES, "status": STATUSES, "verdict": VERDICTS},
        "excluded_verdicts": sorted(EXCLUDED),
        **{k: data[k] for k in ("checked_ok", "decisions", "limitations", "next_steps", "perspectives")},
    }
    # Escape every less-than sign: <!-- and <script also change HTML parsing.
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c")
    title = html.escape(f"{L['dash_title']} - {data['meta']['project']}")
    replacements = {"__LANG__": lang, "__TITLE__": title, "__NOSCRIPT__": esc(L["no_script"]),
                    "__ASSESSMENT__": esc(L["assessment_link"]), "__DATA__": blob,
                    "__THREE_PASS__": three_pass_html(payload.get("three_pass_view"), L),
                    "__EXPERT__": expert_html(payload.get("expert_view"), L)}
    # Substitute only template tokens, not token-like strings inside report data.
    return re.sub(r"__(?:LANG|TITLE|NOSCRIPT|ASSESSMENT|DATA|THREE_PASS|EXPERT)__",
                  lambda match: replacements[match.group(0)], DASHBOARD)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation")
    p.add_argument("--repo", help="audited repository root: embeds redacted source excerpts for path:line locations")
    p.add_argument("--evidence-root", help="explicit local root for fresh evidence-file SHA-256 checks; never executes recorded commands")
    p.add_argument("--evidence-repository", help="explicit local Git repository for commit/path blob checks; requires --evidence-root")
    a = p.parse_args(argv)
    if a.evidence_repository and not a.evidence_root:
        p.error("--evidence-repository requires --evidence-root")
    try:
        data = load(a.findings)
        integrity = None
        if a.evidence_root is not None:
            try:
                integrity = verify_evidence(data, a.evidence_root, repository=a.evidence_repository)
            except (ValueError, OSError):
                # Evidence setup errors can contain private filesystem paths.
                raise SchemaError("evidence integrity: unable to check the explicitly supplied local inputs") from None
        attach_sources(data, a.repo)
        L = LABELS[a.lang]
        # Render before creating any output: nested extension data can fit the
        # input decoder but exceed the encoder limit inside the report payload.
        dashboard = render_dashboard(data, L, a.lang, integrity=integrity)
        assessment = render_assessment_html(data, L, a.lang, integrity=integrity)
    except RecursionError:
        print("render.py: report: JSON nesting is too deep to render", file=sys.stderr)
        return 2
    except (SchemaError, OSError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    html_path = out / "assessment.html"
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "dashboard.html").write_text(dashboard, encoding="utf-8")
        html_path.write_text(assessment, encoding="utf-8")
        if a.no_pdf:
            (out / "assessment.pdf").unlink(missing_ok=True)
    except OSError as e:
        print(f"render.py: cannot write outputs to {a.out}: {e.strerror or e}", file=sys.stderr)
        return 2
    print(f"wrote {out / 'dashboard.html'}")
    print(f"wrote {html_path}")
    if a.no_pdf:
        return 0
    engine = to_pdf(html_path, out / "assessment.pdf")
    if not engine:
        print("render.py: no PDF engine found (Chrome/Chromium or weasyprint); "
              "assessment.html is ready to print", file=sys.stderr)
        return 3
    print(f"wrote {out / 'assessment.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
