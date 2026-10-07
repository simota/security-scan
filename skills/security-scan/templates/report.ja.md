<!--
検出した脆弱性を担当者・セキュリティ窓口・管理者へ報告するテンプレート（メール、非公開チケット、Security Advisory 用）。
1 通に複数の finding をまとめられる。数値と各 finding の内容は findings.json（または dashboard.html の
「コピー」ボタンの出力）から転記し、ダッシュボードと食い違わないようにする。

送る前に確認すること:
- 宛先がリポジトリの閲覧権限を持つ人に限られている。そうでなければソース抜粋を外す
- 動く攻撃ペイロード、シークレットの値を含めていない
- 未検証（Unverified / Likely / Unlikely）の finding を確定事項として書いていない
-->

**件名:** [セキュリティ報告] {{meta.project}} — High {{n_high}} 件 / Medium {{n_medium}} 件（{{meta.date}}）

## 1. 要約

<!-- 最初の 1 行で結論を書く。例: 「他テナントの注文を閲覧できる不備を 1 件確認しました。修正まで該当 API の公開範囲の見直しを推奨します。」 -->


| 深刻度 | 件数 | うち検証済み（Valid） |
|---|---|---|
| High | {{n_high}} | |
| Medium | {{n_medium}} | |
| Low | {{n_low}} | |
| Info | {{n_info}} | |

除外（FalsePositive / NotApplicable）: {{n_excluded}} 件。未検証: {{n_unverified}} 件。

## 2. 対象と方法

| 項目 | 値 |
|---|---|
| 対象 | {{meta.project}} |
| 範囲 | {{meta.scope}} |
| リビジョン | {{meta.commit}} |
| 方法 | {{meta.method}} |
| 診断日 / 診断者 | {{meta.date}} / {{meta.assessor}} |

稼働中の環境へのリクエスト送信は行っていません。

## 3. 優先して対応すべき項目

<!-- 深刻度順。1 件ごとに下のブロックを繰り返す。詳細は issue テンプレート（templates/issue.ja.md）で起票した issue へリンクする。 -->

### {{id}}: {{title}}

- **深刻度 / 確度 / 判定:** {{severity}} / {{confidence}} / {{validation.verdict}}
- **場所:** `{{location}}`
- **実行できる主体:** {{actor}}
- **リクエストの形:** {{request}}
- **影響:** {{impact}}
- **修正方針:** {{fix}}
- **追跡先:** <issue / advisory の URL>

## 4. 依存関係とサプライチェーン

<!-- D-* の finding。パッケージ名、影響バージョン、修正バージョン、アドバイザリ URL。実行されなかった監査（dependency_scan.not_run）も書く。 -->
- 

## 5. 問題がなかった項目

<!-- checked_ok。何を見て問題がなかったかを書く。否定の記録がない報告は、見ていない報告と区別できない。 -->
- 

## 6. 確認できなかったこと（制約）

<!-- limitations。本番設定、実データ、インフラなど静的解析で分からないこと。 -->
- 

## 7. 判断をお願いしたい点

<!-- decisions。ルールが文書化されていない箇所、受容するかどうかなど。 -->
- 

## 8. 推奨する対応順

<!-- next_steps。 -->
1. 

## 添付

- `assessment.pdf` — 診断報告書
- `dashboard.html` — 全 finding の一覧（オフラインで開けます）

<!-- 公開の予定がある場合: 公開予定日、修正版の提供予定、CVE 採番の要否を書く。 -->
