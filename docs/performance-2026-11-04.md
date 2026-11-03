# 性能最適化の検証記録 — 2026-11-04（JST）

## A. 最適化サマリー

基準コミットは `ddaca26df47253abd12414282982f0aa87b792cf`。取得直後の作業ツリーに未コミット変更がないことを確認し、専用ブランチで作業した。最初に全体監査・`make check`・既存8ワークロードの3規模測定を行い、その後に独立した候補を実装・比較した。実行環境は Python 3.12.14 / Linux x86_64。新しい実行時依存関係は追加していない。

本記録の数値は合成したオフライン入力に対する実測であり、ネットワーク監査や本番利用全体の速度を表すものではない。全指標・全入力に対する非劣化を証明したとは扱わない。合成fixtureのうち改善を採用した経路と、無変更の対照経路を区別する。生サンプル、条件、出力ハッシュ、初期値と再測定値は [測定データ](performance-2026-11-04.json) に保存した。

### 調査した領域

| 領域 | 確認範囲・判断 |
|---|---|
| 構成・主要経路 | 標準ライブラリ中心の Python CLI。依存スキャン、所見更新、証拠取得・検証、HTML/PDF生成、契約確認、実行管理を横断した。Python 3.9/3.12 のCIを持ち、Cargo workspaceの一部解析は3.11以降の `tomllib` を使用する。 |
| アルゴリズム | ID重複判定、F/D分類、除外所見の採番、Compose要素の選別、workflow解析の繰り返し、ファイル名判定、URL redactionを確認・計測した。URLの変更は最終的に取り消した。 |
| メモリ・キャッシュ | ソートの一時領域、分類リスト、レポート索引、局所LRU、文字列保持、URL callback生成を確認した。永続キャッシュやキャッシュ上限の変更は加えていない。 |
| I/O・証拠 | ファイルの種別・リンク拒否、サイズ・件数・時間制限、ハッシュ、前後の同一性確認を維持した。再読み込みの省略は行わない。 |
| 非同期・並列・復旧 | writer lock、子プロセスへの継承、期限超過時の終了、checkpoint、stage/rollback、原子的公開を確認した。製品側の並列度は変更していない。 |
| 外部監査・依存 | 外部監査の呼出し、結果解析、triageを調査した。オンライン通信の速度・負荷は未測定で、外部監査の並列化や永続結果キャッシュは保留した。 |
| データベース | 通常業務向けのDB経路はない。SQLiteは件数を制限した再現用fixtureに用いられる。DB改善を成果には数えない。 |
| HTML・JS/CSS・PDF | HTML生成経路、検索・ソート・遅延描画、印刷処理を調査した。既存JSの検索キャッシュ・debounce・詳細DOM遅延構築・共有Collatorを確認。ブラウザやアクセシビリティの実測不足からJS/CSS/PDF実装は変更しない。 |
| vendor・生成物 | `scan_report_kit` とその `MANIFEST` は変更していない。生成されたレポートを製品コードとして編集していない。 |
| CI・ビルド | Makefile、文書参照、構文、vendor整合性、サンプル描画、自己スキャン、Python行列、必須Chrome/PDF gateを確認した。一般的なコンパイルやフロントエンドbundle工程はない。 |

### 実装した最適化

| 優先 | 対象 | 問題と変更 | 計算量・互換性の根拠 |
|---|---|---|---|
| 1 | 契約チェック | IDごとの全件 `count` と所見辞書のmembership比較を除去。ID配列をその場でソートし、隣接重複を一度だけ診断する。F/Dを一回で分類し、不要になったID配列を解放する。 | 重複判定は O(N²)→O(N log N)、分類はO(N²)→O(N)。重複の辞書順、一意性、診断順、F/D相対順を維持。 |
| 2 | 採番 | active/excludedを一回で分類し、従来と同じキーでソート。分類後の参照リストを解放する。 | O(N×除外数)の辞書比較を削除。最初のID走査を残し、異常入力の例外優先順位を維持。 |
| 3 | Compose | トップレベル要素とサービス配下要素の相互membershipを削除。 | ソース行範囲が交わらないため常に不一致。対象選別のO(T×S)を除去し、検査対象・順番・行番号を維持。 |
| 4 | workflow | trigger抽出をテキストごとに一回へ集約。ローカル参照に必須の `./` がない場合だけローカルグラフ用の再解析を省く。 | ファイル読み込み、通常のセキュリティ検査、privilege/input伝播、順序・上限・不完全判定を維持。 |
| 5 | requirements判定 | prose除外regexを、結果が必要な最後の `requirements/` 分岐へ移動。 | 短絡順序、bool戻り値、suffix iterableの消費回数を維持。不一致拡張子や明示的なrequirements名で重複作業を減らす。 |

### 採用しなかった候補

| 候補 | 採否・理由 |
|---|---|
| requirementsの拡張子不一致を先頭でreturn | 最初の案ではrequirementsディレクトリ内の分類でCPU約6.2%増。取り消し、上記の遅延評価へ変更した。 |
| URL guard＋callback共有の最終候補 | OSV解析・HTML生成のCPU時間とプロセスRSSは改善したが、通常規模reportでPython traced peakの増加が繰り返し観測された。通常条件の非劣化が未確定のため本体と6専用testsを取り消し、全統合比較をやり直した。 |
| URL syntax guard単独 | コロン・percentを含む非URLでCPU平均+2.240%、95%区間+0.428～+3.960%。単独案は不採用。callback生成も除去した組合せを別途比較したが、その組合せも上記理由で取り消した。 |
| `has_url_credentials` の同様のguard | 非劣化の根拠が不足したため実装を残していない。 |
| レポートの検証カタログ索引共有 | 時間は改善したが、standalone呼出しの追加メモリや内部API拡張を含む非劣化を確定できず取り消した。 |
| 既知ラベルのeager fallback省略 | LRUに入るキーとeviction順が変わる。境界測定の微小peak差は正逆で反転し固定劣化とは判定しなかったが、保持する文字列サイズまで含めた非劣化が未確定のため取り消した。 |
| Gitオブジェクトのheader/body分割hash | 16MiB単体では改善したが、64B入力で追加peak32B、[hashlibのGIL解放条件](https://docs.python.org/3.12/library/hashlib.html)の境界の変更、実Gitで明確な改善を確定できない問題が残ったため取り消した。 |
| 証拠の再読込省略・検証共有 | 競合・変更・stale結果の検出に必要。安全境界を弱める変更は採用しない。 |
| 全体redaction cache、外部監査並列化、runnerコピー削減、deepcopy範囲縮小、CI cache変更 | 保持量・失効・エラー順序・復旧・外部負荷・実CI効果の検証が不足しており保留。 |

`render.py`、`url_redaction.py`、`evidence_integrity.py`、vendored assets、実行制限、依存関係、CIの必須検査条件は基準と同一である。

## B. 変更ファイル一覧

| ファイル | 変更内容・目的 | 互換性・検証 |
|---|---|---|
| `skills/security-scan/scripts/contract_check.py` | 重複ID検査と所見分類の反復削減、一時配列の寿命短縮 | 診断順・内容・入力不変、ランダム/不正ID/欠損出力、6回帰テスト |
| `skills/security-scan/scripts/findings.py` | active/excludedの一回分類と一時配列解放 | 採番・辞書挿入順・例外優先順位・除外比率、6回帰テスト |
| `skills/security-scan/scripts/deps_scan.py` | Compose、workflow、ファイル名判定の重複作業削減 | 2,861ケース差分一致、8回帰テスト、I/Oカウンタ |
| `scripts/ci/benchmark_performance.py` | 任意のCPU・P95/P99・throughput・Python peak・RSS測定 | 既定JSONのキーを維持する回帰テスト。時間とallocationの測定を分離 |
| `scripts/ci/benchmark_pipeline.py` | 3規模のscan/contract/renumber/HTML/URL/Git-control fixture | 同一fixture・完全出力hash・無害なオフライン入力 |
| `scripts/ci/compare_performance.py` | 別interpreterの交互比較、出力一致、raw sample、bootstrap区間 | 固定revisionの上書き拒否、timeout・子プロセス終了、同一revision smoke test |
| `tests/test_contract_performance.py` | 6回帰テスト | 全体suiteに含めて実行 |
| `tests/test_findings_renumber_performance.py` | 6回帰テスト | 全体suiteに含めて実行 |
| `tests/test_scan_efficiency.py` | 8回帰テスト | 全体suiteに含めて実行 |
| `tests/test_performance_harness.py` | 3回帰テスト | 既定出力形式、予約引数、2-worker比較の完了を検証 |
| `README.md` | 計測方法・新しい比較コマンドの説明 | 文書参照検査 |
| `docs/ci.md` | 条件・限界・RSS範囲・再現コマンドの説明 | 文書参照検査 |
| `docs/performance-2026-11-04.md` | 本報告 | 生データから性能表を生成 |
| `docs/performance-2026-11-04.json` | raw samples・hash・実行条件・判断材料 | 未測定値を補完しない |

## C. 性能比較

### 測定方法

- 同じLinux環境とPython、CPU affinity 1、`PYTHONHASHSEED=0`、bytecode書込みなし。同じ最新harnessで基準worktreeと候補を測定した。
- revisionごとに別interpreterを使い、3回warmup後、各21ペアを前→後／後→前で交互実行した。timed operation同士は並走させていない。
- 入力生成・コピー・IPC・結果hashは計測外。OS/filesystem cacheはwarmで、cold-cache計測とは区別する。
- 時間・CPUと、3回のtracemalloc実行を分離した。各回の完全結果hash一致が必須。採番の辞書挿入順は別の差分テストでも確認した。
- 区間はpaired bootstrap 3,000再標本化による平均時間比の95%区間。1を跨ぐ結果を改善・等価の証明とはしない。多数のケースの未調整区間であり、同一revision同士の対照でも一部に偏りが出るため、単一の有意判定だけで採否を決めず、再測定とコード構造も確認した。
- P95/P99はnearest-rank。21回のP99は観測最大値で、本番tail/SLOを推定できる精度ではない。
- throughputは1バッチ／平均時間。製品の同時リクエスト処理能力ではない。
- Python peakはoperation中に新規追跡したallocationであり、事前の入力・importsを含まない。RSSはworker全体のhigh-waterで、先行workloadやtracingも含む。両者を混同しない。

### 高負荷ワークロード

| ワークロード | 前P50 ms | 後P50 ms | P50変化 | 平均時間比95%区間 | 出力 |
|---|---:|---:|---:|---|---|
| Compose（1,500 services / 1,000 extensions） | 53.335 | 33.619 | -36.97% | 0.606–0.640 | 一致 |
| remote workflow（48 files × 160 steps） | 379.463 | 327.099 | -13.80% | 0.817–0.908 | 一致 |
| local actionを含むworkflow（48 files × 160 steps） | 403.498 | 405.701 | +0.55% | 0.942–1.056 | 一致 |
| source tree（10,000 files） | 471.338 | 437.467 | -7.19% | 0.906–0.976 | 一致 |
| 契約チェック（1,800所見） | 94.160 | 5.346 | -94.32% | 0.055–0.064 | 一致 |
| 採番（999所見、半数除外） | 12.904 | 1.232 | -90.45% | 0.079–0.108 | 一致 |
| HTML 2種（400所見・500証拠・200実行） | 938.391 | 952.789 | +1.53% | 0.994–1.039 | 一致 |
| URLを含まない10,000フィールド | 14.146 | 14.325 | +1.27% | 0.938–1.028 | 一致 |
| 500 URL/行 × 20行 | 79.271 | 80.001 | +0.92% | 0.979–1.033 | 一致 |
| 約21Ki文字、末尾区切り文字 × 100行 | 167.094 | 166.131 | -0.58% | 0.973–1.093 | 一致 |
| workspace探索（600 members） | 617.295 | 576.435 | -6.62% | 0.945–1.047 | 一致 |
| source excerpts（500所見・10,000行） | 40.760 | 41.205 | +1.09% | 0.905–1.034 | 一致 |
| 既存HTML fixture（400所見） | 987.856 | 988.932 | +0.11% | 0.942–1.040 | 一致 |
| source modelなしtriage（100所見） | 0.944 | 1.017 | +7.65% | 0.929–1.224 | 一致 |
| live-integrity HTML（200所見・500証拠） | 1674.410 | 1736.688 | +3.72% | 0.943–1.025 | 一致 |
| OSV独立groups（2,000 records） | 393.577 | 388.323 | -1.33% | 0.919–1.002 | 一致 |
| OSV alias pairs（2,000 records） | 300.110 | 301.903 | +0.60% | 0.925–1.044 | 一致 |
| OSV groupなし（2,000 records） | 416.208 | 415.009 | -0.29% | 0.952–1.019 | 一致 |

### 指標別：契約チェック1,800所見

| 指標 | 最適化前 | 最適化後 | 変化率 | 判定 |
|---|---:|---:|---:|---|
| 平均実行時間 | 95.742 ms | 5.702 ms | -94.04% | 改善 |
| P50 | 94.160 ms | 5.346 ms | -94.32% | 改善 |
| P95 | 114.371 ms | 8.420 ms | -92.64% | 改善 |
| P99（観測最大） | 125.639 ms | 9.424 ms | -92.50% | 改善 |
| CPU時間P50 | 94.157 ms | 5.349 ms | -94.32% | 改善 |
| 直列throughput | 10.445 checks/s | 175.379 checks/s | +1579.11% | 改善 |
| Python peak（3回中央値） | 1,472,420 B | 1,456,252 B | -1.10% | 改善 |
| ファイル読込 | 4回 | 4回 | 0% | 読込量も同一（個別I/O計測） |
| 物理disk I/O・online network・DB負荷 | 未測定 | 未測定 | — | 未検証／DB通常経路は対象なし |
| CPU使用率・GC pause・並行throughput | 未測定 | 未測定 | — | 未検証 |

### 全規模のP50変化率

数値は各初回統合比較の点推定である。小規模のノイズや再測定の結果を省略しない。URL・HTMLなど本体が無変更の対照経路の変動を改善成果に数えない。raw samplesと信頼区間は測定データを参照する。

| ワークロード | small | normal | high |
|---|---:|---:|---:|
| compose | -0.82% | +0.88% | -36.97% |
| workflow_remote | -10.17% | -17.43% | -13.80% |
| workflow_local | -8.52% | +0.81% | +0.55% |
| source_tree | -7.71% | -3.26% | -7.19% |
| contract | +7.93% | -50.93% | -94.32% |
| renumber | -17.24% | -78.67% | -90.45% |
| verification_catalog | -3.03% | -0.23% | +1.53% |
| url_plain | +1.52% | -2.17% | +1.27% |
| url_dense | +0.11% | -6.28% | +0.92% |
| url_symbols | -0.11% | -0.32% | -0.58% |
| offline_workspaces | -1.06% | -2.09% | -6.62% |
| shared_source_excerpts | -9.55% | -2.15% | +1.09% |
| structured_verification_report | -2.41% | +3.22% | +0.11% |
| triage_without_source_model | -2.80% | -12.95% | +7.65% |
| live_integrity_report | -6.08% | -1.64% | +3.72% |
| osv_distinct_groups | -7.73% | +1.98% | -1.33% |
| osv_alias_pairs | +0.38% | -1.10% | +0.60% |
| osv_ungrouped | -4.87% | -5.20% | -0.29% |

### 小規模・メモリ・起動の追加検証

小規模の契約チェックは初回21ペアでP50が増えたが、同じharness・入力を501ペアで再測定した。下表はその再測定であり、初回値は上表と生データに残している。時間比の区間が1を跨ぐため、改善とも同等性の証明とも扱わない。

| 指標 | 前 | 後 | 判定 |
|---|---:|---:|---|
| P50 | 0.333156 ms | 0.333386 ms | +0.069%、明確な差を確認せず |
| 平均時間比95%区間 | — | 0.979–1.050 | 同等性の証明ではない |
| Python peak | 207,802 B | 207,625 B | 減少 |

scanの初回比較には別々のfixtureディレクトリを用いた。Composeで4 B、source treeで4 / 36 / 96 Bの差が出たため、同じ実ファイル・inode・内容・安定metadataを使い、各revisionを新しいinterpreterで3回warmup＋5回traceした。高負荷Composeとsource treeの3規模は、対応する5サンプルのpeakと保持データがすべて一致した。

| 共有入力 | 前Python peak中央値 | 後Python peak中央値 | 結果 |
|---|---:|---:|---|
| high/compose | 1,336,553 B | 1,336,553 B | 出力・順序・保持サイズ・各peak一致 |
| small/source_tree | 48,892 B | 48,892 B | 出力・順序・保持サイズ・各peak一致 |
| normal/source_tree | 1,965,721 B | 1,965,721 B | 出力・順序・保持サイズ・各peak一致 |
| high/source_tree | 12,537,983 B | 12,537,983 B | 出力・順序・保持サイズ・各peak一致 |

small/local workflowは最初のtraceに59 Bの差が残り、5回中央値では8 B差だった。同じ実ファイルとworkerを使ってrevision実行順を逆にした再測定では、対応する5サンプルすべてが一致した（38,432 / 38,424 / 38,416 / 38,408 / 38,392 B）。初回差を隠さず記録し、持続する増加とは判定していない。

無変更の描画関数を使う対照にも差が残る。normal catalogのPython peak中央値は5,123,424→5,123,706 B（+282 B）、high live-integrityは10,579,175→10,585,144 B（+5,969 B）だった。両経路の計測本体は今回変更した関数を呼ばないことを静的に確認した。同一revision同士の対照でも変動が観測されるが、import状態や先行workloadも含むため、この残差の機序を測定ノイズと特定したわけではない。これらを速度改善・完全なメモリ同等性の根拠には数えない。

起動は4つのCLIの `--help` をfresh interpreterで各31ペア比較した。既存bytecodeの有無による条件差を除くため、両revisionで同じ空のbytecode prefixを指定した。さらにscriptパスの差を除くため、同一の作業用コピーへ本体3ファイルだけを計測外で切り替え、全変更ファイルのbyte一致を確認してから起動した。bytecodeの読み込み・書き込みはともに行わない。OSのファイルcacheはwarmであり、cold-cache起動とは異なる。異なるscriptパスで測定した最初の2回も、生データの予備測定欄に残している。

| CLI | 前起動P50 ms | 後起動P50 ms | 平均時間比95%区間 | 前/後RSS中央値 B |
|---|---:|---:|---|---:|
| deps_scan.py | 361.791 | 353.288 | 0.954–1.028 | 27,172,864 / 27,164,672 |
| findings.py | 276.994 | 289.018 | 0.994–1.090 | 23,310,336 / 23,285,760 |
| contract_check.py | 196.392 | 195.057 | 0.970–1.050 | 17,354,752 / 17,354,752 |
| render.py | 330.760 | 318.112 | 0.955–1.034 | 22,204,416 / 22,204,416 |

上記のRSSはwrapper・imports・source compileを含むプロセス全体のhigh-waterである。起動時間やRSSの小さな点推定差だけから改善・非劣化を断定しない。全サンプルとCPU区間は生データに保存した。

### その他のメモリ・I/O検証

IDをランダム順にした1,800件のfull contract checkを、出力ファイルがすべて欠ける条件でも比較した。大きなJSON読込にpeakが隠されない条件で、valid / invalid / mixedの診断が一致し、3ケースともpeakが約16 KiB減少した。採番は0/1/10/999件・除外なし/半数/全数の9ケースでpeakが減った。

scanのPythonファイルAPIカウンタでは、Compose・source tree・local workflowの回数と入力読込byte数が同一。remote workflowは `read_text` 40回・141,035 Bを維持し、`stat` 170→166、`lstat` 426→394となった。これはPython APIの観測であり、物理disk転送量やOS cache missの実測ではない。

URL候補を含んだ統合試行と追加診断は `pre_integration_experiments` の `rejected_url_integrated` / `rejected_url_followups` に分離した。採用後の数値に流用していない。候補取消後に基準と最終状態を改めて全比較した。最終状態の追加比較は `followups` に保存した。

## D. 品質保証結果

- 初期 `make check`: 1,097件実行、成功1,071、失敗0、error0、既存opt-in skip26。
- 最終 `make check`: 1120件実行、成功1094、失敗0、error0、skip26。追加23件はすべて成功。
- 追加テストは実行速度の閾値でなく、出力・順序・異常系・入力不変・比較回数の上限を確認する。
- 同じ内容・異なる順序のID、欠落/非文字列/Unicode ID、重複・同一辞書、除外所見、Compose legacy/empty/repeated section、local call伝播、escaped trigger、suffix generatorを検証した。
- 検討中のURL案でも型・例外・quote位置・多重encoding等を差分検証したが、メモリ条件の非劣化未確定により取り消した。この案の6専用テストは最終suite数に含めない。既存のURL・redaction回帰テストは全体suiteで実行する。
- `make benchmark`、`make detection-benchmark`、文書参照、vendor MANIFEST、サンプル描画、自己依存スキャン、`git diff --check`、NodeによるJS構文チェックを実行した。
- 全PythonファイルをPython 3.9文法でAST解析した。これは実際のPython 3.9 runtimeテストや型チェックとは別である。
- 専用type checker/linter設定は存在しない。mypy/ruff成功とは報告しない。通常のコンパイル・bundle工程はなく、`make check`を配布整合性のgateとして扱う。
- 起動確認はfresh interpreterのCLI `--help`を各31ペアで比較。出力hashを一致させ、warm filesystem・同一runpy wrapperの条件と全サンプルを測定データに記録した。

### ブラウザ・PDFとCI

ローカルには実行可能なChrome/ChromiumとPython Playwrightがなく、既存opt-inの26件は未実行。必須browser/PDF gateの成功とは扱わない。

基準コミットの [CI run 41657402714](https://github.com/simota/security-scan/actions/runs/41657402714) ではPython 3.9/3.12 jobsは成功し、reports jobはテスト実行前のChrome version guardで失敗していた。観測版 `156.0.8078.79` に対し許可版は `155.0.8059.39,156.0.8078.47`。今回、許可リスト・必須テスト・skip禁止条件を緩めていない。候補コミットのCI結果はPRのChecksを参照する。

## E. 残存リスク・終了条件

1. 実ネットワーク監査、外部サービス負荷、cold-cache起動、実disk転送量、GC pause分布、多利用者でのP95/P99・同時実行throughputは未検証である。
2. report peakの微小変動と時間ノイズは初回値・再測定・同一revision controlで区別する。信頼区間が1を跨ぐだけでは同等性の証明にならない。
3. ブラウザの表示品質、アクセシビリティ、日本語/英語PDFの実行確認には、承認済みの実ブラウザ環境の復旧が必要である。
4. カタログ索引共有、全体cache、外部監査の並列化、runnerのコピー削減には残存余地があるが、保持量・失効・競合・障害復旧を含む非劣化を確認するまで保留する。
5. 検証できない領域の改善率・運用費用削減率を推測で補っていない。高リスクの追加変更や、測定ノイズ内の効果を追って複雑化する段階で停止した。

## 再現

`docs/ci.md` の「Offline performance comparisons」に、両worktreeを同じharnessで比較するコマンドと各指標の範囲を記載している。厳密なサイズ・引数・環境は測定データの `comparison_invocations` を使う。基準コミットと候補のproduction file SHA-256も同ファイルに記録した。外部監査コマンド・対象アプリ・記録されたreproduction commandをベンチマークが実行することはない。
