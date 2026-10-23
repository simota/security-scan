# Detection benchmark evidence

`scripts/ci/benchmark_detection.py` turns already-recorded security-scan
findings and independent adjudications into versioned detection evidence. It is
an offline adapter: it does not invoke security-scan, execute a target, call a
model, fetch a corpus, or decide whether findings match ground truth.

## Claim boundary

Every result labels its measured modality `static-source-review`, its scope
`security-scan-only`, and `artex_outcome_comparable: false`. These results must
not be quoted as an ARTEX comparison or as evidence of equivalent capability.
ARTEX's public L3 benchmark at mirror commit
`a9c7a75a73e4aadbe0e75465eeafcd742db4930e` gives a running application to the
system, requires an independent LLM judge for its image mode, grades executed
proof, and can use DrostBench flag capture as an objective oracle. This
repository remains a static, read-only source review: it has no target
execution, flag-capture oracle, or paired ARTEX run.

The adapter deliberately carries over comparison discipline from that pinned
ARTEX contract: versioned ground truth, four gates weighted component 1 / class
2 / mechanism keywords 1 / proof 1, invalid-record exclusion, unmatched
findings as discovery candidates, a denominator and Wilson 95% interval for
each detection rate, conservative precision bounds while candidates await
disposition, and replication before aggregation. The local schema also adds
reviewed benign source locations, which ARTEX's vulnerable-only example does
not provide. Those locations make false positives and true negatives explicit,
so precision, recall, F1, and false-positive rate are derived from TP/FP/FN/TN
rather than from gate scores. Gate rates describe evidence quality only.

Pinned ARTEX references:

- [ARTEX benchmark README](https://github.com/BaaRai/ARTEX/blob/a9c7a75a73e4aadbe0e75465eeafcd742db4930e/scripts/benchmark/README.md): standing scoring rules,
  discovery candidates, replication warning, and image/Drost modalities.
- [ARTEX benchmark runner](https://github.com/BaaRai/ARTEX/blob/a9c7a75a73e4aadbe0e75465eeafcd742db4930e/scripts/benchmark/run_bench.py): gate weights, Wilson
  interval, invalid records, precision bounds, and version stamps.
- [ARTEX Juice Shop ground truth](https://github.com/BaaRai/ARTEX/blob/a9c7a75a73e4aadbe0e75465eeafcd742db4930e/scripts/benchmark/ground_truth/juice-shop.json):
  deliberately coarse component, class, and mechanism ground truth.

## Inputs and refusal states

Ground truth is a schema-version-3 object with a stable benchmark ID and
version, `modality: "static-source-review"`, a `public` or `synthetic` source,
an immutable `git:<40 lowercase hex>` or `sha256:<64 lowercase hex>` revision,
an exact source-artifact SHA-256, a safe local `artifact_path`, a source URI,
and a license. The adapter reads that regular file, rejects links, recomputes
its digest, and verifies that every case `location` identifies an existing,
nonblank line in those exact bytes. Lines are numbered by LF, as editors and
`file:line` references count them; a CRLF ending is not part of the line, and
a lone CR, form feed, NEL, or U+2028 inside a line does not start a new one.
Results sealed before this rule are unaffected unless their source contains one
of those characters; re-run `validate` for such sources rather than pooling
old and new results. The bundled fixture uses the single
committed `examples/detection-fixture-source.txt`; its `sha256:` revision is
the digest of that file, not a self-declared label. Each case has a `vulnerable`
or `benign` disposition, source `location`, component, class, mechanism, and
literal finding/source terms for all four evidence gates. A valid corpus
contains both dispositions. A public corpus may use one deterministic
concatenated source artifact or file manifest as the reviewed artifact; pin its
checkout by commit and record the manifest/artifact digest. Changing source
bytes, labels, locations, or gates requires a new ground-truth version. The
adapter never fetches the artifact.

The public ARTEX Juice Shop JSON is useful provenance but is not accepted
unchanged: it represents a black-box vulnerable-only corpus and lacks immutable
source-artifact identity, reviewed benign locations, and static gate
expectations. Convert and independently review it under this source schema;
silently treating it as source-review ground truth would weaken the modality
and identity boundary.

The findings input is a run envelope containing:

- a complete manifest with exact ground-truth SHA-256, benchmark identity,
  source revision, scanner/model/role identity, the source-review condition,
  duration/tokens/model calls, and `estimated_cost_usd`;
- the exact UTF-8 scanner-configuration and input-set bytes plus their
  recomputed SHA-256 digests. A content-derived execution/input fingerprint
  binds those bytes to the method, ground truth, source artifact, subject, and
  condition;
- the scanner's findings; a record without summary, report, impact, or request
  evidence is named as invalid and excluded. A title is only a display label:
  control characters and whitespace runs fold to single spaces, and it is cut
  to 200 characters;
- exactly one independent detection adjudication per vulnerable case, including
  all four gates, a reason, an exact excerpt from the matched finding, and an
  exact source line from the verified artifact (tabs included; other C0/C1
  controls, DEL, and U+2028/U+2029 cannot be quoted). A passed gate must contain all
  ground-truth finding/source terms; arbitrary booleans or unrelated excerpts
  are refused. The reason, gates, and structured evidence survive in the sealed
  result;
- exactly one evidence-backed benign adjudication per reviewed benign case.
  It is a true negative with no finding, or a false-positive location linked to
  one or more independently rejected findings. Every linked finding counts as
  an FP; this prevents two false alarms at one location from being undercounted.
  Findings cannot be reused across outcomes.

The confusion matrix is `TP=detected vulnerable`, `FN=missed vulnerable`,
`FP=each finding independently disproved at a reviewed benign location`, and
`TN=each reviewed benign location with no finding`. Point precision is `TP/(TP+FP)`,
recall is `TP/(TP+FN)`, F1 is `2TP/(2TP+FP+FN)`, and false-positive rate is
`FP/(FP+TN)`. Unmatched usable findings remain visible, non-scoring discovery
candidates. Structurally invalid findings are also non-scoring, but they and
candidates are included adversely in the lower precision bound; the upper
bound equals the evidence-backed point precision. This prevents malformed or
unsettled noise from improving the reported quality.

The command refuses malformed or duplicate JSON, mutable source identifiers,
absent/linked/mismatched source artifacts, nonexistent source locations,
configuration or input bytes whose digests do not match, identity mismatches,
incomplete runs, non-static modalities, missing cases, unknown/invalid/reused
matched findings, unrelated evidence, unsupported gate claims, missing or
unevidenced benign adjudications, inconsistent confusion metrics, and unsafe
input files before scoring. It emits a structured `status: refused` record to
stderr and exits 2. Outputs contain exact raw-input and bound-byte digests, the
execution/input fingerprint, a normalized substantive-observation fingerprint,
and a canonical payload seal. Aggregation refuses edited results, repeated run
IDs or envelopes, relabeled duplicate observations, mixed target/source/input
identity, or changed subject, scanner configuration, method, or source-review
condition.
Output paths are create-only so a rerun cannot silently replace evidence.

Distinct run IDs, envelope digests, and normalized observation fingerprints
prevent accidental or merely relabeled duplicate aggregation; they do not prove
operational independence. Operators remain responsible for
running security-scan separately under the recorded configuration and for
using an adjudicator that did not produce the findings. The bundled fixture
uses `fixture-oracle` explicitly and is only an executable format example.

## Reproducible fixture path

From the source repository root, choose a new evidence directory and run the
complete offline fixture in one command:

```sh
make detection-benchmark DETECTION_OUT="$PWD/detection-evidence/fixture-v3"
```

The target refuses an existing directory and retains `run-1.json`,
`run-2.json`, `run-3.json`, and `summary.json` at `DETECTION_OUT`; it never
deletes its only audit trail. Without an override the explicit default is
`${TMPDIR:-/tmp}/security-scan-detection-results`. Remove or archive an output
directory deliberately, or select a new versioned path for the next run.

The equivalent individual commands are:

```sh
work=$(mktemp -d "${TMPDIR:-/tmp}/security-scan-detection.XXXXXX")
python3 scripts/ci/benchmark_detection.py validate \
  --ground-truth examples/detection-ground-truth.sample.json \
  --findings examples/detection-run-1.sample.json --out "$work/run-1.json"
python3 scripts/ci/benchmark_detection.py validate \
  --ground-truth examples/detection-ground-truth.sample.json \
  --findings examples/detection-run-2.sample.json --out "$work/run-2.json"
python3 scripts/ci/benchmark_detection.py validate \
  --ground-truth examples/detection-ground-truth.sample.json \
  --findings examples/detection-run-3.sample.json --out "$work/run-3.json"
python3 scripts/ci/benchmark_detection.py summarize \
  --runs "$work/run-1.json" "$work/run-2.json" "$work/run-3.json" \
  --min-runs 3 --out "$work/summary.json"
python3 -m json.tool "$work/summary.json"
```

Each `--out` command writes sealed JSON and prints one concise human line with
TP/FP/FN/TN, all four point metrics, candidate/invalid counts, and the ARTEX
non-comparability label. The aggregate line reports pooled confusion-derived
metrics; JSON additionally retains mean, range, and sample standard deviation
across runs, candidate/invalid counts, gate observations, and total estimated
cost. A run with no true or false positive has undefined precision; it still
counts in the pooled totals, and each precision spread names it in
`undefined_runs` instead of refusing the summary, so the weakest run cannot be
left out to make the aggregate look better.
For real evidence, retain the sealed run results and summary under a new
versioned evidence directory, together with the immutable corpus checkout and
the independent adjudication record. Review discovery candidates separately;
only a later, recorded disposition can narrow their precision interval.

The bundled values are mechanism evidence for the schema and calculations,
not public-corpus accuracy or a security-scan capability claim. The direct
ARTEX-versus-security-scan measurement remains outside this local
boundary. It would require the same pinned local corpus, subject model and
resource cap for both systems, at least three runs of each, provider access,
local target containers, and independent adjudication. No such comparison was
performed here.
