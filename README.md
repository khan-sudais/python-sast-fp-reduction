# Python SAST False-Positive Reduction with LLM Context Slicing

An empirical replication package for evaluating whether different code-context slices help a Large Language Model reduce false positives from Python static application security testing (SAST).

The authoritative study version is **V6**. It uses **Bandit 1.9.4**, **Semgrep CE 1.176.1 with frozen study-defined local rules**, and **Qwen3.8-27B** through Alibaba Cloud Model Studio (Bailian).

## Study design

The V6 pipeline has four stages:

1. Freeze a curated set of 100 real Python repositories at exact commits.
2. Run Bandit and Semgrep over a shared deterministic production-file manifest.
3. Canonicalize scanner observations into source-statement/security-family findings and sample 300 findings for independent human annotation.
4. Evaluate the same 300 findings with three context variants using a blinded Qwen3.8-27B classification protocol.

Scanner output is treated as **alerts/findings, not confirmed vulnerabilities**.

## Frozen V6 corpus

- 100 requested repositories
- 100 successfully scanned
- 10,516 candidate Python files
- 10,512 files comparable across both scanners after mapped parser incompatibilities
- 2,268 raw scanner observations
- 1,302 canonical findings
- 966 duplicate cross-scanner observations merged during canonicalization
- 0 alerts/findings in non-comparable parser-incompatible files
- Coverage audit complete

The gRPC monorepo is intentionally scoped to `src/python`; other repositories use the frozen scope recorded in the V6 manifest.

## Scanner protocol

The scanner protocol is frozen in `config/scanner_protocol.json`.

### Bandit

Version: **1.9.4**

Tests:

- B102
- B108
- B301
- B307
- B324
- B501
- B602
- B603
- B608

### Semgrep

Version: **1.176.1**

The experiment uses the frozen local rules in `config/semgrep-python-security.yml`, not Semgrep registry/auto configuration.

Rule families include:

- exec
- eval
- hard-coded temporary paths
- unsafe deserialization
- weak hashes
- disabled certificate validation
- shell execution
- subprocess execution
- dynamic SQL

The weak-hash rule excludes calls explicitly using `usedforsecurity=False`.

### Production-file scope

Only `.py` files are scanned. The shared target manifest excludes:

`tests`, `test`, `testing`, `docs`, `doc`, `examples`, `example`, `benchmarks`, `benchmark`, `.venv`, `venv`, `build`, and `dist`.

The canonical finding unit is:

`canonical_source_statement_plus_security_family`

Raw scanner evidence is retained separately from canonical findings.

## Human ground truth

A proportional CWE-stratified sample of **300 canonical findings** was independently annotated by two humans and then adjudicated where necessary.

Final labels:

- FALSE_POSITIVE: **278**
- TRUE_BUG: **13**
- UNCERTAIN: **9**

Pre-adjudication agreement:

- Agreement: **296/300 = 98.67%**
- Cohen's kappa: **0.904**
- Disagreements adjudicated: **4**

The 9 final human-UNCERTAIN findings are excluded from headline binary performance metrics and reported separately.

Ground-truth artifacts are under `data/annotation_v6/`.

## Context variants

### Variant A — isolated local context

The flagged source statement with approximately ±3 surrounding lines.

### Variant B — intra-procedural dependency/control slice

An AST-based slice within the enclosing function that traces relevant local dependencies and control context.

There are **17 documented Variant B fallbacks** when a normal intra-procedural slice cannot be constructed.

### Variant C — same-file caller expansion

Variant B context expanded with callers found in the **same Python file**, using breadth-first caller expansion to a maximum depth of 3.

Variant C is **not cross-module interprocedural analysis** and **not a true taint-analysis implementation**. Manuscript text and result interpretation should use the term **same-file caller expansion**.

Slicing audit artifacts are under `data/slicing_v6/`.

## LLM protocol

The frozen LLM protocol is `config/llm_protocol_v6.json`.

- Provider: Alibaba Cloud Model Studio / Bailian
- Region: cn-beijing
- Model: **qwen3.8-27b**
- Reasoning effort: **medium**
- API: OpenAI-compatible Responses API
- Client: Python standard-library `urllib`
- External SDK required: no
- Tools: disabled
- Web search: disabled
- Max output tokens: 4096
- Slice truncation: none
- Request-order seed: 42
- Ground-truth labels: blinded
- Scanner identity/rule/severity/confidence: blinded

The model could return only:

- TRUE_BUG
- FALSE_POSITIVE
- UNCERTAIN

The official experiment contained **900 requests = 300 findings × 3 variants**.

All 900 requests completed successfully. The raw run retained 17 non-success attempt records associated with retries, while the frozen prediction table contains exactly one successful prediction for every request.

Token usage:

- Input: **693,767**
- Cached input: **2,432**
- Output: **946,086**
- Reasoning: **735,024**
- Total: **1,639,853**

Frozen LLM artifacts are under `data/llm_v6/`.

## Final V6 results

Headline binary metrics use the **291 human-resolved findings**. A model `UNCERTAIN` prediction is treated as an abstention.

| Variant | Strict accuracy | FP reduction | True-bug recall | Bug precision | Coverage |
|---|---:|---:|---:|---:|---:|
| A | 83.85% | 86.33% | **30.77%** | 21.05% | 91.75% |
| B | 87.29% | 90.29% | 23.08% | 20.00% | 93.81% |
| C | **87.63%** | **90.65%** | 23.08% | **23.08%** | 93.81% |

Observed strict-accuracy 95% Wilson confidence intervals:

- A: 79.18%–87.63%
- B: 82.97%–90.63%
- C: 83.35%–90.93%

Observed false-positive-reduction 95% Wilson confidence intervals:

- A: 81.79%–89.88%
- B: 86.24%–93.24%
- C: 86.65%–93.54%

Observed true-bug-recall 95% Wilson confidence intervals:

- A: 12.68%–57.63%
- B: 8.18%–50.26%
- C: 8.18%–50.26%

Variant C had the highest observed strict accuracy and false-positive reduction, while Variant A retained the largest share of human-confirmed true bugs.

**No A/B/C pairwise comparison was statistically significant after Holm correction at α = 0.05.** The numerical differences therefore should not be described as statistically established superiority.

A central finding is the trade-off between strong false-positive suppression and low true-bug retention. The result should not be summarized using false-positive reduction alone.

Final tables, figures, and result summaries are under `results_v6/`.

## Repository structure

```text
config/
  bandit.yaml
  corpus_protocol_v6.json
  coverage_protocol.json
  llm_protocol_v6.json
  scanner_protocol.json
  semgrep-python-security.yml

data/
  annotation_v6/
  evaluation_v6/
  llm_v6/
  slicing_v6/
  curated_100_repositories_scoped_v6.csv
  frozen_100_repository_snapshot_v6.csv
  ground_truth_annotation_sample_v6.csv
  LEGACY_PROVENANCE.md

results_v6/
  figure_fp_reduction_vs_bug_recall_v6.png
  figure_variant_metrics_v6.png
  results_summary_v6.json
  results_summary_v6.md
  table_main_results_v6.csv
  table_pairwise_mcnemar_v6.csv

src/
  ast_slicer.py
  scoped_frozen_repository_scanner.py
  build_llm_experiment_manifest_v6.py
  run_llm_experiment_v6.py
  validate_and_freeze_qwen_v6.py
  evaluate_qwen_v6.py
  build_results_artifacts_v6.py
  ...

MANUSCRIPT_V6.md
README.md
requirements.txt
```

## Reproducing the analysis

Install the frozen scanner versions and analysis dependencies:

```powershell
py -m pip install -r requirements.txt
```

Compile the research scripts:

```powershell
py -m compileall src
```

For an already completed V6 run, validate and regenerate downstream analysis from the frozen evidence:

```powershell
py src\validate_and_freeze_qwen_v6.py
py src\evaluate_qwen_v6.py
py src\build_results_artifacts_v6.py
```

The full corpus scan and LLM invocation stages depend on network access, frozen external repository commits, scanner executables, and a valid Bailian API key. The LLM runner reads the key from:

```text
DASHSCOPE_API_KEY
```

Do not commit API keys.

## Legacy artifacts

Earlier pilot/main-study files and the historical 362/909/1029 counts are retained only for provenance. They are **not authoritative V6 results** and must not be reused as repaired study outcomes.

See:

`data/LEGACY_PROVENANCE.md`

## Interpretation boundary

This repository evaluates a false-positive-reduction/classification workflow on the frozen V6 sample. It does not establish that scanner alerts are vulnerabilities, does not estimate exact whole-population vulnerability prevalence from the 300-item annotation sample, and does not demonstrate statistically significant superiority of Variant C over the other context variants.
