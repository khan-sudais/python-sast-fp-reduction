# MANUSCRIPT V6 — Draft

## Title

**Evaluating Context Slicing for LLM-Assisted False-Positive Reduction in Python Static Security Analysis**

## Abstract

Static application security testing can produce many alerts that require manual review. This study evaluates whether progressively richer code context improves Large Language Model classification of Python SAST findings while preserving true security defects. A frozen corpus of 100 real Python repositories was scanned with Bandit 1.9.4 and Semgrep CE 1.176.1 using a shared deterministic production-file manifest and frozen study-defined rules. The scan produced 2,268 raw scanner observations that were canonicalized into 1,302 source-statement/security-family findings. A proportional CWE-stratified sample of 300 canonical findings was independently annotated by two humans. Pre-adjudication agreement was 98.67% with Cohen's kappa of 0.904; after adjudication, the sample contained 278 FALSE_POSITIVE, 13 TRUE_BUG, and 9 UNCERTAIN findings.

Each sampled finding was evaluated with Qwen3.8-27B under three blinded context conditions: Variant A, isolated local context; Variant B, an intra-procedural dependency/control slice; and Variant C, Variant B augmented with same-file caller expansion to depth three. The official experiment contained 900 model requests. Human-UNCERTAIN findings were excluded from headline binary metrics, leaving 291 resolved cases per variant, while model UNCERTAIN predictions were treated as abstentions. Strict accuracy was 83.85% for A, 87.29% for B, and 87.63% for C. False-positive reduction was 86.33%, 90.29%, and 90.65%, respectively. However, true-bug recall was only 30.77% for A and 23.08% for both B and C. No pairwise comparison was statistically significant after Holm correction. These results suggest that additional context may improve false-positive suppression numerically, but the observed gains were not statistically established and were accompanied by low true-bug retention. The study therefore highlights a central safety trade-off: aggressive false-positive reduction can remove reviewer burden while also risking suppression of genuine security defects.

## 1. Introduction

Static application security testing is widely used to identify potentially dangerous code patterns before deployment. In practice, scanner output is not equivalent to confirmed vulnerability evidence. A scanner can flag a syntactically suspicious operation even when surrounding program logic makes the operation benign, constrained, unreachable, or otherwise non-exploitable. Manual triage is therefore often required.

Large Language Models offer a possible second-stage triage mechanism because they can reason over source context rather than only matching a local syntactic pattern. The amount and structure of context supplied to the model may substantially influence the classification. Too little context can omit guards, sanitization, or data dependencies. Too much context may increase cost and introduce irrelevant information.

This study evaluates three context-construction strategies for LLM-assisted triage of Python SAST findings. The goal is not to replace security analyzers and not to claim that scanner alerts are vulnerabilities. Instead, the study asks whether increasingly structured context changes the model's ability to distinguish human-confirmed false positives from human-confirmed true bugs.

The authoritative V6 study corrects earlier prototype and synthetic artifacts by using real repository snapshots, official Bandit and Semgrep executions, a shared scanner scope, independently annotated human ground truth, frozen LLM prompts, preserved raw model responses, and paired statistical evaluation.

## 2. Study Objective

The study compares three context variants for the same set of SAST findings:

- **Variant A:** isolated local code around the flagged statement.
- **Variant B:** an intra-procedural AST dependency/control slice.
- **Variant C:** Variant B plus same-file caller expansion to a maximum depth of three.

The primary empirical question is whether richer context improves false-positive suppression and overall classification quality without materially reducing retention of human-confirmed true bugs.

Because the same 300 findings are evaluated under all three variants, the design is paired.

## 3. Corpus and Repository Freezing

The V6 corpus contains 100 real Python repositories. Every repository is frozen at an exact commit SHA. The scanner requested all 100 repositories and successfully processed all 100.

The final V6 scope contained:

- 10,516 candidate Python files.
- 10,512 files comparable across both scanners after mapped parser incompatibilities.
- 2,268 raw scanner observations.
- 1,302 canonical findings.
- 966 cross-scanner duplicate observations merged during canonicalization.

The gRPC repository is a monorepo and is scoped specifically to `src/python`. Other repositories use the frozen scope defined in the V6 corpus manifest.

Mapped parser incompatibilities are retained in the corpus audit rather than silently removed. No scanner alerts occurred in the non-comparable parser-incompatible files, and the coverage audit completed successfully.

## 4. Scanner Protocol

### 4.1 Bandit

Bandit version 1.9.4 was used with the following frozen tests:

B102, B108, B301, B307, B324, B501, B602, B603, and B608.

### 4.2 Semgrep

Semgrep CE version 1.176.1 was used with frozen local study-defined rules rather than registry or automatic rulesets. The rule families cover exec, eval, hard-coded temporary paths, unsafe deserialization, weak hashes, disabled certificate validation, shell execution, subprocess execution, and dynamic SQL. The weak-hash rule excludes calls that explicitly use `usedforsecurity=False`.

### 4.3 Shared scan scope

Both scanners operate over the same deterministic Python file manifest. Only `.py` files are included. The production-file policy excludes directories named:

`tests`, `test`, `testing`, `docs`, `doc`, `examples`, `example`, `benchmarks`, `benchmark`, `.venv`, `venv`, `build`, and `dist`.

Raw scanner observations are preserved. Scanner observations are then canonicalized by source statement and security family. The annotation sampling unit is the canonical finding, not an individual scanner alert.

## 5. Ground-Truth Construction

A sample of 300 canonical findings was selected using proportional CWE-stratified sampling with a fixed seed.

Two human annotators independently reviewed every sampled finding. Before adjudication, the annotators agreed on 296 of 300 findings, corresponding to 98.67% raw agreement. Cohen's kappa was 0.904. Four disagreements were jointly adjudicated.

The final ground-truth distribution was:

- 278 FALSE_POSITIVE.
- 13 TRUE_BUG.
- 9 UNCERTAIN.

The nine human-UNCERTAIN findings are retained as part of the annotated dataset but excluded from headline binary performance metrics. Therefore, the primary binary evaluation contains 291 resolved findings for each context variant.

The sample should not be interpreted as an exact estimate of vulnerability prevalence over all 1,302 canonical findings.

## 6. Context Construction

### 6.1 Variant A: Isolated local context

Variant A supplies the flagged statement together with approximately three surrounding lines on each side. It represents a low-cost local-context baseline.

### 6.2 Variant B: Intra-procedural slice

Variant B constructs an AST-based slice within the enclosing function. It attempts to preserve data dependencies and relevant control context connected to the flagged operation.

Seventeen sampled findings required documented Variant B fallback behavior because a standard intra-procedural target slice could not be produced.

### 6.3 Variant C: Same-file caller expansion

Variant C begins with Variant B and augments it with callers identified in the same Python source file. Caller expansion uses breadth-first traversal to a maximum depth of three.

Variant C must not be described as cross-module interprocedural taint analysis. The implemented scope is same-file caller expansion only.

In the V6 slicing audit, 158 sampled findings had at least one caller added by Variant C and 142 had no caller expansion.

## 7. LLM Evaluation Protocol

The official LLM experiment used Alibaba Cloud Model Studio (Bailian), region `cn-beijing`, with model `qwen3.8-27b` and medium reasoning effort.

The model received no tools and no web access. Ground-truth labels, scanner identity, scanner rule identity, severity, and confidence were blinded. Slice truncation was disabled.

The model was required to output exactly one of three labels:

- TRUE_BUG
- FALSE_POSITIVE
- UNCERTAIN

The system instruction required decisions to be based only on supplied code context.

The final experiment contained 900 requests:

300 findings × 3 variants.

All 900 requests completed successfully. The raw results preserve request payloads, raw responses, response identifiers, returned model identifiers, token usage, and timestamps. Seventeen non-success attempt records were also retained as retry evidence.

Total model usage was:

- 693,767 input tokens.
- 2,432 cached input tokens.
- 946,086 output tokens.
- 735,024 reasoning tokens.
- 1,639,853 total tokens.

## 8. Evaluation Metrics

The positive class is TRUE_BUG and the negative class is FALSE_POSITIVE.

Human-UNCERTAIN findings are excluded from headline binary metrics.

A model UNCERTAIN prediction is treated as an abstention. For strict accuracy, an abstention counts as not correct. Selective metrics can additionally be computed over non-abstained predictions.

The main reported metrics are:

- Strict accuracy.
- Coverage.
- Explicit TRUE_BUG precision.
- Strict true-bug recall.
- False-positive reduction rate.
- False-alarm rate.
- F1 score.

Ninety-five percent confidence intervals for proportions use Wilson score intervals.

Because the same findings are evaluated under all variants, pairwise comparisons use exact McNemar tests on discordant paired outcomes. Holm correction is applied within each endpoint across the A-B, A-C, and B-C comparisons.

## 9. Results

### 9.1 Main performance

| Variant | Strict accuracy | FP reduction | True-bug recall | Bug precision | Coverage |
|---|---:|---:|---:|---:|---:|
| A | 83.85% | 86.33% | 30.77% | 21.05% | 91.75% |
| B | 87.29% | 90.29% | 23.08% | 20.00% | 93.81% |
| C | 87.63% | 90.65% | 23.08% | 23.08% | 93.81% |

Variant C achieved the highest observed strict accuracy, at 87.63%, with a 95% Wilson confidence interval of 83.35% to 90.93%. Variant B achieved 87.29% and Variant A achieved 83.85%.

Variant C also achieved the highest observed false-positive reduction, at 90.65%, followed by Variant B at 90.29% and Variant A at 86.33%.

The direction reversed for true-bug retention. Variant A correctly retained 4 of 13 human-confirmed bugs, for strict recall of 30.77%. Variants B and C each retained 3 of 13, for recall of 23.08%.

### 9.2 Confusion counts and abstention

For Variant A, the strict resolved-case counts were TP=4, TN=240, FP=15, and FN=8, with 24 abstentions.

For Variant B, the counts were TP=3, TN=251, FP=12, and FN=7, with 18 abstentions.

For Variant C, the counts were TP=3, TN=252, FP=10, and FN=8, with 18 abstentions.

The low number of human-confirmed true bugs produces wide confidence intervals for true-bug recall. The recall estimate should therefore be interpreted cautiously.

### 9.3 Paired statistical comparisons

No pairwise A/B/C comparison reached statistical significance after Holm correction at alpha = 0.05.

For strict overall correctness:

- A vs B: exact p = 0.1325; Holm-adjusted p = 0.3244.
- A vs C: exact p = 0.1081; Holm-adjusted p = 0.3244.
- B vs C: exact p = 1.0000; Holm-adjusted p = 1.0000.

For false-positive suppression:

- A vs B: exact p = 0.0801; Holm-adjusted p = 0.1957.
- A vs C: exact p = 0.0652; Holm-adjusted p = 0.1957.
- B vs C: exact p = 1.0000; Holm-adjusted p = 1.0000.

True-bug retention comparisons were also non-significant.

Consequently, Variant C's higher observed accuracy and false-positive reduction should be described as numerical trends rather than statistically established superiority.

## 10. Discussion

The results show that larger structured context is not uniformly beneficial.

Moving from Variant A to B and C increased observed strict accuracy by roughly 3.4 to 3.8 percentage points and increased observed false-positive suppression by roughly 4 percentage points. These improvements are consistent with the hypothesis that additional intra-procedural and caller context can help the model recognize benign conditions surrounding a scanner warning.

However, the same richer variants did not improve true-bug recall. Variant A retained one more confirmed bug than B or C. This matters because a false-positive reduction layer sits downstream of a security scanner: incorrectly suppressing a genuine defect can be more consequential than leaving an extra warning for human review.

The strongest empirical conclusion is therefore not that Variant C is the best method. Instead, the study identifies a trade-off. Richer context produced better observed suppression of false positives, but true-bug retention remained low across all variants, and the differences between variants were not statistically significant.

For deployment, an LLM filter with these observed recall levels should not be used as an autonomous vulnerability-removal gate. A safer role would be prioritization, explanation, or review assistance while retaining access to the original scanner evidence.

## 11. Threats to Validity

### 11.1 Ground-truth class imbalance

Only 13 of the 300 annotated findings were human-confirmed true bugs. As a result, true-bug recall estimates have wide confidence intervals and limited statistical power.

### 11.2 Sample-based evaluation

The 300 annotated findings are a proportional CWE-stratified sample from 1,302 canonical findings. Results characterize the evaluated sample and should not be presented as exact whole-population vulnerability prevalence.

### 11.3 Scanner scope and rules

The conclusions depend on the frozen Bandit tests, frozen local Semgrep rules, production-directory exclusion policy, and canonicalization scheme. Different scanners or rulesets may produce different finding distributions.

### 11.4 Model dependence

The LLM evaluation uses one model configuration: Qwen3.8-27B with medium reasoning. Results do not establish that other models will behave similarly.

### 11.5 Context implementation

Variant C is limited to same-file caller expansion. It does not trace callers across modules and is not a full interprocedural taint-analysis system.

### 11.6 Repository snapshot dependence

The corpus is frozen at exact commit SHAs. The results are reproducible against those snapshots but may not represent later repository versions.

## 12. Reproducibility

The repository preserves:

- Frozen repository manifests and commit SHAs.
- Frozen scanner configuration and hashes.
- Raw and canonical scanner evidence.
- Sampling metadata.
- Independent annotation files and adjudication records.
- Slicing audit outputs.
- Frozen LLM protocol and request manifest.
- Raw model responses and retry evidence.
- Frozen final prediction tables.
- Evaluation scripts.
- Final tables and figures.

The primary V6 artifacts are located under:

- `config/`
- `data/annotation_v6/`
- `data/slicing_v6/`
- `data/llm_v6/`
- `data/evaluation_v6/`
- `results_v6/`

Earlier pilot artifacts and the historical 362, 909, and 1029 counts are retained only for provenance and are not authoritative V6 results.

## 13. Conclusion

This study evaluated three code-context strategies for LLM-assisted triage of Python static security findings. Variant C produced the highest observed strict accuracy and false-positive reduction, but the improvement was not statistically significant. More importantly, all variants retained only a minority of the human-confirmed true bugs, with Variant A achieving the highest observed true-bug recall.

The results support a cautious interpretation of LLM-based false-positive reduction. Context slicing can help an LLM suppress many warnings that humans classify as false positives, but false-positive reduction alone is not a sufficient safety metric. Any practical system must evaluate and protect true-bug retention, preserve abstention behavior, and maintain access to original scanner evidence.

## 14. Related Work and References

This draft intentionally does not invent literature citations. Add the final verified related-work sources and bibliography before journal or conference submission.
