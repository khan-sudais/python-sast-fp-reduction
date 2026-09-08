# V6 Final Results Summary

Model: qwen3.8-27b with medium reasoning.

Human ground truth contained 300 findings: 278 FALSE_POSITIVE, 13 TRUE_BUG, and 9 UNCERTAIN. The 9 human-UNCERTAIN findings were excluded from headline binary metrics, leaving 291 resolved cases per variant.

Independent human annotation agreement was 98.67% with Cohen's kappa = 0.904.

## Variant results

| Variant | Strict accuracy (95% CI) | FP reduction (95% CI) | Bug recall (95% CI) | Bug precision | Coverage | Abstentions |
|---|---:|---:|---:|---:|---:|---:|
| A | 83.85% [79.18, 87.63] | 86.33% [81.79, 89.88] | 30.77% [12.68, 57.63] | 21.05% | 91.75% | 24 |
| B | 87.29% [82.97, 90.63] | 90.29% [86.24, 93.24] | 23.08% [8.18, 50.26] | 20.00% | 93.81% | 18 |
| C | 87.63% [83.35, 90.93] | 90.65% [86.65, 93.54] | 23.08% [8.18, 50.26] | 23.08% | 93.81% | 18 |

## Interpretation

Variant C had the highest observed strict accuracy, while Variant C had the highest observed false-positive reduction. Variant A retained the largest share of human-confirmed true bugs.

No pairwise comparison was statistically significant after Holm correction at alpha = 0.05. Therefore, the observed improvements from additional context should be described as numerical trends rather than statistically established superiority.

The false-positive reduction rates were high for all three variants, but true-bug recall was low and based on only 13 human-confirmed bugs. This trade-off is a central result and should be reported prominently rather than presenting false-positive reduction alone.

Variant C is a same_file_caller_expansion_only strategy, not cross-module taint analysis.

## LLM usage

Input tokens: 693,767
Output tokens: 946,086
Reasoning tokens: 735,024
Total tokens: 1,639,853
