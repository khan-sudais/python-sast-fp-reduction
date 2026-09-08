import csv
import json
from pathlib import Path

import matplotlib.pyplot as plt


PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVAL_JSON = PROJECT_ROOT / "data" / "evaluation_v6" / "qwen_evaluation_v6.json"
AGREEMENT_JSON = PROJECT_ROOT / "data" / "annotation_v6" / "annotation_agreement_v6.json"
PRED_META = PROJECT_ROOT / "data" / "llm_v6" / "final_qwen_predictions_v6_metadata.json"
SLICING_AUDIT = PROJECT_ROOT / "data" / "slicing_v6" / "slicing_audit_v6.json"
OUTPUT_DIR = PROJECT_ROOT / "results_v6"
MAIN_TABLE = OUTPUT_DIR / "table_main_results_v6.csv"
MCNEMAR_TABLE = OUTPUT_DIR / "table_pairwise_mcnemar_v6.csv"
SUMMARY_JSON = OUTPUT_DIR / "results_summary_v6.json"
SUMMARY_MD = OUTPUT_DIR / "results_summary_v6.md"
FIG_METRICS = OUTPUT_DIR / "figure_variant_metrics_v6.png"
FIG_TRADEOFF = OUTPUT_DIR / "figure_fp_reduction_vs_bug_recall_v6.png"


def pct(value):
    return 100.0 * value


def ci_text(metric):
    return (
        f"{pct(metric['value']):.2f}% "
        f"[{pct(metric['ci95_low']):.2f}, "
        f"{pct(metric['ci95_high']):.2f}]"
    )


def main():
    for path in [
        EVAL_JSON,
        AGREEMENT_JSON,
        PRED_META,
        SLICING_AUDIT,
    ]:
        if not path.exists():
            raise FileNotFoundError(
                f"Required file not found: {path}"
            )

    evaluation = json.loads(
        EVAL_JSON.read_text(encoding="utf-8")
    )
    agreement = json.loads(
        AGREEMENT_JSON.read_text(encoding="utf-8")
    )
    prediction_meta = json.loads(
        PRED_META.read_text(encoding="utf-8")
    )
    slicing = json.loads(
        SLICING_AUDIT.read_text(encoding="utf-8")
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    variants = ["A", "B", "C"]
    metrics = evaluation["variant_metrics"]

    main_rows = []

    for variant in variants:
        item = metrics[variant]
        main_rows.append(
            {
                "variant": variant,
                "tp": item["tp"],
                "tn": item["tn"],
                "fp": item["fp"],
                "fn": item["fn"],
                "abstain_total": item["abstain_total"],
                "strict_accuracy": item["strict_accuracy"]["value"],
                "strict_accuracy_ci95_low": item["strict_accuracy"]["ci95_low"],
                "strict_accuracy_ci95_high": item["strict_accuracy"]["ci95_high"],
                "coverage": item["coverage"]["value"],
                "bug_precision_explicit": item["bug_precision_explicit"]["value"],
                "bug_recall_strict": item["bug_recall_strict"]["value"],
                "bug_recall_ci95_low": item["bug_recall_strict"]["ci95_low"],
                "bug_recall_ci95_high": item["bug_recall_strict"]["ci95_high"],
                "false_positive_reduction_rate": item[
                    "false_positive_reduction_rate"
                ]["value"],
                "fp_reduction_ci95_low": item[
                    "false_positive_reduction_rate"
                ]["ci95_low"],
                "fp_reduction_ci95_high": item[
                    "false_positive_reduction_rate"
                ]["ci95_high"],
                "f1_strict": item["f1_strict"]["value"],
            }
        )

    with MAIN_TABLE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(main_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(main_rows)

    mcnemar_rows = evaluation["pairwise_mcnemar"]

    with MCNEMAR_TABLE.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(mcnemar_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(mcnemar_rows)

    best_accuracy = max(
        variants,
        key=lambda variant: metrics[variant][
            "strict_accuracy"
        ]["value"],
    )
    best_fp_reduction = max(
        variants,
        key=lambda variant: metrics[variant][
            "false_positive_reduction_rate"
        ]["value"],
    )
    best_bug_recall = max(
        variants,
        key=lambda variant: metrics[variant][
            "bug_recall_strict"
        ]["value"],
    )

    significant_pairwise = [
        row
        for row in mcnemar_rows
        if row["p_value_holm_within_endpoint"] < 0.05
    ]

    summary = {
        "study_version": "v6",
        "model": evaluation["model"],
        "reasoning_effort": evaluation["reasoning_effort"],
        "ground_truth": {
            "sample_size": 300,
            "false_positive": 278,
            "true_bug": 13,
            "uncertain": 9,
            "resolved_binary_cases": 291,
            "raw_agreement": agreement["raw_agreement"],
            "cohen_kappa": agreement["cohen_kappa"],
            "disagreements": agreement["disagreement_count"],
        },
        "slicing": {
            "variant_b_fallback_count": slicing[
                "variant_b_fallback_count"
            ],
            "variant_c_with_callers_count": slicing[
                "variant_c_with_callers_count"
            ],
            "variant_c_zero_callers_count": slicing[
                "variant_c_zero_callers_count"
            ],
            "variant_c_scope": slicing["variant_c_scope"],
        },
        "llm_usage": prediction_meta["usage_totals"],
        "best_observed_strict_accuracy_variant": best_accuracy,
        "best_observed_fp_reduction_variant": best_fp_reduction,
        "best_observed_bug_recall_variant": best_bug_recall,
        "significant_pairwise_tests_after_holm": significant_pairwise,
        "variant_metrics": {
            variant: {
                "strict_accuracy": metrics[variant][
                    "strict_accuracy"
                ],
                "coverage": metrics[variant]["coverage"],
                "bug_precision_explicit": metrics[variant][
                    "bug_precision_explicit"
                ],
                "bug_recall_strict": metrics[variant][
                    "bug_recall_strict"
                ],
                "false_positive_reduction_rate": metrics[
                    variant
                ]["false_positive_reduction_rate"],
                "f1_strict": metrics[variant]["f1_strict"],
            }
            for variant in variants
        },
    }

    SUMMARY_JSON.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
        newline="\n",
    )

    lines = [
        "# V6 Final Results Summary",
        "",
        f"Model: {evaluation['model']} with {evaluation['reasoning_effort']} reasoning.",
        "",
        "Human ground truth contained 300 findings: 278 FALSE_POSITIVE, 13 TRUE_BUG, and 9 UNCERTAIN. The 9 human-UNCERTAIN findings were excluded from headline binary metrics, leaving 291 resolved cases per variant.",
        "",
        f"Independent human annotation agreement was {pct(agreement['raw_agreement']):.2f}% with Cohen's kappa = {agreement['cohen_kappa']:.3f}.",
        "",
        "## Variant results",
        "",
        "| Variant | Strict accuracy (95% CI) | FP reduction (95% CI) | Bug recall (95% CI) | Bug precision | Coverage | Abstentions |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]

    for variant in variants:
        item = metrics[variant]
        lines.append(
            f"| {variant} | "
            f"{ci_text(item['strict_accuracy'])} | "
            f"{ci_text(item['false_positive_reduction_rate'])} | "
            f"{ci_text(item['bug_recall_strict'])} | "
            f"{pct(item['bug_precision_explicit']['value']):.2f}% | "
            f"{pct(item['coverage']['value']):.2f}% | "
            f"{item['abstain_total']} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            f"Variant {best_accuracy} had the highest observed strict accuracy, while Variant {best_fp_reduction} had the highest observed false-positive reduction. Variant {best_bug_recall} retained the largest share of human-confirmed true bugs.",
            "",
            "No pairwise comparison was statistically significant after Holm correction at alpha = 0.05. Therefore, the observed improvements from additional context should be described as numerical trends rather than statistically established superiority.",
            "",
            "The false-positive reduction rates were high for all three variants, but true-bug recall was low and based on only 13 human-confirmed bugs. This trade-off is a central result and should be reported prominently rather than presenting false-positive reduction alone.",
            "",
            f"Variant C is a {slicing['variant_c_scope']} strategy, not cross-module taint analysis.",
            "",
            "## LLM usage",
            "",
            f"Input tokens: {prediction_meta['usage_totals']['input_tokens']:,}",
            f"Output tokens: {prediction_meta['usage_totals']['output_tokens']:,}",
            f"Reasoning tokens: {prediction_meta['usage_totals']['reasoning_tokens']:,}",
            f"Total tokens: {prediction_meta['usage_totals']['total_tokens']:,}",
            "",
        ]
    )

    SUMMARY_MD.write_text(
        "\n".join(lines),
        encoding="utf-8",
        newline="\n",
    )

    accuracy_values = [
        pct(metrics[variant]["strict_accuracy"]["value"])
        for variant in variants
    ]
    fp_values = [
        pct(
            metrics[variant][
                "false_positive_reduction_rate"
            ]["value"]
        )
        for variant in variants
    ]
    recall_values = [
        pct(metrics[variant]["bug_recall_strict"]["value"])
        for variant in variants
    ]

    x = list(range(len(variants)))
    width = 0.24

    plt.figure(figsize=(8, 5))
    plt.bar(
        [value - width for value in x],
        accuracy_values,
        width=width,
        label="Strict accuracy",
    )
    plt.bar(
        x,
        fp_values,
        width=width,
        label="FP reduction",
    )
    plt.bar(
        [value + width for value in x],
        recall_values,
        width=width,
        label="Bug recall",
    )
    plt.xticks(x, variants)
    plt.ylabel("Percent")
    plt.xlabel("Context variant")
    plt.ylim(0, 100)
    plt.legend()
    plt.tight_layout()
    plt.savefig(
        FIG_METRICS,
        dpi=300,
        bbox_inches="tight",
    )
    plt.close()

    plt.figure(figsize=(6, 5))

    for variant in variants:
        x_value = pct(
            metrics[variant][
                "false_positive_reduction_rate"
            ]["value"]
        )
        y_value = pct(
            metrics[variant][
                "bug_recall_strict"
            ]["value"]
        )
        plt.scatter(
            [x_value],
            [y_value],
            s=80,
        )
        plt.annotate(
            variant,
            (x_value, y_value),
            xytext=(5, 5),
            textcoords="offset points",
        )

    plt.xlabel("False-positive reduction (%)")
    plt.ylabel("True-bug recall (%)")
    plt.xlim(80, 95)
    plt.ylim(0, 40)
    plt.tight_layout()
    plt.savefig(
        FIG_TRADEOFF,
        dpi=300,
        bbox_inches="tight",
    )
    plt.close()

    print(
        json.dumps(
            {
                "best_observed_strict_accuracy_variant": best_accuracy,
                "best_observed_fp_reduction_variant": best_fp_reduction,
                "best_observed_bug_recall_variant": best_bug_recall,
                "significant_pairwise_tests_after_holm": len(
                    significant_pairwise
                ),
                "outputs": {
                    "main_table": str(MAIN_TABLE),
                    "mcnemar_table": str(MCNEMAR_TABLE),
                    "summary_json": str(SUMMARY_JSON),
                    "summary_markdown": str(SUMMARY_MD),
                    "metrics_figure": str(FIG_METRICS),
                    "tradeoff_figure": str(FIG_TRADEOFF),
                },
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
