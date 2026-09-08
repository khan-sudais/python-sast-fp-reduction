import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path
from statistics import NormalDist

from scipy.stats import binomtest


PROJECT_ROOT = Path(__file__).resolve().parent.parent
GT_CSV = PROJECT_ROOT / "data" / "annotation_v6" / "final_ground_truth_v6.csv"
GT_META = PROJECT_ROOT / "data" / "annotation_v6" / "final_ground_truth_v6_metadata.json"
PRED_CSV = PROJECT_ROOT / "data" / "llm_v6" / "final_qwen_predictions_v6.csv"
PRED_META = PROJECT_ROOT / "data" / "llm_v6" / "final_qwen_predictions_v6_metadata.json"
OUTPUT_DIR = PROJECT_ROOT / "data" / "evaluation_v6"
SCORED_CSV = OUTPUT_DIR / "qwen_predictions_scored_v6.csv"
METRICS_CSV = OUTPUT_DIR / "qwen_variant_metrics_v6.csv"
MCNEMAR_CSV = OUTPUT_DIR / "qwen_pairwise_mcnemar_v6.csv"
SUMMARY_JSON = OUTPUT_DIR / "qwen_evaluation_v6.json"
ALLOWED = {"TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"}
VARIANTS = ["A", "B", "C"]


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def relative_path(path):
    return path.relative_to(PROJECT_ROOT).as_posix()


def canonical_text_sha256(path):
    text = path.read_text(encoding="utf-8")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def safe_div(numerator, denominator):
    if denominator == 0:
        return None
    return numerator / denominator


def wilson_interval(successes, total, confidence=0.95):
    if total == 0:
        return [None, None]

    z = NormalDist().inv_cdf(0.5 + confidence / 2)
    p = successes / total
    z2 = z * z
    denominator = 1 + z2 / total
    center = (p + z2 / (2 * total)) / denominator
    half = (
        z
        * math.sqrt(
            (p * (1 - p) / total)
            + (z2 / (4 * total * total))
        )
        / denominator
    )
    return [max(0.0, center - half), min(1.0, center + half)]


def metric_entry(value, successes=None, total=None):
    entry = {"value": value}
    if successes is not None and total is not None:
        low, high = wilson_interval(successes, total)
        entry["ci95_low"] = low
        entry["ci95_high"] = high
        entry["numerator"] = successes
        entry["denominator"] = total
    return entry


def holm_adjust(rows):
    ordered = sorted(
        enumerate(rows),
        key=lambda item: item[1]["p_value_exact"],
    )
    adjusted = [None] * len(rows)
    running = 0.0
    m = len(rows)

    for rank, (original_index, row) in enumerate(ordered):
        value = min(1.0, row["p_value_exact"] * (m - rank))
        running = max(running, value)
        adjusted[original_index] = min(1.0, running)

    for index, value in enumerate(adjusted):
        rows[index]["p_value_holm_within_endpoint"] = value


def exact_mcnemar(first_success, second_success):
    first_only = sum(
        1
        for a, b in zip(first_success, second_success)
        if a and not b
    )
    second_only = sum(
        1
        for a, b in zip(first_success, second_success)
        if b and not a
    )
    discordant = first_only + second_only

    if discordant == 0:
        p_value = 1.0
    else:
        p_value = binomtest(
            first_only,
            n=discordant,
            p=0.5,
            alternative="two-sided",
        ).pvalue

    return first_only, second_only, discordant, p_value


def main():
    for path in [GT_CSV, GT_META, PRED_CSV, PRED_META]:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    gt_meta = json.loads(GT_META.read_text(encoding="utf-8"))
    pred_meta = json.loads(PRED_META.read_text(encoding="utf-8"))

    if canonical_text_sha256(GT_CSV) != gt_meta["final_csv_canonical_sha256"]:
        raise RuntimeError("Ground-truth canonical CSV hash mismatch")

    if canonical_text_sha256(PRED_CSV) != pred_meta["final_predictions_csv_canonical_sha256"]:
        raise RuntimeError("Prediction canonical CSV hash mismatch")

    gt_rows = read_csv(GT_CSV)
    pred_rows = read_csv(PRED_CSV)

    if len(gt_rows) != 300:
        raise RuntimeError(
            f"Expected 300 ground-truth rows, found {len(gt_rows)}"
        )

    if len(pred_rows) != 900:
        raise RuntimeError(
            f"Expected 900 prediction rows, found {len(pred_rows)}"
        )

    gt_by_id = {}

    for row in gt_rows:
        finding_id = row["finding_id"]
        label = row["final_label"].strip().upper()

        if finding_id in gt_by_id:
            raise RuntimeError(
                f"Duplicate ground-truth finding ID: {finding_id}"
            )

        if label not in ALLOWED:
            raise RuntimeError(
                f"Invalid ground-truth label for {finding_id}: {label}"
            )

        gt_by_id[finding_id] = {
            **row,
            "final_label": label,
        }

    prediction_by_variant = {
        variant: {}
        for variant in VARIANTS
    }

    for row in pred_rows:
        finding_id = row["finding_id"]
        variant = row["variant_short"].strip().upper()
        label = row["label"].strip().upper()

        if variant not in VARIANTS:
            raise RuntimeError(
                f"Unexpected variant {variant} for {finding_id}"
            )

        if label not in ALLOWED:
            raise RuntimeError(
                f"Invalid prediction label for {finding_id}/{variant}: {label}"
            )

        if finding_id not in gt_by_id:
            raise RuntimeError(
                f"Prediction finding absent from ground truth: {finding_id}"
            )

        if finding_id in prediction_by_variant[variant]:
            raise RuntimeError(
                f"Duplicate prediction for {finding_id}/{variant}"
            )

        prediction_by_variant[variant][finding_id] = {
            **row,
            "label": label,
        }

    for variant in VARIANTS:
        missing = sorted(
            set(gt_by_id) - set(prediction_by_variant[variant])
        )
        extra = sorted(
            set(prediction_by_variant[variant]) - set(gt_by_id)
        )

        if missing or extra:
            raise RuntimeError(
                f"Variant {variant} mismatch: missing={missing[:5]}, extra={extra[:5]}"
            )

    resolved_ids = [
        finding_id
        for finding_id, row in gt_by_id.items()
        if row["final_label"] != "UNCERTAIN"
    ]
    uncertain_gt_ids = [
        finding_id
        for finding_id, row in gt_by_id.items()
        if row["final_label"] == "UNCERTAIN"
    ]

    gt_counts = Counter(
        row["final_label"]
        for row in gt_by_id.values()
    )

    if gt_counts != Counter(
        {
            "FALSE_POSITIVE": 278,
            "TRUE_BUG": 13,
            "UNCERTAIN": 9,
        }
    ):
        raise RuntimeError(
            f"Unexpected ground-truth distribution: {dict(gt_counts)}"
        )

    scored_rows = []
    metrics = {}
    metric_rows = []

    for variant in VARIANTS:
        predictions = prediction_by_variant[variant]
        resolved = []

        for finding_id in resolved_ids:
            gt = gt_by_id[finding_id]["final_label"]
            pred = predictions[finding_id]["label"]
            resolved.append((finding_id, gt, pred))

        total = len(resolved)
        gt_positive = sum(
            1 for _, gt, _ in resolved
            if gt == "TRUE_BUG"
        )
        gt_negative = sum(
            1 for _, gt, _ in resolved
            if gt == "FALSE_POSITIVE"
        )
        abstain = sum(
            1 for _, _, pred in resolved
            if pred == "UNCERTAIN"
        )
        abstain_positive = sum(
            1 for _, gt, pred in resolved
            if gt == "TRUE_BUG" and pred == "UNCERTAIN"
        )
        abstain_negative = sum(
            1 for _, gt, pred in resolved
            if gt == "FALSE_POSITIVE" and pred == "UNCERTAIN"
        )
        tp = sum(
            1 for _, gt, pred in resolved
            if gt == "TRUE_BUG" and pred == "TRUE_BUG"
        )
        tn = sum(
            1 for _, gt, pred in resolved
            if gt == "FALSE_POSITIVE" and pred == "FALSE_POSITIVE"
        )
        fp = sum(
            1 for _, gt, pred in resolved
            if gt == "FALSE_POSITIVE" and pred == "TRUE_BUG"
        )
        fn = sum(
            1 for _, gt, pred in resolved
            if gt == "TRUE_BUG" and pred == "FALSE_POSITIVE"
        )
        correct = tp + tn
        covered = total - abstain
        explicit_bug_predictions = tp + fp
        strict_accuracy = safe_div(correct, total)
        coverage = safe_div(covered, total)
        selective_accuracy = safe_div(correct, covered)
        bug_precision = safe_div(tp, explicit_bug_predictions)
        bug_recall_strict = safe_div(tp, gt_positive)
        fp_reduction = safe_div(tn, gt_negative)
        false_alarm_rate = safe_div(fp, gt_negative)
        bug_miss_rate = safe_div(fn + abstain_positive, gt_positive)
        f1_strict = None

        if bug_precision is not None and bug_recall_strict is not None:
            denominator = bug_precision + bug_recall_strict
            if denominator > 0:
                f1_strict = (
                    2
                    * bug_precision
                    * bug_recall_strict
                    / denominator
                )
            else:
                f1_strict = 0.0

        selective_recall = safe_div(tp, tp + fn)
        selective_specificity = safe_div(tn, tn + fp)
        selective_precision = safe_div(tp, tp + fp)
        selective_f1 = None

        if selective_precision is not None and selective_recall is not None:
            denominator = selective_precision + selective_recall
            if denominator > 0:
                selective_f1 = (
                    2
                    * selective_precision
                    * selective_recall
                    / denominator
                )
            else:
                selective_f1 = 0.0

        all_300_counts = Counter(
            predictions[finding_id]["label"]
            for finding_id in gt_by_id
        )
        resolved_counts = Counter(
            pred
            for _, _, pred in resolved
        )
        human_uncertain_prediction_counts = Counter(
            predictions[finding_id]["label"]
            for finding_id in uncertain_gt_ids
        )

        variant_metrics = {
            "variant": variant,
            "resolved_ground_truth_n": total,
            "human_true_bug_n": gt_positive,
            "human_false_positive_n": gt_negative,
            "human_uncertain_excluded_n": len(uncertain_gt_ids),
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "abstain_total": abstain,
            "abstain_on_true_bug": abstain_positive,
            "abstain_on_false_positive": abstain_negative,
            "all_300_prediction_counts": dict(
                sorted(all_300_counts.items())
            ),
            "resolved_prediction_counts": dict(
                sorted(resolved_counts.items())
            ),
            "predictions_on_human_uncertain": dict(
                sorted(human_uncertain_prediction_counts.items())
            ),
            "strict_accuracy": metric_entry(
                strict_accuracy,
                correct,
                total,
            ),
            "coverage": metric_entry(
                coverage,
                covered,
                total,
            ),
            "abstention_rate": metric_entry(
                safe_div(abstain, total),
                abstain,
                total,
            ),
            "selective_accuracy": metric_entry(
                selective_accuracy,
                correct,
                covered,
            ),
            "bug_precision_explicit": metric_entry(
                bug_precision,
                tp,
                explicit_bug_predictions,
            ),
            "bug_recall_strict": metric_entry(
                bug_recall_strict,
                tp,
                gt_positive,
            ),
            "false_positive_reduction_rate": metric_entry(
                fp_reduction,
                tn,
                gt_negative,
            ),
            "false_alarm_rate": metric_entry(
                false_alarm_rate,
                fp,
                gt_negative,
            ),
            "bug_miss_or_abstain_rate": metric_entry(
                bug_miss_rate,
                fn + abstain_positive,
                gt_positive,
            ),
            "f1_strict": metric_entry(f1_strict),
            "selective_recall": metric_entry(selective_recall),
            "selective_specificity": metric_entry(selective_specificity),
            "selective_precision": metric_entry(selective_precision),
            "selective_f1": metric_entry(selective_f1),
        }

        metrics[variant] = variant_metrics

        metric_rows.append(
            {
                "variant": variant,
                "resolved_n": total,
                "human_true_bug_n": gt_positive,
                "human_false_positive_n": gt_negative,
                "human_uncertain_excluded_n": len(uncertain_gt_ids),
                "tp": tp,
                "tn": tn,
                "fp": fp,
                "fn": fn,
                "abstain_total": abstain,
                "abstain_on_true_bug": abstain_positive,
                "abstain_on_false_positive": abstain_negative,
                "strict_accuracy": strict_accuracy,
                "strict_accuracy_ci95_low": variant_metrics[
                    "strict_accuracy"
                ]["ci95_low"],
                "strict_accuracy_ci95_high": variant_metrics[
                    "strict_accuracy"
                ]["ci95_high"],
                "coverage": coverage,
                "coverage_ci95_low": variant_metrics["coverage"][
                    "ci95_low"
                ],
                "coverage_ci95_high": variant_metrics["coverage"][
                    "ci95_high"
                ],
                "selective_accuracy": selective_accuracy,
                "bug_precision_explicit": bug_precision,
                "bug_recall_strict": bug_recall_strict,
                "bug_recall_ci95_low": variant_metrics[
                    "bug_recall_strict"
                ]["ci95_low"],
                "bug_recall_ci95_high": variant_metrics[
                    "bug_recall_strict"
                ]["ci95_high"],
                "false_positive_reduction_rate": fp_reduction,
                "fp_reduction_ci95_low": variant_metrics[
                    "false_positive_reduction_rate"
                ]["ci95_low"],
                "fp_reduction_ci95_high": variant_metrics[
                    "false_positive_reduction_rate"
                ]["ci95_high"],
                "false_alarm_rate": false_alarm_rate,
                "f1_strict": f1_strict,
                "selective_recall": selective_recall,
                "selective_specificity": selective_specificity,
                "selective_precision": selective_precision,
                "selective_f1": selective_f1,
            }
        )

        for finding_id in gt_by_id:
            gt_row = gt_by_id[finding_id]
            pred_row = predictions[finding_id]
            gt = gt_row["final_label"]
            pred = pred_row["label"]
            resolved_flag = gt != "UNCERTAIN"
            correct_flag = resolved_flag and pred == gt
            scored_rows.append(
                {
                    "finding_id": finding_id,
                    "variant": variant,
                    "repository": gt_row["repository"],
                    "filename": gt_row["filename"],
                    "line_number": gt_row["line_number"],
                    "security_family": gt_row["security_family"],
                    "cwe_id": gt_row["cwe_id"],
                    "human_label": gt,
                    "model_label": pred,
                    "resolved_for_binary_metrics": str(
                        resolved_flag
                    ).lower(),
                    "strict_correct": (
                        str(correct_flag).lower()
                        if resolved_flag
                        else ""
                    ),
                    "model_abstained": str(
                        pred == "UNCERTAIN"
                    ).lower(),
                    "request_id": pred_row["request_id"],
                }
            )

    endpoint_builders = {
        "strict_overall_correctness": lambda gt, pred: pred == gt,
        "false_positive_suppression": lambda gt, pred: (
            gt == "FALSE_POSITIVE"
            and pred == "FALSE_POSITIVE"
        ),
        "true_bug_retention": lambda gt, pred: (
            gt == "TRUE_BUG"
            and pred == "TRUE_BUG"
        ),
    }

    endpoint_ids = {
        "strict_overall_correctness": resolved_ids,
        "false_positive_suppression": [
            finding_id
            for finding_id in resolved_ids
            if gt_by_id[finding_id]["final_label"]
            == "FALSE_POSITIVE"
        ],
        "true_bug_retention": [
            finding_id
            for finding_id in resolved_ids
            if gt_by_id[finding_id]["final_label"]
            == "TRUE_BUG"
        ],
    }

    mcnemar_rows = []

    for endpoint, builder in endpoint_builders.items():
        endpoint_rows = []

        for first, second in combinations(VARIANTS, 2):
            ids = endpoint_ids[endpoint]
            first_success = []
            second_success = []

            for finding_id in ids:
                gt = gt_by_id[finding_id]["final_label"]
                first_pred = prediction_by_variant[first][
                    finding_id
                ]["label"]
                second_pred = prediction_by_variant[second][
                    finding_id
                ]["label"]
                first_success.append(
                    builder(gt, first_pred)
                )
                second_success.append(
                    builder(gt, second_pred)
                )

            first_only, second_only, discordant, p_value = (
                exact_mcnemar(
                    first_success,
                    second_success,
                )
            )
            first_rate = safe_div(
                sum(first_success),
                len(ids),
            )
            second_rate = safe_div(
                sum(second_success),
                len(ids),
            )

            endpoint_rows.append(
                {
                    "endpoint": endpoint,
                    "n": len(ids),
                    "variant_1": first,
                    "variant_2": second,
                    "variant_1_successes": sum(first_success),
                    "variant_2_successes": sum(second_success),
                    "variant_1_rate": first_rate,
                    "variant_2_rate": second_rate,
                    "variant_1_only_success": first_only,
                    "variant_2_only_success": second_only,
                    "discordant_pairs": discordant,
                    "delta_variant_2_minus_variant_1": (
                        second_rate - first_rate
                    ),
                    "p_value_exact": p_value,
                }
            )

        holm_adjust(endpoint_rows)
        mcnemar_rows.extend(endpoint_rows)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with SCORED_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(scored_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(scored_rows)

    with METRICS_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=list(metric_rows[0].keys()),
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(metric_rows)

    with MCNEMAR_CSV.open(
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

    summary = {
        "evaluation_version": "v6",
        "model": pred_meta["configured_model_id"],
        "reasoning_effort": pred_meta["reasoning_effort"],
        "hash_policy": "canonical_lf_text_v1",
        "ground_truth_sha256": canonical_text_sha256(GT_CSV),
        "predictions_sha256": canonical_text_sha256(PRED_CSV),
        "ground_truth_counts": dict(sorted(gt_counts.items())),
        "resolved_binary_cases": len(resolved_ids),
        "excluded_human_uncertain_cases": len(uncertain_gt_ids),
        "scoring_policy": {
            "positive_class": "TRUE_BUG",
            "negative_class": "FALSE_POSITIVE",
            "human_uncertain": "excluded_from_headline_binary_metrics",
            "model_uncertain": "abstention",
            "strict_accuracy": "abstention_counts_as_not_correct",
            "bug_recall_strict": "model_abstention_on_true_bug_counts_as_not_retained",
            "false_positive_reduction_rate": "only_explicit_FALSE_POSITIVE_prediction_counts_as_successful_suppression",
            "selective_metrics": "computed_only_on_non_abstained_predictions",
        },
        "confidence_intervals": {
            "method": "Wilson score interval",
            "confidence": 0.95,
        },
        "paired_tests": {
            "method": "exact McNemar via two-sided exact binomial test on discordant pairs",
            "multiple_testing": "Holm correction within each endpoint across A-B, A-C, B-C",
        },
        "variant_metrics": metrics,
        "pairwise_mcnemar": mcnemar_rows,
        "outputs": {
            "scored_predictions_csv": relative_path(SCORED_CSV),
            "variant_metrics_csv": relative_path(METRICS_CSV),
            "pairwise_mcnemar_csv": relative_path(MCNEMAR_CSV),
            "summary_json": relative_path(SUMMARY_JSON),
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

    summary["output_sha256"] = {
        "scored_predictions_csv": sha256(SCORED_CSV),
        "variant_metrics_csv": sha256(METRICS_CSV),
        "pairwise_mcnemar_csv": sha256(MCNEMAR_CSV),
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

    compact = {
        "evaluation_version": summary["evaluation_version"],
        "model": summary["model"],
        "ground_truth_counts": summary["ground_truth_counts"],
        "resolved_binary_cases": summary["resolved_binary_cases"],
        "excluded_human_uncertain_cases": summary[
            "excluded_human_uncertain_cases"
        ],
        "variant_metrics": {
            variant: {
                "tp": metrics[variant]["tp"],
                "tn": metrics[variant]["tn"],
                "fp": metrics[variant]["fp"],
                "fn": metrics[variant]["fn"],
                "abstain_total": metrics[variant]["abstain_total"],
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
                "false_positive_reduction_rate": metrics[variant][
                    "false_positive_reduction_rate"
                ],
                "f1_strict": metrics[variant]["f1_strict"],
            }
            for variant in VARIANTS
        },
        "pairwise_mcnemar": mcnemar_rows,
        "outputs": summary["outputs"],
    }

    print(json.dumps(compact, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
