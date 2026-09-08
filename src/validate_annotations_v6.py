import argparse
import csv
import json
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT_ROOT / "data" / "ground_truth_annotation_sample_v6.csv"
ANNOTATION_DIR = PROJECT_ROOT / "data" / "annotation_v6"
DEFAULT_OUTPUT = ANNOTATION_DIR / "annotation_validation_v6.json"
ALLOWED_LABELS = {"TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"}
IMMUTABLE_COLUMNS = [
    "finding_id",
    "repo_id",
    "repository",
    "commit_sha",
    "security_family",
    "cwe_id",
    "filename",
    "statement_start",
    "statement_end",
    "line_number",
    "statement_code",
]


def read_csv(path):
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def normalize(value):
    return "" if value is None else str(value)


def normalize_immutable(value):
    return normalize(value).replace("\r\n", "\n").replace("\r", "\n")


def validate_annotator(annotator, source_rows, allow_pending):
    path = ANNOTATION_DIR / f"annotator_{annotator}_v6.csv"
    result = {
        "annotator": annotator,
        "file": str(path),
        "exists": path.exists(),
        "rows": 0,
        "unique_finding_ids": 0,
        "pending_labels": 0,
        "valid_completed_labels": 0,
        "blank_rationales_for_completed_labels": 0,
        "invalid_labels": [],
        "duplicate_finding_ids": [],
        "missing_finding_ids": [],
        "extra_finding_ids": [],
        "immutable_field_mismatches": [],
        "annotation_row_id_mismatches": [],
        "complete": False,
        "valid": False,
    }

    if not path.exists():
        return result

    rows = read_csv(path)
    result["rows"] = len(rows)

    finding_ids = [normalize(row.get("finding_id")) for row in rows]
    result["unique_finding_ids"] = len(set(finding_ids))

    seen = set()
    duplicates = []

    for finding_id in finding_ids:
        if finding_id in seen and finding_id not in duplicates:
            duplicates.append(finding_id)
        seen.add(finding_id)

    result["duplicate_finding_ids"] = duplicates

    source_by_id = {
        normalize(row["finding_id"]): row
        for row in source_rows
    }
    current_by_id = {
        normalize(row.get("finding_id")): row
        for row in rows
    }

    result["missing_finding_ids"] = sorted(
        set(source_by_id) - set(current_by_id)
    )
    result["extra_finding_ids"] = sorted(
        set(current_by_id) - set(source_by_id)
    )

    for index, row in enumerate(rows, start=1):
        expected_row_id = f"GT-{index:03d}"

        if normalize(row.get("annotation_row_id")) != expected_row_id:
            result["annotation_row_id_mismatches"].append(
                {
                    "row": index,
                    "expected": expected_row_id,
                    "found": normalize(row.get("annotation_row_id")),
                }
            )

        finding_id = normalize(row.get("finding_id"))
        source_row = source_by_id.get(finding_id)

        if source_row is not None:
            for column in IMMUTABLE_COLUMNS:
                expected = normalize_immutable(source_row.get(column))
                found = normalize_immutable(row.get(column))

                if expected != found:
                    result["immutable_field_mismatches"].append(
                        {
                            "finding_id": finding_id,
                            "column": column,
                            "expected": expected,
                            "found": found,
                        }
                    )

        label = normalize(row.get("label")).strip().upper()
        rationale = normalize(row.get("rationale")).strip()

        if label == "PENDING":
            result["pending_labels"] += 1
        elif label in ALLOWED_LABELS:
            result["valid_completed_labels"] += 1

            if not rationale:
                result["blank_rationales_for_completed_labels"] += 1
        else:
            result["invalid_labels"].append(
                {
                    "finding_id": finding_id,
                    "label": normalize(row.get("label")),
                }
            )

    structural_valid = (
        result["rows"] == 300
        and result["unique_finding_ids"] == 300
        and not result["duplicate_finding_ids"]
        and not result["missing_finding_ids"]
        and not result["extra_finding_ids"]
        and not result["immutable_field_mismatches"]
        and not result["annotation_row_id_mismatches"]
        and not result["invalid_labels"]
        and result["blank_rationales_for_completed_labels"] == 0
    )

    result["complete"] = (
        structural_valid
        and result["pending_labels"] == 0
        and result["valid_completed_labels"] == 300
    )
    result["valid"] = structural_valid and (
        allow_pending or result["complete"]
    )

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--annotator",
        choices=["1", "2", "all"],
        default="all",
    )
    parser.add_argument("--allow-pending", action="store_true")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    if not SOURCE.exists():
        raise FileNotFoundError(f"Frozen V6 sample not found: {SOURCE}")

    source_rows = read_csv(SOURCE)

    if len(source_rows) != 300:
        raise RuntimeError(
            f"Frozen source sample must contain 300 rows, found {len(source_rows)}"
        )

    annotators = [1, 2] if args.annotator == "all" else [int(args.annotator)]

    results = [
        validate_annotator(
            annotator,
            source_rows,
            args.allow_pending,
        )
        for annotator in annotators
    ]

    report = {
        "annotation_protocol_version": "v6",
        "line_ending_normalization": "CRLF_and_CR_normalized_to_LF_for_immutable_comparison",
        "allow_pending": args.allow_pending,
        "annotators_checked": annotators,
        "all_valid": all(result["valid"] for result in results),
        "all_complete": all(result["complete"] for result in results),
        "results": results,
    }

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2, ensure_ascii=False))

    if not report["all_valid"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
