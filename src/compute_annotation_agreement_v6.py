import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ANNOTATION_DIR = PROJECT_ROOT / "data" / "annotation_v6"
ANNOTATOR_1 = ANNOTATION_DIR / "annotator_1_v6.csv"
ANNOTATOR_2 = ANNOTATION_DIR / "annotator_2_v6.csv"
AGREEMENT_JSON = ANNOTATION_DIR / "annotation_agreement_v6.json"
CONFUSION_CSV = ANNOTATION_DIR / "annotation_confusion_matrix_v6.csv"
DISAGREEMENTS_CSV = ANNOTATION_DIR / "annotation_disagreements_v6.csv"
ADJUDICATION_CSV = ANNOTATION_DIR / "annotation_adjudication_v6.csv"
LABELS = ["TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"]
IMMUTABLE_COLUMNS = [
    "annotation_row_id",
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
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize(value):
    return "" if value is None else str(value)


def normalize_text(value):
    return normalize(value).replace("\r\n", "\n").replace("\r", "\n")


def validate_rows(rows, name):
    if len(rows) != 300:
        raise RuntimeError(f"{name} must contain 300 rows, found {len(rows)}")

    finding_ids = [normalize(row.get("finding_id")) for row in rows]

    if len(set(finding_ids)) != 300:
        raise RuntimeError(f"{name} must contain 300 unique finding IDs")

    for row in rows:
        finding_id = normalize(row.get("finding_id"))
        label = normalize(row.get("label")).strip().upper()
        rationale = normalize(row.get("rationale")).strip()

        if label not in LABELS:
            raise RuntimeError(
                f"{name} contains invalid or incomplete label for {finding_id}: {label}"
            )

        if not rationale:
            raise RuntimeError(
                f"{name} contains blank rationale for {finding_id}"
            )


def main():
    rows_1 = read_csv(ANNOTATOR_1)
    rows_2 = read_csv(ANNOTATOR_2)

    validate_rows(rows_1, "Annotator 1")
    validate_rows(rows_2, "Annotator 2")

    by_id_2 = {
        normalize(row["finding_id"]): row
        for row in rows_2
    }

    disagreements = []
    pairs = []
    immutable_mismatches = []

    for row_1 in rows_1:
        finding_id = normalize(row_1["finding_id"])

        if finding_id not in by_id_2:
            raise RuntimeError(
                f"Annotator 2 is missing finding ID {finding_id}"
            )

        row_2 = by_id_2[finding_id]

        for column in IMMUTABLE_COLUMNS:
            left = normalize_text(row_1.get(column))
            right = normalize_text(row_2.get(column))

            if left != right:
                immutable_mismatches.append(
                    {
                        "finding_id": finding_id,
                        "column": column,
                        "annotator_1": left,
                        "annotator_2": right,
                    }
                )

        label_1 = normalize(row_1["label"]).strip().upper()
        label_2 = normalize(row_2["label"]).strip().upper()
        pairs.append((label_1, label_2))

        if label_1 != label_2:
            disagreement = {
                column: row_1.get(column, "")
                for column in IMMUTABLE_COLUMNS
            }
            disagreement.update(
                {
                    "annotator_1_label": label_1,
                    "annotator_1_rationale": row_1.get("rationale", ""),
                    "annotator_1_evidence_locations": row_1.get(
                        "evidence_locations",
                        "",
                    ),
                    "annotator_2_label": label_2,
                    "annotator_2_rationale": row_2.get("rationale", ""),
                    "annotator_2_evidence_locations": row_2.get(
                        "evidence_locations",
                        "",
                    ),
                }
            )
            disagreements.append(disagreement)

    if immutable_mismatches:
        raise RuntimeError(
            f"Immutable field mismatches detected: {len(immutable_mismatches)}"
        )

    n = len(pairs)
    agreement_count = sum(
        1
        for label_1, label_2 in pairs
        if label_1 == label_2
    )
    raw_agreement = agreement_count / n

    counts_1 = Counter(label_1 for label_1, _ in pairs)
    counts_2 = Counter(label_2 for _, label_2 in pairs)

    expected_agreement = sum(
        (counts_1[label] / n) * (counts_2[label] / n)
        for label in LABELS
    )

    if expected_agreement == 1:
        kappa = 1.0 if raw_agreement == 1 else None
    else:
        kappa = (
            raw_agreement - expected_agreement
        ) / (
            1 - expected_agreement
        )

    confusion = {
        label_1: {
            label_2: 0
            for label_2 in LABELS
        }
        for label_1 in LABELS
    }

    for label_1, label_2 in pairs:
        confusion[label_1][label_2] += 1

    per_label = {}

    for label in LABELS:
        both = confusion[label][label]
        annotator_1_count = counts_1[label]
        annotator_2_count = counts_2[label]
        either = annotator_1_count + annotator_2_count - both

        per_label[label] = {
            "annotator_1_count": annotator_1_count,
            "annotator_2_count": annotator_2_count,
            "joint_agreement_count": both,
            "agreement_given_either_used_label": (
                both / either if either else None
            ),
        }

    report = {
        "annotation_protocol_version": "v6",
        "sample_size": n,
        "annotator_1_sha256": file_sha256(ANNOTATOR_1),
        "annotator_2_sha256": file_sha256(ANNOTATOR_2),
        "agreement_count": agreement_count,
        "disagreement_count": len(disagreements),
        "raw_agreement": raw_agreement,
        "expected_agreement": expected_agreement,
        "cohen_kappa": kappa,
        "labels": LABELS,
        "annotator_1_label_counts": {
            label: counts_1[label]
            for label in LABELS
        },
        "annotator_2_label_counts": {
            label: counts_2[label]
            for label in LABELS
        },
        "per_label": per_label,
        "confusion_matrix": confusion,
        "outputs": {
            "agreement_json": str(AGREEMENT_JSON),
            "confusion_matrix_csv": str(CONFUSION_CSV),
            "disagreements_csv": str(DISAGREEMENTS_CSV),
            "adjudication_csv": str(ADJUDICATION_CSV),
        },
    }

    AGREEMENT_JSON.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    with CONFUSION_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["annotator_1_label", *LABELS, "row_total"]
        )

        for label_1 in LABELS:
            values = [
                confusion[label_1][label_2]
                for label_2 in LABELS
            ]
            writer.writerow(
                [label_1, *values, sum(values)]
            )

        writer.writerow(
            [
                "column_total",
                *[
                    sum(
                        confusion[label_1][label_2]
                        for label_1 in LABELS
                    )
                    for label_2 in LABELS
                ],
                n,
            ]
        )

    disagreement_columns = [
        *IMMUTABLE_COLUMNS,
        "annotator_1_label",
        "annotator_1_rationale",
        "annotator_1_evidence_locations",
        "annotator_2_label",
        "annotator_2_rationale",
        "annotator_2_evidence_locations",
    ]

    with DISAGREEMENTS_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=disagreement_columns,
        )
        writer.writeheader()
        writer.writerows(disagreements)

    adjudication_columns = [
        *disagreement_columns,
        "adjudicated_label",
        "adjudication_rationale",
        "adjudication_evidence_locations",
    ]

    with ADJUDICATION_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=adjudication_columns,
        )
        writer.writeheader()

        for row in disagreements:
            adjudication_row = dict(row)
            adjudication_row["adjudicated_label"] = "PENDING"
            adjudication_row["adjudication_rationale"] = ""
            adjudication_row["adjudication_evidence_locations"] = ""
            writer.writerow(adjudication_row)

    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
