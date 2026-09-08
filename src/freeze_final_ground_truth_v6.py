import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
ANNOTATION_DIR = DATA_DIR / "annotation_v6"
SOURCE = DATA_DIR / "ground_truth_annotation_sample_v6.csv"
ANNOTATOR_1 = ANNOTATION_DIR / "annotator_1_v6.csv"
ANNOTATOR_2 = ANNOTATION_DIR / "annotator_2_v6.csv"
ADJUDICATION = ANNOTATION_DIR / "annotation_adjudication_v6.csv"
FINAL_CSV = ANNOTATION_DIR / "final_ground_truth_v6.csv"
FINAL_JSON = ANNOTATION_DIR / "final_ground_truth_v6.json"
METADATA_JSON = ANNOTATION_DIR / "final_ground_truth_v6_metadata.json"
EXPECTED_SOURCE_SHA256 = "e25c2870b96adc7e5eb9604d8c4320d7b478ec9ec011a1e3697a3b06288806d3"
ALLOWED_LABELS = {"TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"}
SOURCE_IMMUTABLE_COLUMNS = [
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


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def normalize(value):
    return "" if value is None else str(value)


def normalize_text(value):
    return normalize(value).replace("\r\n", "\n").replace("\r", "\n")


def validate_complete_annotation(rows, name):
    if len(rows) != 300:
        raise RuntimeError(f"{name} must contain 300 rows, found {len(rows)}")

    ids = [normalize(row.get("finding_id")) for row in rows]

    if len(set(ids)) != 300:
        raise RuntimeError(f"{name} must contain 300 unique finding IDs")

    for index, row in enumerate(rows, start=1):
        finding_id = normalize(row.get("finding_id"))
        expected_row_id = f"GT-{index:03d}"
        actual_row_id = normalize(row.get("annotation_row_id"))

        if actual_row_id != expected_row_id:
            raise RuntimeError(
                f"{name} has annotation_row_id {actual_row_id} for {finding_id}; expected {expected_row_id}"
            )

        label = normalize(row.get("label")).strip().upper()
        rationale = normalize(row.get("rationale")).strip()

        if label not in ALLOWED_LABELS:
            raise RuntimeError(
                f"{name} has invalid label for {finding_id}: {label}"
            )

        if not rationale:
            raise RuntimeError(
                f"{name} has blank rationale for {finding_id}"
            )


def main():
    if sha256(SOURCE) != EXPECTED_SOURCE_SHA256:
        raise RuntimeError(
            "Frozen V6 source sample SHA-256 does not match the authoritative sample"
        )

    source_rows = read_csv(SOURCE)
    rows_1 = read_csv(ANNOTATOR_1)
    rows_2 = read_csv(ANNOTATOR_2)
    adjudication_rows = read_csv(ADJUDICATION)

    if len(source_rows) != 300:
        raise RuntimeError(
            f"Frozen V6 source must contain 300 rows, found {len(source_rows)}"
        )

    validate_complete_annotation(rows_1, "Annotator 1")
    validate_complete_annotation(rows_2, "Annotator 2")

    by_id_1 = {
        normalize(row["finding_id"]): row
        for row in rows_1
    }
    by_id_2 = {
        normalize(row["finding_id"]): row
        for row in rows_2
    }

    source_ids = [normalize(row["finding_id"]) for row in source_rows]

    if len(set(source_ids)) != 300:
        raise RuntimeError("Frozen V6 source must contain 300 unique finding IDs")

    if set(source_ids) != set(by_id_1) or set(source_ids) != set(by_id_2):
        raise RuntimeError(
            "Annotator finding IDs do not exactly match the frozen V6 sample"
        )

    disagreement_ids = []

    for index, source_row in enumerate(source_rows, start=1):
        finding_id = normalize(source_row["finding_id"])
        row_1 = by_id_1[finding_id]
        row_2 = by_id_2[finding_id]
        expected_row_id = f"GT-{index:03d}"

        if normalize(row_1.get("annotation_row_id")) != expected_row_id:
            raise RuntimeError(
                f"Annotator 1 annotation_row_id mismatch for {finding_id}"
            )

        if normalize(row_2.get("annotation_row_id")) != expected_row_id:
            raise RuntimeError(
                f"Annotator 2 annotation_row_id mismatch for {finding_id}"
            )

        for column in SOURCE_IMMUTABLE_COLUMNS:
            source_value = normalize_text(source_row.get(column))
            value_1 = normalize_text(row_1.get(column))
            value_2 = normalize_text(row_2.get(column))

            if source_value != value_1:
                raise RuntimeError(
                    f"Annotator 1 changed immutable field {column} for {finding_id}"
                )

            if source_value != value_2:
                raise RuntimeError(
                    f"Annotator 2 changed immutable field {column} for {finding_id}"
                )

        label_1 = normalize(row_1["label"]).strip().upper()
        label_2 = normalize(row_2["label"]).strip().upper()

        if label_1 != label_2:
            disagreement_ids.append(finding_id)

    adjudication_by_id = {}

    for row in adjudication_rows:
        finding_id = normalize(row.get("finding_id"))

        if not finding_id:
            continue

        if finding_id in adjudication_by_id:
            raise RuntimeError(
                f"Duplicate adjudication row for {finding_id}"
            )

        adjudication_by_id[finding_id] = row

    if set(adjudication_by_id) != set(disagreement_ids):
        missing = sorted(set(disagreement_ids) - set(adjudication_by_id))
        extra = sorted(set(adjudication_by_id) - set(disagreement_ids))
        raise RuntimeError(
            f"Adjudication rows do not match disagreements. Missing={missing}, Extra={extra}"
        )

    for finding_id in disagreement_ids:
        row = adjudication_by_id[finding_id]
        label = normalize(row.get("adjudicated_label")).strip().upper()
        rationale = normalize(row.get("adjudication_rationale")).strip()
        evidence = normalize(row.get("adjudication_evidence_locations")).strip()

        if label not in ALLOWED_LABELS:
            raise RuntimeError(
                f"Invalid adjudicated label for {finding_id}: {label}"
            )

        if not rationale:
            raise RuntimeError(
                f"Blank adjudication rationale for {finding_id}"
            )

        if not evidence:
            raise RuntimeError(
                f"Blank adjudication evidence locations for {finding_id}"
            )

    final_rows = []

    for index, source_row in enumerate(source_rows, start=1):
        finding_id = normalize(source_row["finding_id"])
        row_1 = by_id_1[finding_id]
        row_2 = by_id_2[finding_id]
        label_1 = normalize(row_1["label"]).strip().upper()
        label_2 = normalize(row_2["label"]).strip().upper()
        agreed = label_1 == label_2

        if agreed:
            adjudicated_label = ""
            adjudication_rationale = ""
            adjudication_evidence = ""
            final_label = label_1
            final_rationale = (
                "Independent annotators agreed; original rationales are preserved "
                "in the annotator rationale fields."
            )
            final_evidence = "; ".join(
                value
                for value in [
                    normalize(row_1.get("evidence_locations")).strip(),
                    normalize(row_2.get("evidence_locations")).strip(),
                ]
                if value
            )
            decision_source = "independent_agreement"
        else:
            adjudication_row = adjudication_by_id[finding_id]
            adjudicated_label = normalize(
                adjudication_row.get("adjudicated_label")
            ).strip().upper()
            adjudication_rationale = normalize(
                adjudication_row.get("adjudication_rationale")
            ).strip()
            adjudication_evidence = normalize(
                adjudication_row.get("adjudication_evidence_locations")
            ).strip()
            final_label = adjudicated_label
            final_rationale = adjudication_rationale
            final_evidence = adjudication_evidence
            decision_source = "adjudication"

        final_row = {
            "annotation_row_id": f"GT-{index:03d}",
            **{
                column: source_row.get(column, "")
                for column in SOURCE_IMMUTABLE_COLUMNS
            },
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
            "pre_adjudication_agreement": str(agreed).lower(),
            "adjudicated_label": adjudicated_label,
            "adjudication_rationale": adjudication_rationale,
            "adjudication_evidence_locations": adjudication_evidence,
            "final_label": final_label,
            "final_rationale": final_rationale,
            "final_evidence_locations": final_evidence,
            "final_decision_source": decision_source,
        }

        final_rows.append(final_row)

    final_counts = Counter(
        row["final_label"]
        for row in final_rows
    )

    fieldnames = [
        "annotation_row_id",
        *SOURCE_IMMUTABLE_COLUMNS,
        "annotator_1_label",
        "annotator_1_rationale",
        "annotator_1_evidence_locations",
        "annotator_2_label",
        "annotator_2_rationale",
        "annotator_2_evidence_locations",
        "pre_adjudication_agreement",
        "adjudicated_label",
        "adjudication_rationale",
        "adjudication_evidence_locations",
        "final_label",
        "final_rationale",
        "final_evidence_locations",
        "final_decision_source",
    ]

    with FINAL_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(final_rows)

    FINAL_JSON.write_text(
        json.dumps(
            final_rows,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    metadata = {
        "annotation_protocol_version": "v6",
        "source_sample_sha256": sha256(SOURCE),
        "annotator_1_sha256": sha256(ANNOTATOR_1),
        "annotator_2_sha256": sha256(ANNOTATOR_2),
        "adjudication_sha256": sha256(ADJUDICATION),
        "sample_size": len(final_rows),
        "agreement_count": len(final_rows) - len(disagreement_ids),
        "disagreement_count": len(disagreement_ids),
        "adjudicated_count": len(disagreement_ids),
        "final_label_counts": {
            label: final_counts[label]
            for label in sorted(ALLOWED_LABELS)
        },
        "unresolved_pending_count": 0,
        "final_csv": str(FINAL_CSV),
        "final_json": str(FINAL_JSON),
    }

    metadata["final_csv_sha256"] = sha256(FINAL_CSV)
    metadata["final_json_sha256"] = sha256(FINAL_JSON)

    METADATA_JSON.write_text(
        json.dumps(
            metadata,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(json.dumps(metadata, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
