import csv
import hashlib
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE = PROJECT_ROOT / "data" / "ground_truth_annotation_sample_v6.csv"
OUTPUT_DIR = PROJECT_ROOT / "data" / "annotation_v6"
EXPECTED_SHA256 = "e25c2870b96adc7e5eb9604d8c4320d7b478ec9ec011a1e3697a3b06288806d3"
KEEP_COLUMNS = [
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
OUTPUT_COLUMNS = [
    "annotation_row_id",
    *KEEP_COLUMNS,
    "label",
    "rationale",
    "evidence_locations",
]


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_annotator_file(rows, annotator):
    path = OUTPUT_DIR / f"annotator_{annotator}_v6.csv"

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()

        for index, source_row in enumerate(rows, start=1):
            row = {
                "annotation_row_id": f"GT-{index:03d}",
                **{column: source_row[column] for column in KEEP_COLUMNS},
                "label": "PENDING",
                "rationale": "",
                "evidence_locations": "",
            }
            writer.writerow(row)

    return path


def main():
    if not SOURCE.exists():
        raise FileNotFoundError(f"Frozen V6 sample not found: {SOURCE}")

    source_hash = sha256(SOURCE)

    if source_hash != EXPECTED_SHA256:
        raise RuntimeError(
            f"Frozen sample SHA-256 mismatch: expected {EXPECTED_SHA256}, found {source_hash}"
        )

    with SOURCE.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        fieldnames = set(reader.fieldnames or [])

    missing = set(KEEP_COLUMNS).difference(fieldnames)

    if missing:
        raise RuntimeError(
            "Frozen sample is missing required columns: "
            + ", ".join(sorted(missing))
        )

    if len(rows) != 300:
        raise RuntimeError(f"Expected 300 findings, found {len(rows)}")

    finding_ids = [row["finding_id"] for row in rows]

    if len(set(finding_ids)) != 300:
        raise RuntimeError("Frozen sample contains duplicate finding IDs")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    annotator_1 = write_annotator_file(rows, 1)
    annotator_2 = write_annotator_file(rows, 2)

    metadata = {
        "annotation_protocol_version": "v6",
        "source_file": str(SOURCE.resolve()),
        "source_sha256": source_hash,
        "sample_size": len(rows),
        "finding_ids_unique": True,
        "blinded_fields_removed": [
            "scanner_count",
            "scanners",
            "rule_ids",
            "raw_alert_count",
            "raw_alert_ids",
            "reported_lines",
            "severity",
            "confidence",
            "messages",
        ],
        "allowed_labels": [
            "TRUE_BUG",
            "FALSE_POSITIVE",
            "UNCERTAIN",
        ],
        "annotator_1_file": str(annotator_1.resolve()),
        "annotator_1_sha256": sha256(annotator_1),
        "annotator_2_file": str(annotator_2.resolve()),
        "annotator_2_sha256": sha256(annotator_2),
        "independent_annotation_required": True,
    }

    metadata_path = OUTPUT_DIR / "annotation_preparation_metadata_v6.json"
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "source_sha256": source_hash,
                "sample_size": len(rows),
                "unique_finding_ids": len(set(finding_ids)),
                "annotator_1": str(annotator_1),
                "annotator_2": str(annotator_2),
                "annotator_1_sha256": metadata["annotator_1_sha256"],
                "annotator_2_sha256": metadata["annotator_2_sha256"],
                "metadata": str(metadata_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
