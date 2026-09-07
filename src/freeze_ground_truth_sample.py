import argparse
import hashlib
import json
import shutil
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUN_ID = "final_100_v5_complete"
GENERATED_ROOT = PROJECT_ROOT / "data" / "generated" / "runs"
DEFAULT_CSV = PROJECT_ROOT / "data" / "ground_truth_annotation_sample_v5.csv"
DEFAULT_XLSX = PROJECT_ROOT / "data" / "ground_truth_annotation_sample_v5.xlsx"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "ground_truth_sampling_metadata_v5.json"


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--output-csv", default=str(DEFAULT_CSV))
    parser.add_argument("--output-xlsx", default=str(DEFAULT_XLSX))
    parser.add_argument("--metadata", default=str(DEFAULT_METADATA))
    args = parser.parse_args()

    processed = GENERATED_ROOT / args.run_id / "processed"
    source_sample = processed / "annotation_sample.csv"
    population_file = processed / "canonical_findings_comparable.csv"

    if not source_sample.exists():
        raise FileNotFoundError(f"Missing annotation sample: {source_sample}")

    if not population_file.exists():
        raise FileNotFoundError(f"Missing canonical population: {population_file}")

    sample = pd.read_csv(source_sample)
    population = pd.read_csv(population_file)

    if len(population) != 1414:
        raise RuntimeError(
            f"Expected canonical population of 1414, found {len(population)}"
        )

    if len(sample) != 300:
        raise RuntimeError(f"Expected annotation sample of 300, found {len(sample)}")

    if sample["finding_id"].duplicated().any():
        raise RuntimeError("Annotation sample contains duplicate finding_id values")

    missing_ids = sorted(
        set(sample["finding_id"].astype(str))
        - set(population["finding_id"].astype(str))
    )

    if missing_ids:
        raise RuntimeError(
            f"{len(missing_ids)} sample finding IDs are absent from the population"
        )

    for column in [
        "annotator_1_label",
        "annotator_2_label",
        "adjudicated_label",
        "rationale",
    ]:
        if column not in sample.columns:
            raise RuntimeError(f"Missing annotation column: {column}")

        values = sample[column].astype("string").fillna("<NA>")

        if not (values == "PENDING").all():
            raise RuntimeError(
                f"Annotation column {column} is not entirely PENDING"
            )

    output_csv = Path(args.output_csv).resolve()
    output_xlsx = Path(args.output_xlsx).resolve()
    metadata_path = Path(args.metadata).resolve()

    output_csv.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_sample, output_csv)
    sample.to_excel(output_xlsx, index=False)

    metadata = {
        "sampling_metadata_version": "v5",
        "source_run_id": args.run_id,
        "population_file": str(population_file.resolve()),
        "population_sha256": file_sha256(population_file),
        "sample_source_file": str(source_sample.resolve()),
        "sample_source_sha256": file_sha256(source_sample),
        "frozen_sample_csv": str(output_csv),
        "frozen_sample_csv_sha256": file_sha256(output_csv),
        "frozen_sample_xlsx": str(output_xlsx),
        "population_size": int(len(population)),
        "sample_size": int(len(sample)),
        "sampling_unit": "canonical_finding",
        "sampling_seed": 42,
        "stratification_variable": "cwe_id",
        "allocation_method": "proportional_largest_remainder",
        "sampling_without_replacement": True,
        "annotation_state_at_freeze": "PENDING",
        "unique_sample_finding_ids": int(sample["finding_id"].nunique()),
        "repositories_in_population": int(population["repository"].nunique()),
        "repositories_in_sample": int(sample["repository"].nunique()),
        "security_families_in_population": int(
            population["security_family"].nunique()
        ),
        "security_families_in_sample": int(
            sample["security_family"].nunique()
        ),
        "domains_in_population": int(population["domain"].nunique()),
        "domains_in_sample": int(sample["domain"].nunique()),
        "cohorts_in_population": int(population["cohort"].nunique()),
        "cohorts_in_sample": int(sample["cohort"].nunique()),
    }

    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "population_size": len(population),
                "sample_size": len(sample),
                "unique_sample_finding_ids": int(
                    sample["finding_id"].nunique()
                ),
                "repositories_in_sample": int(
                    sample["repository"].nunique()
                ),
                "security_families_in_sample": int(
                    sample["security_family"].nunique()
                ),
                "domains_in_sample": int(sample["domain"].nunique()),
                "cohorts_in_sample": int(sample["cohort"].nunique()),
                "all_annotation_fields_pending": True,
                "sample_csv_sha256": file_sha256(output_csv),
                "output_csv": str(output_csv),
                "output_xlsx": str(output_xlsx),
                "metadata": str(metadata_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
