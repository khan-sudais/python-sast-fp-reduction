import argparse
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUN_ID = "final_100_v5_complete"
GENERATED_ROOT = PROJECT_ROOT / "data" / "generated" / "runs"
RESULTS_ROOT = PROJECT_ROOT / "results_generated"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "ground_truth_sample_audit_v5.json"


def distribution(dataframe, columns):
    grouped = (
        dataframe.groupby(columns, dropna=False)
        .size()
        .reset_index(name="count")
        .sort_values(columns)
        .reset_index(drop=True)
    )
    return grouped


def distribution_dict(dataframe, columns):
    grouped = distribution(dataframe, columns)
    records = []

    for _, row in grouped.iterrows():
        record = {column: row[column] for column in columns}
        record["count"] = int(row["count"])
        records.append(record)

    return records


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args()

    processed = GENERATED_ROOT / args.run_id / "processed"
    canonical_path = processed / "canonical_findings_comparable.csv"
    sample_path = processed / "annotation_sample.csv"

    if not canonical_path.exists():
        raise FileNotFoundError(f"Missing canonical findings: {canonical_path}")

    if not sample_path.exists():
        raise FileNotFoundError(f"Missing annotation sample: {sample_path}")

    canonical = pd.read_csv(canonical_path)
    sample = pd.read_csv(sample_path)

    if "finding_id" not in canonical.columns:
        raise RuntimeError("canonical_findings_comparable.csv has no finding_id column")

    if "finding_id" not in sample.columns:
        raise RuntimeError("annotation_sample.csv has no finding_id column")

    canonical_ids = canonical["finding_id"].astype(str)
    sample_ids = sample["finding_id"].astype(str)

    duplicate_sample_ids = sample_ids[sample_ids.duplicated()].tolist()
    missing_from_canonical = sorted(set(sample_ids) - set(canonical_ids))
    exact_rows = sample.merge(
        canonical,
        on="finding_id",
        suffixes=("_sample", "_canonical"),
        how="left",
        validate="many_to_one",
        indicator=True,
    )

    shared_columns = [
        column
        for column in sample.columns
        if column in canonical.columns and column != "finding_id"
    ]

    mismatches = []

    for column in shared_columns:
        left = exact_rows[f"{column}_sample"].astype("string").fillna("<NA>")
        right = exact_rows[f"{column}_canonical"].astype("string").fillna("<NA>")
        mismatch_count = int((left != right).sum())

        if mismatch_count:
            mismatches.append(
                {
                    "column": column,
                    "mismatch_count": mismatch_count,
                }
            )

    pending_columns = [
        "annotator_1_label",
        "annotator_2_label",
        "adjudicated_label",
        "rationale",
    ]

    pending_summary = {}

    for column in pending_columns:
        if column in sample.columns:
            values = sample[column].astype("string").fillna("<NA>")
            pending_summary[column] = {
                "unique_values": sorted(str(value) for value in values.unique()),
                "pending_count": int((values == "PENDING").sum()),
            }

    strata = []

    for columns in [
        ["security_family"],
        ["cwe_id"],
        ["domain"],
        ["cohort"],
        ["security_family", "cohort"],
        ["security_family", "domain"],
    ]:
        if all(column in canonical.columns for column in columns):
            population_distribution = distribution(canonical, columns)
            sample_distribution = distribution(sample, columns)
            merged = population_distribution.merge(
                sample_distribution,
                on=columns,
                how="outer",
                suffixes=("_population", "_sample"),
            ).fillna(0)

            merged["population_share"] = (
                merged["count_population"] / len(canonical)
            )
            merged["sample_share"] = (
                merged["count_sample"] / len(sample)
            )
            merged["absolute_share_difference"] = (
                merged["sample_share"] - merged["population_share"]
            ).abs()

            strata.append(
                {
                    "columns": columns,
                    "max_absolute_share_difference": float(
                        merged["absolute_share_difference"].max()
                    ),
                    "rows": [
                        {
                            **{
                                column: row[column]
                                for column in columns
                            },
                            "population_count": int(row["count_population"]),
                            "sample_count": int(row["count_sample"]),
                            "population_share": float(row["population_share"]),
                            "sample_share": float(row["sample_share"]),
                            "absolute_share_difference": float(
                                row["absolute_share_difference"]
                            ),
                        }
                        for _, row in merged.iterrows()
                    ],
                }
            )

    result = {
        "run_id": args.run_id,
        "canonical_population_rows": int(len(canonical)),
        "annotation_sample_rows": int(len(sample)),
        "unique_population_finding_ids": int(canonical_ids.nunique()),
        "unique_sample_finding_ids": int(sample_ids.nunique()),
        "duplicate_sample_finding_ids": duplicate_sample_ids,
        "sample_ids_missing_from_population": missing_from_canonical,
        "shared_column_mismatches": mismatches,
        "annotation_status": pending_summary,
        "repositories_in_population": int(canonical["repository"].nunique())
        if "repository" in canonical.columns
        else None,
        "repositories_in_sample": int(sample["repository"].nunique())
        if "repository" in sample.columns
        else None,
        "security_families_in_population": int(canonical["security_family"].nunique())
        if "security_family" in canonical.columns
        else None,
        "security_families_in_sample": int(sample["security_family"].nunique())
        if "security_family" in sample.columns
        else None,
        "domains_in_population": int(canonical["domain"].nunique())
        if "domain" in canonical.columns
        else None,
        "domains_in_sample": int(sample["domain"].nunique())
        if "domain" in sample.columns
        else None,
        "cohorts_in_population": int(canonical["cohort"].nunique())
        if "cohort" in canonical.columns
        else None,
        "cohorts_in_sample": int(sample["cohort"].nunique())
        if "cohort" in sample.columns
        else None,
        "population_by_security_family": distribution_dict(
            canonical,
            ["security_family"],
        )
        if "security_family" in canonical.columns
        else [],
        "sample_by_security_family": distribution_dict(
            sample,
            ["security_family"],
        )
        if "security_family" in sample.columns
        else [],
        "stratification_comparison": strata,
    }

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(json.dumps(
        {
            "canonical_population_rows": result["canonical_population_rows"],
            "annotation_sample_rows": result["annotation_sample_rows"],
            "unique_sample_finding_ids": result["unique_sample_finding_ids"],
            "duplicate_sample_finding_ids": len(
                result["duplicate_sample_finding_ids"]
            ),
            "sample_ids_missing_from_population": len(
                result["sample_ids_missing_from_population"]
            ),
            "shared_column_mismatches": result["shared_column_mismatches"],
            "repositories_in_population": result["repositories_in_population"],
            "repositories_in_sample": result["repositories_in_sample"],
            "security_families_in_population": result[
                "security_families_in_population"
            ],
            "security_families_in_sample": result[
                "security_families_in_sample"
            ],
            "domains_in_population": result["domains_in_population"],
            "domains_in_sample": result["domains_in_sample"],
            "cohorts_in_population": result["cohorts_in_population"],
            "cohorts_in_sample": result["cohorts_in_sample"],
            "annotation_status": result["annotation_status"],
            "output": str(output),
        },
        indent=2,
    ))

    print("\n=== SECURITY FAMILY DISTRIBUTION ===")
    population_family = distribution(canonical, ["security_family"])
    sample_family = distribution(sample, ["security_family"])
    family = population_family.merge(
        sample_family,
        on="security_family",
        how="outer",
        suffixes=("_population", "_sample"),
    ).fillna(0)
    family["population_pct"] = (
        family["count_population"] / len(canonical) * 100
    ).round(2)
    family["sample_pct"] = (
        family["count_sample"] / len(sample) * 100
    ).round(2)
    print(family.to_string(index=False))

    print("\n=== DOMAIN DISTRIBUTION ===")
    domain_population = distribution(canonical, ["domain"])
    domain_sample = distribution(sample, ["domain"])
    domain = domain_population.merge(
        domain_sample,
        on="domain",
        how="outer",
        suffixes=("_population", "_sample"),
    ).fillna(0)
    domain["population_pct"] = (
        domain["count_population"] / len(canonical) * 100
    ).round(2)
    domain["sample_pct"] = (
        domain["count_sample"] / len(sample) * 100
    ).round(2)
    print(domain.to_string(index=False))


if __name__ == "__main__":
    main()
