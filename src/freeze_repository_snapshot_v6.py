import argparse
import json
import re
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUN_ID = "final_100_v6"
DEFAULT_SCOPED_MANIFEST = PROJECT_ROOT / "data" / "curated_100_repositories_scoped_v6.csv"
DEFAULT_OUTPUT_XLSX = PROJECT_ROOT / "data" / "frozen_100_repository_snapshot_v6.xlsx"
DEFAULT_OUTPUT_CSV = PROJECT_ROOT / "data" / "frozen_100_repository_snapshot_v6.csv"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "frozen_100_repository_snapshot_v6.json"
CORPUS_PROTOCOL = PROJECT_ROOT / "config" / "corpus_protocol_v6.json"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate_sha(value):
    return bool(re.fullmatch(r"[0-9a-f]{40}", str(value)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", default=DEFAULT_RUN_ID)
    parser.add_argument("--manifest", default=str(DEFAULT_SCOPED_MANIFEST))
    parser.add_argument("--output-xlsx", default=str(DEFAULT_OUTPUT_XLSX))
    parser.add_argument("--output-csv", default=str(DEFAULT_OUTPUT_CSV))
    parser.add_argument("--metadata", default=str(DEFAULT_METADATA))
    args = parser.parse_args()

    run_root = PROJECT_ROOT / "data" / "generated" / "runs" / args.run_id
    results_root = PROJECT_ROOT / "results_generated" / args.run_id

    scan_manifest_path = run_root / "processed" / "scan_manifest.csv"
    coverage_path = run_root / "processed" / "coverage_by_repository.csv"
    scanner_summary_path = results_root / "run_summary.json"
    coverage_summary_path = results_root / "coverage_summary.json"
    scoped_manifest_path = Path(args.manifest).resolve()

    required_paths = [
        scan_manifest_path,
        coverage_path,
        scanner_summary_path,
        coverage_summary_path,
        scoped_manifest_path,
        CORPUS_PROTOCOL,
    ]

    for path in required_paths:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    scan = pd.read_csv(scan_manifest_path)
    coverage = pd.read_csv(coverage_path)
    scoped = pd.read_csv(scoped_manifest_path)
    scanner_summary = load_json(scanner_summary_path)
    coverage_summary = load_json(coverage_summary_path)
    corpus_protocol = load_json(CORPUS_PROTOCOL)

    if len(scan) != 100:
        raise RuntimeError(f"Expected 100 scan rows, found {len(scan)}")

    if (scan["status"].astype(str) != "SUCCESS").any():
        failed = scan.loc[
            scan["status"].astype(str) != "SUCCESS",
            ["repo_id", "repository", "status", "error"],
        ]
        raise RuntimeError(
            "Snapshot cannot be frozen because repositories failed:\n"
            + failed.to_string(index=False)
        )

    if scan["repo_id"].duplicated().any():
        raise RuntimeError("Duplicate repo_id values in final scan")

    if scan["repository"].duplicated().any():
        raise RuntimeError("Duplicate repositories in final scan")

    bad_sha = scan.loc[
        ~scan["commit_sha"].astype(str).map(validate_sha),
        ["repo_id", "repository", "commit_sha"],
    ]

    if not bad_sha.empty:
        raise RuntimeError(
            "Invalid commit SHA values:\n"
            + bad_sha.to_string(index=False)
        )

    if "commit_matches_frozen" not in scan.columns:
        raise RuntimeError("scan_manifest.csv has no commit_matches_frozen column")

    commit_matches = (
        scan["commit_matches_frozen"]
        .astype(str)
        .str.strip()
        .str.casefold()
        .isin({"true", "1"})
    )

    if not commit_matches.all():
        raise RuntimeError("One or more repositories do not match frozen SHAs")

    if not bool(coverage_summary.get("coverage_audit_complete")):
        raise RuntimeError("Coverage audit is not complete")

    if int(scanner_summary.get("repositories_successful", 0)) != 100:
        raise RuntimeError("Scanner summary does not report 100 successful repositories")

    if int(scanner_summary.get("repositories_failed", -1)) != 0:
        raise RuntimeError("Scanner summary reports failed repositories")

    if not bool(scanner_summary.get("all_commits_match_frozen_manifest")):
        raise RuntimeError("Run summary does not confirm frozen commit matches")

    if scanner_summary.get("corpus_protocol_version") != corpus_protocol.get(
        "corpus_protocol_version"
    ):
        raise RuntimeError("Corpus protocol version mismatch")

    base_columns = [
        "repo_id",
        "repository",
        "domain",
        "cohort",
        "commit_sha",
        "frozen_commit_sha",
        "commit_matches_frozen",
        "scan_subpath",
        "target_files",
        "target_manifest_sha256",
        "bandit_findings",
        "bandit_errors",
        "semgrep_findings",
        "semgrep_errors",
    ]

    missing_base = [column for column in base_columns if column not in scan.columns]

    if missing_base:
        raise RuntimeError(
            "scan_manifest.csv is missing required columns: "
            + ", ".join(missing_base)
        )

    frozen = scan[base_columns].copy()

    scoped_columns = [
        column
        for column in [
            "repo_id",
            "original_repository",
            "repair_action",
            "repair_reason",
            "remote_verified",
            "scope_reason",
        ]
        if column in scoped.columns
    ]

    if len(scoped_columns) > 1:
        frozen = frozen.merge(
            scoped[scoped_columns],
            on="repo_id",
            how="left",
            validate="one_to_one",
        )

    coverage_columns = [
        "repo_id",
        "candidate_target_files",
        "bandit_parse_incompatibilities",
        "semgrep_parse_incompatibilities",
        "cross_scanner_incompatible_files",
        "effective_cross_scanner_files",
        "bandit_runtime_or_unmapped_errors",
        "semgrep_runtime_or_unmapped_errors",
        "coverage_complete",
    ]

    frozen = frozen.merge(
        coverage[coverage_columns],
        on="repo_id",
        how="left",
        validate="one_to_one",
    )

    frozen = frozen.sort_values("repo_id").reset_index(drop=True)

    output_xlsx = Path(args.output_xlsx).resolve()
    output_csv = Path(args.output_csv).resolve()
    metadata_path = Path(args.metadata).resolve()

    output_xlsx.parent.mkdir(parents=True, exist_ok=True)
    frozen.to_excel(output_xlsx, index=False)
    frozen.to_csv(output_csv, index=False)

    metadata = {
        "snapshot_version": "v6",
        "source_run_id": args.run_id,
        "repository_count": len(frozen),
        "unique_repository_count": int(frozen["repository"].nunique()),
        "all_commits_match_frozen_manifest": True,
        "scanner_protocol_version": scanner_summary.get("scanner_protocol_version"),
        "coverage_protocol_version": coverage_summary.get("coverage_protocol_version"),
        "corpus_protocol_version": scanner_summary.get("corpus_protocol_version"),
        "repository_revision_policy": scanner_summary.get("repository_revision_policy"),
        "repository_scope_policy": scanner_summary.get("repository_scope_policy"),
        "scoped_repositories": scanner_summary.get("scoped_repositories"),
        "bandit_version": scanner_summary.get("bandit_version"),
        "semgrep_version": scanner_summary.get("semgrep_version"),
        "bandit_config_sha256": scanner_summary.get("bandit_config_sha256"),
        "semgrep_config_sha256": scanner_summary.get("semgrep_config_sha256"),
        "total_scanner_alerts": scanner_summary.get("total_scanner_alerts"),
        "total_canonical_findings": scanner_summary.get("total_canonical_findings"),
        "cross_scanner_duplicate_alerts": scanner_summary.get(
            "cross_scanner_duplicate_alerts"
        ),
        "candidate_target_files": coverage_summary.get("candidate_target_files"),
        "effective_cross_scanner_files": coverage_summary.get(
            "effective_cross_scanner_files"
        ),
        "cross_scanner_incompatible_files": coverage_summary.get(
            "cross_scanner_incompatible_files"
        ),
        "bandit_parse_incompatibilities": coverage_summary.get(
            "bandit_parse_incompatibilities"
        ),
        "semgrep_parse_incompatibilities": coverage_summary.get(
            "semgrep_parse_incompatibilities"
        ),
        "bandit_runtime_or_unmapped_errors": coverage_summary.get(
            "bandit_runtime_or_unmapped_errors"
        ),
        "semgrep_runtime_or_unmapped_errors": coverage_summary.get(
            "semgrep_runtime_or_unmapped_errors"
        ),
        "coverage_audit_complete": coverage_summary.get("coverage_audit_complete"),
        "finding_unit": scanner_summary.get("finding_unit"),
        "targeting_strategy": scanner_summary.get("targeting_strategy"),
        "raw_scanner_alerts_preserved": scanner_summary.get(
            "raw_scanner_alerts_preserved"
        ),
    }

    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "snapshot_rows": len(frozen),
                "unique_repositories": int(frozen["repository"].nunique()),
                "unique_commit_shas": int(frozen["commit_sha"].nunique()),
                "all_repositories_successful": True,
                "all_commits_match_frozen_manifest": True,
                "coverage_audit_complete": True,
                "candidate_target_files": int(
                    frozen["candidate_target_files"].sum()
                ),
                "effective_cross_scanner_files": int(
                    frozen["effective_cross_scanner_files"].sum()
                ),
                "output_xlsx": str(output_xlsx),
                "output_csv": str(output_csv),
                "metadata": str(metadata_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
