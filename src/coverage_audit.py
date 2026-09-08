import argparse
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
GENERATED_ROOT = PROJECT_ROOT / "data" / "generated" / "runs"
REPOSITORY_CACHE = PROJECT_ROOT / "data" / "generated" / "repositories"
RESULTS_ROOT = PROJECT_ROOT / "results_generated"


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save_json(path, value):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def repository_folder(repository):
    return str(repository).replace("/", "__")


def normalize_path(path_value, repository_root):
    if not path_value:
        return ""

    value = str(path_value).replace("\\", "/")
    candidate = Path(path_value)

    try:
        if candidate.is_absolute():
            return (
                candidate.resolve()
                .relative_to(Path(repository_root).resolve())
                .as_posix()
            )
    except (OSError, ValueError):
        pass

    root = Path(repository_root).resolve().as_posix().rstrip("/") + "/"

    if value.startswith(root):
        value = value[len(root):]

    marker = "/data/generated/repositories/"
    normalized_root = root.replace("\\", "/")

    if marker in normalized_root and marker in value:
        suffix = value.split(marker, 1)[1]
        parts = suffix.split("/", 1)
        if len(parts) == 2:
            value = parts[1]

    return value.lstrip("./")


def error_fields(error):
    if isinstance(error, dict):
        error_type = str(error.get("type", ""))
        message = str(
            error.get(
                "message",
                error.get("reason", ""),
            )
        )
        path_value = str(
            error.get(
                "path",
                error.get("filename", ""),
            )
            or ""
        )
        code = error.get("code", "")
        level = str(error.get("level", ""))
        return error_type, message, path_value, code, level

    return "", str(error), "", "", ""


def is_parser_error(error_type, message):
    text = f"{error_type} {message}".casefold()
    markers = (
        "syntax error",
        "syntaxerror",
        "parse error",
        "parsing error",
        "failed to parse",
        "could not parse",
        "invalid syntax",
    )
    return any(marker in text for marker in markers)


def collect_error_rows(
    scanner,
    report,
    repo_id,
    repository,
    commit_sha,
    repository_root,
    target_files,
):
    rows = []
    parser_files = set()
    runtime_errors = 0

    for error in report.get("errors", []):
        error_type, message, path_value, code, level = error_fields(error)
        relative_path = normalize_path(path_value, repository_root)
        parser_error = is_parser_error(error_type, message)
        in_target_manifest = relative_path in target_files if relative_path else False

        if parser_error and in_target_manifest:
            classification = "parser_incompatibility"
            parser_files.add(relative_path)
        elif parser_error:
            classification = "parser_error_unmapped"
            runtime_errors += 1
        else:
            classification = "runtime_or_other_error"
            runtime_errors += 1

        rows.append(
            {
                "repo_id": repo_id,
                "repository": repository,
                "commit_sha": commit_sha,
                "scanner": scanner,
                "classification": classification,
                "filename": relative_path,
                "in_target_manifest": in_target_manifest,
                "error_type": error_type,
                "error_code": code,
                "level": level,
                "message": message,
            }
        )

    return rows, parser_files, runtime_errors


def add_coverage_column(dataframe, incompatible_keys):
    result = dataframe.copy()

    if result.empty:
        result["coverage_comparable"] = pd.Series(dtype="boolean")
        return result

    result["coverage_comparable"] = [
        (str(repo_id), str(filename)) not in incompatible_keys
        for repo_id, filename in zip(
            result["repo_id"],
            result["filename"],
        )
    ]
    result["coverage_comparable"] = result["coverage_comparable"].astype(
        "boolean"
    )
    return result


def audit_run(run_id):
    run_root = GENERATED_ROOT / run_id
    processed_root = run_root / "processed"
    result_root = RESULTS_ROOT / run_id
    scan_manifest_path = processed_root / "scan_manifest.csv"

    if not scan_manifest_path.exists():
        raise FileNotFoundError(
            f"Scan manifest not found: {scan_manifest_path}"
        )

    scan_manifest = pd.read_csv(scan_manifest_path)
    coverage_rows = []
    error_rows = []
    incompatible_keys = set()

    for _, scan_row in scan_manifest.iterrows():
        repo_id = str(scan_row["repo_id"])
        repository = str(scan_row["repository"])
        status = str(scan_row["status"])
        commit_sha = str(scan_row.get("commit_sha", ""))
        raw_root = run_root / "raw" / repo_id
        target_manifest_path = raw_root / "target_manifest.json"

        coverage_row = {
            "repo_id": repo_id,
            "repository": repository,
            "commit_sha": commit_sha,
            "status": status,
            "candidate_target_files": 0,
            "bandit_parse_incompatibilities": 0,
            "semgrep_parse_incompatibilities": 0,
            "cross_scanner_incompatible_files": 0,
            "effective_cross_scanner_files": 0,
            "bandit_runtime_or_unmapped_errors": 0,
            "semgrep_runtime_or_unmapped_errors": 0,
            "coverage_complete": False,
        }

        if status != "SUCCESS" or not target_manifest_path.exists():
            coverage_rows.append(coverage_row)
            continue

        target_manifest = load_json(target_manifest_path)
        target_files = set(
            str(value) for value in target_manifest.get("files", [])
        )
        repository_root = (
            REPOSITORY_CACHE / repository_folder(repository)
        ).resolve()

        bandit_path = raw_root / "bandit.json"
        semgrep_path = raw_root / "semgrep.json"

        if not bandit_path.exists() or not semgrep_path.exists():
            coverage_rows.append(coverage_row)
            continue

        bandit_report = load_json(bandit_path)
        semgrep_report = load_json(semgrep_path)

        bandit_rows, bandit_parser_files, bandit_runtime = (
            collect_error_rows(
                "Bandit",
                bandit_report,
                repo_id,
                repository,
                commit_sha,
                repository_root,
                target_files,
            )
        )

        semgrep_rows, semgrep_parser_files, semgrep_runtime = (
            collect_error_rows(
                "Semgrep",
                semgrep_report,
                repo_id,
                repository,
                commit_sha,
                repository_root,
                target_files,
            )
        )

        error_rows.extend(bandit_rows)
        error_rows.extend(semgrep_rows)

        incompatible_files = bandit_parser_files | semgrep_parser_files

        for filename in incompatible_files:
            incompatible_keys.add((repo_id, filename))

        candidate_count = len(target_files)
        effective_count = candidate_count - len(incompatible_files)

        coverage_row.update(
            {
                "candidate_target_files": candidate_count,
                "bandit_parse_incompatibilities": len(
                    bandit_parser_files
                ),
                "semgrep_parse_incompatibilities": len(
                    semgrep_parser_files
                ),
                "cross_scanner_incompatible_files": len(
                    incompatible_files
                ),
                "effective_cross_scanner_files": effective_count,
                "bandit_runtime_or_unmapped_errors": bandit_runtime,
                "semgrep_runtime_or_unmapped_errors": semgrep_runtime,
                "coverage_complete": (
                    bandit_runtime == 0 and semgrep_runtime == 0
                ),
            }
        )

        coverage_rows.append(coverage_row)

    coverage_df = pd.DataFrame(coverage_rows)
    errors_df = pd.DataFrame(
        error_rows,
        columns=[
            "repo_id",
            "repository",
            "commit_sha",
            "scanner",
            "classification",
            "filename",
            "in_target_manifest",
            "error_type",
            "error_code",
            "level",
            "message",
        ],
    )

    coverage_df.to_csv(
        processed_root / "coverage_by_repository.csv",
        index=False,
    )
    errors_df.to_csv(
        processed_root / "scanner_coverage_errors.csv",
        index=False,
    )

    parser_df = errors_df[
        errors_df["classification"] == "parser_incompatibility"
    ].copy()

    parser_df.to_csv(
        processed_root / "parser_incompatibilities.csv",
        index=False,
    )

    scanner_alerts_path = processed_root / "scanner_alerts.csv"
    canonical_findings_path = processed_root / "canonical_findings.csv"

    comparable_alerts = 0
    noncomparable_alerts = 0
    comparable_findings = 0
    noncomparable_findings = 0

    if scanner_alerts_path.exists():
        scanner_alerts = pd.read_csv(scanner_alerts_path)
        scanner_with_coverage = add_coverage_column(
            scanner_alerts,
            incompatible_keys,
        )
        scanner_with_coverage.to_csv(
            processed_root / "scanner_alerts_with_coverage.csv",
            index=False,
        )
        scanner_with_coverage[
            scanner_with_coverage["coverage_comparable"]
        ].to_csv(
            processed_root / "scanner_alerts_comparable.csv",
            index=False,
        )
        comparable_alerts = int(
            scanner_with_coverage["coverage_comparable"].sum()
        )
        noncomparable_alerts = int(
            (~scanner_with_coverage["coverage_comparable"]).sum()
        )

    if canonical_findings_path.exists():
        canonical_findings = pd.read_csv(canonical_findings_path)
        canonical_with_coverage = add_coverage_column(
            canonical_findings,
            incompatible_keys,
        )
        canonical_with_coverage.to_csv(
            processed_root / "canonical_findings_with_coverage.csv",
            index=False,
        )
        canonical_with_coverage[
            canonical_with_coverage["coverage_comparable"]
        ].to_csv(
            processed_root / "canonical_findings_comparable.csv",
            index=False,
        )
        comparable_findings = int(
            canonical_with_coverage["coverage_comparable"].sum()
        )
        noncomparable_findings = int(
            (~canonical_with_coverage["coverage_comparable"]).sum()
        )

    successful = int(
        (scan_manifest["status"].astype(str) == "SUCCESS").sum()
    )
    failed = int(
        (scan_manifest["status"].astype(str) != "SUCCESS").sum()
    )
    candidate_total = int(
        coverage_df["candidate_target_files"].sum()
    )
    effective_total = int(
        coverage_df["effective_cross_scanner_files"].sum()
    )
    bandit_parser_total = int(
        coverage_df["bandit_parse_incompatibilities"].sum()
    )
    semgrep_parser_total = int(
        coverage_df["semgrep_parse_incompatibilities"].sum()
    )
    incompatible_total = int(
        coverage_df["cross_scanner_incompatible_files"].sum()
    )
    bandit_runtime_total = int(
        coverage_df["bandit_runtime_or_unmapped_errors"].sum()
    )
    semgrep_runtime_total = int(
        coverage_df["semgrep_runtime_or_unmapped_errors"].sum()
    )
    repositories_with_parser_limits = int(
        (
            coverage_df["cross_scanner_incompatible_files"] > 0
        ).sum()
    )

    summary = {
        "run_id": run_id,
        "coverage_protocol_version": "1.0.0",
        "repositories_requested": len(scan_manifest),
        "repositories_successful": successful,
        "repositories_failed": failed,
        "candidate_target_files": candidate_total,
        "bandit_parse_incompatibilities": bandit_parser_total,
        "semgrep_parse_incompatibilities": semgrep_parser_total,
        "cross_scanner_incompatible_files": incompatible_total,
        "effective_cross_scanner_files": effective_total,
        "repositories_with_parser_incompatibilities": (
            repositories_with_parser_limits
        ),
        "bandit_runtime_or_unmapped_errors": bandit_runtime_total,
        "semgrep_runtime_or_unmapped_errors": semgrep_runtime_total,
        "comparable_scanner_alerts": comparable_alerts,
        "noncomparable_scanner_alerts": noncomparable_alerts,
        "comparable_canonical_findings": comparable_findings,
        "noncomparable_canonical_findings": noncomparable_findings,
        "coverage_audit_complete": (
            failed == 0
            and bandit_runtime_total == 0
            and semgrep_runtime_total == 0
        ),
        "coverage_policy": (
            "Any target file with a scanner parser incompatibility is "
            "retained in raw evidence but excluded from cross-scanner "
            "comparable outputs."
        ),
    }

    save_json(
        result_root / "coverage_summary.json",
        summary,
    )

    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    audit_run(args.run_id)


if __name__ == "__main__":
    main()
