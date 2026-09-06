import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pandas as pd

from ast_slicer import PythonProgramSlicer
from alert_canonicalizer import canonicalize_alerts
from bandit_engine import get_bandit_tests, get_bandit_version, run_bandit
from semgrep_engine import get_semgrep_rule_ids, get_semgrep_version, run_semgrep
from scan_scope import collect_python_targets, relative_target_manifest, target_manifest_sha256


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "curated_100_repositories.xlsx"
DEFAULT_BANDIT_CONFIG = PROJECT_ROOT / "config" / "bandit.yaml"
DEFAULT_SEMGREP_CONFIG = PROJECT_ROOT / "config" / "semgrep-python-security.yml"
PROTOCOL_FILE = PROJECT_ROOT / "config" / "scanner_protocol.json"
REPOSITORY_CACHE = PROJECT_ROOT / "data" / "generated" / "repositories"
GENERATED_ROOT = PROJECT_ROOT / "data" / "generated" / "runs"
RESULTS_ROOT = PROJECT_ROOT / "results_generated"
REQUIRED_COLUMNS = {"repo_id", "repository", "domain", "cohort"}
PRODUCTION_EXCLUDES = (
    "tests",
    "test",
    "testing",
    "docs",
    "doc",
    "examples",
    "example",
    "benchmarks",
    "benchmark",
    ".venv",
    "venv",
    "build",
    "dist",
)


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_scanner_protocol(bandit_config, semgrep_config):
    if not PROTOCOL_FILE.exists():
        raise FileNotFoundError(f"Scanner protocol not found: {PROTOCOL_FILE}")

    protocol = json.loads(PROTOCOL_FILE.read_text(encoding="utf-8"))

    if protocol.get("targeting_strategy") != "shared_python_file_manifest":
        raise RuntimeError("Unsupported scanner targeting strategy")

    required_bandit = protocol.get("bandit", {}).get("required_version")
    required_semgrep = protocol.get("semgrep", {}).get("required_version")
    installed_bandit = get_bandit_version()
    installed_semgrep = get_semgrep_version()

    if required_bandit and installed_bandit != required_bandit:
        raise RuntimeError(
            f"Bandit version mismatch: required {required_bandit}, installed {installed_bandit}"
        )

    if required_semgrep and installed_semgrep != required_semgrep:
        raise RuntimeError(
            f"Semgrep version mismatch: required {required_semgrep}, installed {installed_semgrep}"
        )

    bandit_path = Path(bandit_config).resolve()
    semgrep_path = Path(semgrep_config).resolve()

    if not bandit_path.exists():
        raise FileNotFoundError(f"Bandit config not found: {bandit_path}")

    if not semgrep_path.exists():
        raise FileNotFoundError(f"Semgrep config not found: {semgrep_path}")

    bandit_hash = file_sha256(bandit_path)
    semgrep_hash = file_sha256(semgrep_path)

    if bandit_path == DEFAULT_BANDIT_CONFIG.resolve():
        expected = protocol.get("bandit_config_sha256")
        if expected and bandit_hash != expected:
            raise RuntimeError(
                "Bandit config hash does not match scanner_protocol.json"
            )

    if semgrep_path == DEFAULT_SEMGREP_CONFIG.resolve():
        expected = protocol.get("semgrep_config_sha256")
        if expected and semgrep_hash != expected:
            raise RuntimeError(
                "Semgrep config hash does not match scanner_protocol.json"
            )

    return protocol, bandit_hash, semgrep_hash

def run_git(arguments, cwd=None):
    command = ["git", *arguments]
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Git command failed: {' '.join(command)}\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def repository_url(repository, transport):
    if transport == "ssh443":
        return f"ssh://git@ssh.github.com:443/{repository}.git"
    return f"https://github.com/{repository}.git"


def repository_folder(repository):
    return repository.replace("/", "__")


def clone_or_update_repository(repository, transport, refresh=False):
    REPOSITORY_CACHE.mkdir(parents=True, exist_ok=True)
    destination = REPOSITORY_CACHE / repository_folder(repository)

    if destination.exists() and not (destination / ".git").exists():
        shutil.rmtree(destination)

    if not destination.exists():
        run_git(
            [
                "clone",
                "--depth",
                "1",
                "--no-tags",
                repository_url(repository, transport),
                str(destination),
            ]
        )
    elif refresh:
        run_git(["fetch", "--depth", "1", "origin"], cwd=destination)
        default_branch = run_git(
            ["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
            cwd=destination,
        ).removeprefix("origin/")
        run_git(["checkout", default_branch], cwd=destination)
        run_git(["reset", "--hard", f"origin/{default_branch}"], cwd=destination)

    commit_sha = run_git(["rev-parse", "HEAD"], cwd=destination)
    return destination.resolve(), commit_sha


def normalize_relative_path(path_value, repository_path):
    if not path_value:
        return ""

    candidate = Path(path_value)

    try:
        if candidate.is_absolute():
            return candidate.resolve().relative_to(repository_path.resolve()).as_posix()
    except (OSError, ValueError):
        pass

    normalized = str(path_value).replace("\\", "/")
    root = repository_path.as_posix().rstrip("/") + "/"

    if normalized.startswith(root):
        normalized = normalized[len(root):]

    return normalized.lstrip("./")


def source_path(repository_path, relative_path):
    candidate = repository_path / Path(relative_path)
    return candidate.resolve()


def code_context(repository_path, relative_path, line_number, window=3):
    if not relative_path or not line_number:
        return ""

    path = source_path(repository_path, relative_path)

    if not path.exists() or not path.is_file():
        return ""

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ""

    start = max(0, int(line_number) - 1 - window)
    end = min(len(lines), int(line_number) + window)
    return "\n".join(lines[start:end])


def extract_cwe(value):
    if value is None:
        return "CWE-UNKNOWN"

    if isinstance(value, (list, tuple, set)):
        for item in value:
            cwe = extract_cwe(item)
            if cwe != "CWE-UNKNOWN":
                return cwe
        return "CWE-UNKNOWN"

    if isinstance(value, dict):
        if "id" in value:
            return f"CWE-{value['id']}"
        return "CWE-UNKNOWN"

    match = re.search(r"CWE[-\s:]*(\d+)", str(value), flags=re.IGNORECASE)
    if match:
        return f"CWE-{match.group(1)}"

    if str(value).isdigit():
        return f"CWE-{value}"

    return "CWE-UNKNOWN"


def bandit_alerts(report, row, repository_path, commit_sha):
    results = sorted(
        report.get("results", []),
        key=lambda item: (
            str(item.get("filename", "")),
            int(item.get("line_number", 0) or 0),
            str(item.get("test_id", "")),
        ),
    )

    alerts = []

    for item in results:
        relative_path = normalize_relative_path(
            item.get("filename", ""),
            repository_path,
        )
        line_number = int(item.get("line_number", 0) or 0)

        alerts.append(
            {
                "repo_id": str(row["repo_id"]),
                "repository": str(row["repository"]),
                "commit_sha": commit_sha,
                "domain": str(row["domain"]),
                "cohort": str(row["cohort"]),
                "scanner": "Bandit",
                "rule_id": str(item.get("test_id", "")),
                "rule_name": str(item.get("test_name", "")),
                "cwe_id": extract_cwe(item.get("issue_cwe")),
                "severity": str(item.get("issue_severity", "")),
                "confidence": str(item.get("issue_confidence", "")),
                "filename": relative_path,
                "line_number": line_number,
                "message": str(item.get("issue_text", "")),
                "code_snippet": code_context(
                    repository_path,
                    relative_path,
                    line_number,
                ),
            }
        )

    return alerts


def semgrep_alerts(report, row, repository_path, commit_sha):
    results = sorted(
        report.get("results", []),
        key=lambda item: (
            str(item.get("path", "")),
            int((item.get("start") or {}).get("line", 0) or 0),
            str(item.get("check_id", "")),
        ),
    )

    alerts = []

    for item in results:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        relative_path = normalize_relative_path(
            item.get("path", ""),
            repository_path,
        )
        line_number = int((item.get("start") or {}).get("line", 0) or 0)

        alerts.append(
            {
                "repo_id": str(row["repo_id"]),
                "repository": str(row["repository"]),
                "commit_sha": commit_sha,
                "domain": str(row["domain"]),
                "cohort": str(row["cohort"]),
                "scanner": "Semgrep",
                "rule_id": str(item.get("check_id", "")),
                "rule_name": str(item.get("check_id", "")),
                "cwe_id": extract_cwe(metadata.get("cwe")),
                "severity": str(extra.get("severity", "")),
                "confidence": str(metadata.get("confidence", "")),
                "filename": relative_path,
                "line_number": line_number,
                "message": str(extra.get("message", "")),
                "code_snippet": code_context(
                    repository_path,
                    relative_path,
                    line_number,
                ),
            }
        )

    return alerts


def validate_manifest(dataframe):
    missing = REQUIRED_COLUMNS.difference(dataframe.columns)
    if missing:
        raise ValueError(
            "Manifest is missing required columns: "
            + ", ".join(sorted(missing))
        )

    repositories = dataframe["repository"].astype(str)
    duplicates = repositories[repositories.duplicated()].tolist()

    if duplicates:
        raise ValueError(
            "Manifest contains duplicate repositories: "
            + ", ".join(sorted(set(duplicates)))
        )


def load_manifest(path, selected_repositories=None, limit=None):
    manifest_path = Path(path).resolve()

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    if manifest_path.suffix.lower() == ".xlsx":
        dataframe = pd.read_excel(manifest_path)
    elif manifest_path.suffix.lower() == ".csv":
        dataframe = pd.read_csv(manifest_path)
    else:
        raise ValueError("Manifest must be .xlsx or .csv")

    validate_manifest(dataframe)

    if "inclusion_status" in dataframe.columns:
        dataframe = dataframe[
            dataframe["inclusion_status"].astype(str).str.upper() == "INCLUDED"
        ]

    if selected_repositories:
        selected = set(selected_repositories)
        dataframe = dataframe[
            dataframe["repository"].astype(str).isin(selected)
        ]

    if limit is not None:
        dataframe = dataframe.head(limit)

    return dataframe.reset_index(drop=True)


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def proportional_sample(dataframe, sample_size, seed, id_column):
    if dataframe.empty or sample_size <= 0:
        return dataframe.head(0).copy()

    if len(dataframe) <= sample_size:
        return dataframe.copy()

    counts = dataframe["cwe_id"].value_counts().sort_index()
    exact = counts / counts.sum() * sample_size
    quotas = exact.apply(int)
    remaining = sample_size - int(quotas.sum())

    if remaining > 0:
        remainders = (exact - quotas).sort_values(ascending=False)
        for cwe_id in remainders.index[:remaining]:
            quotas.loc[cwe_id] += 1

    samples = []

    for index, (cwe_id, quota) in enumerate(quotas.items()):
        if quota <= 0:
            continue

        group = dataframe[dataframe["cwe_id"] == cwe_id]
        quota = min(int(quota), len(group))

        samples.append(
            group.sample(
                n=quota,
                random_state=seed + index,
            )
        )

    result = pd.concat(samples, ignore_index=True)

    if len(result) < sample_size:
        used = set(result[id_column])
        remaining_rows = dataframe[~dataframe[id_column].isin(used)]
        needed = min(sample_size - len(result), len(remaining_rows))

        if needed:
            result = pd.concat(
                [
                    result,
                    remaining_rows.sample(
                        n=needed,
                        random_state=seed + 10000,
                    ),
                ],
                ignore_index=True,
            )

    return result.head(sample_size)


def generate_slices(alerts, repository_locations):
    sliced = []

    for alert in alerts:
        repository = alert["repository"]
        filename = alert["filename"]
        line_number = alert["line_number"]
        repository_path = repository_locations.get(repository)

        item = {
            "alert_id": alert["alert_id"],
            "repo_id": alert["repo_id"],
            "repository": repository,
            "commit_sha": alert["commit_sha"],
            "scanner": alert["scanner"],
            "rule_id": alert["rule_id"],
            "cwe_id": alert["cwe_id"],
            "filename": filename,
            "target_line": line_number,
        }

        if not repository_path or not filename or not line_number:
            item["slice_error"] = "Source location unavailable"
            sliced.append(item)
            continue

        path = source_path(repository_path, filename)

        try:
            slicer = PythonProgramSlicer(path)
            variant_a = slicer.extract_variant_a(line_number)
            variant_b = slicer.extract_variant_b(line_number)
            variant_c = slicer.extract_variant_c(line_number)

            item["variant_a_code"] = variant_a["code"]
            item["variant_b_code"] = variant_b["code"]
            item["variant_c_code"] = variant_c["code"]
        except Exception as exc:
            item["slice_error"] = f"{type(exc).__name__}: {exc}"

        sliced.append(item)

    return sliced



def scan_excludes(scope, extra_excludes):
    extra = list(extra_excludes or [])

    if scope == "all":
        return extra

    excludes = list(PRODUCTION_EXCLUDES)
    excludes.extend(extra)
    return excludes


def run_pipeline(args):
    protocol, bandit_config_hash, semgrep_config_hash = validate_scanner_protocol(
        args.bandit_config,
        args.semgrep_config,
    )

    manifest = load_manifest(
        args.manifest,
        selected_repositories=args.repo,
        limit=args.limit,
    )

    if manifest.empty:
        raise RuntimeError("No repositories selected from the manifest")

    run_root = GENERATED_ROOT / args.run_id
    raw_root = run_root / "raw"
    processed_root = run_root / "processed"
    result_root = RESULTS_ROOT / args.run_id

    raw_root.mkdir(parents=True, exist_ok=True)
    processed_root.mkdir(parents=True, exist_ok=True)
    result_root.mkdir(parents=True, exist_ok=True)

    all_alerts = []
    scan_rows = []
    repository_locations = {}
    excluded_directories = scan_excludes(
        args.scope,
        args.exclude,
    )

    for _, row in manifest.iterrows():
        repository = str(row["repository"])
        repo_id = str(row["repo_id"])
        repo_raw_dir = raw_root / repo_id
        repo_raw_dir.mkdir(parents=True, exist_ok=True)

        scan_record = {
            "repo_id": repo_id,
            "repository": repository,
            "domain": str(row["domain"]),
            "cohort": str(row["cohort"]),
            "status": "FAILED",
            "commit_sha": "",
            "bandit_findings": 0,
            "bandit_errors": 0,
            "semgrep_findings": 0,
            "semgrep_errors": 0,
            "target_files": 0,
            "target_manifest_sha256": "",
            "error": "",
        }

        print(f"[{repo_id}] {repository}")

        try:
            repository_path, commit_sha = clone_or_update_repository(
                repository,
                args.transport,
                refresh=args.refresh,
            )
            repository_locations[repository] = repository_path
            scan_record["commit_sha"] = commit_sha

            targets = collect_python_targets(
                repository_path,
                excluded_directories,
            )
            relative_targets = relative_target_manifest(
                repository_path,
                targets,
            )
            target_hash = target_manifest_sha256(relative_targets)

            scan_record["target_files"] = len(targets)
            scan_record["target_manifest_sha256"] = target_hash

            save_json(
                repo_raw_dir / "target_manifest.json",
                {
                    "repository": repository,
                    "commit_sha": commit_sha,
                    "targeting_strategy": "shared_python_file_manifest",
                    "target_files": len(relative_targets),
                    "target_manifest_sha256": target_hash,
                    "excluded_directory_names": excluded_directories,
                    "files": relative_targets,
                },
            )

            bandit_report = run_bandit(
                targets,
                output_json=repo_raw_dir / "bandit.json",
                config=args.bandit_config,
                tests=protocol["bandit"]["tests"],
            )

            semgrep_report = run_semgrep(
                targets,
                output_json=repo_raw_dir / "semgrep.json",
                config=args.semgrep_config,
            )

            current_alerts = []
            current_alerts.extend(
                bandit_alerts(
                    bandit_report,
                    row,
                    repository_path,
                    commit_sha,
                )
            )
            current_alerts.extend(
                semgrep_alerts(
                    semgrep_report,
                    row,
                    repository_path,
                    commit_sha,
                )
            )

            scan_record["bandit_findings"] = len(
                bandit_report.get("results", [])
            )
            scan_record["bandit_errors"] = len(
                bandit_report.get("errors", [])
            )
            scan_record["semgrep_findings"] = len(
                semgrep_report.get("results", [])
            )
            scan_record["semgrep_errors"] = len(
                semgrep_report.get("errors", [])
            )
            scan_record["status"] = "SUCCESS"
            all_alerts.extend(current_alerts)

            save_json(
                repo_raw_dir / "metadata.json",
                {
                    **scan_record,
                    "bandit_version": get_bandit_version(),
                    "semgrep_version": get_semgrep_version(),
                    "transport": args.transport,
                    "bandit_config": str(Path(args.bandit_config).resolve()),
                    "bandit_config_sha256": bandit_config_hash,
                    "semgrep_config": str(Path(args.semgrep_config).resolve()),
                    "semgrep_config_sha256": semgrep_config_hash,
                    "scanner_protocol_version": protocol.get("protocol_version"),
                    "targeting_strategy": "shared_python_file_manifest",
                    "scope": args.scope,
                    "excluded_directory_names": excluded_directories,
                    "target_file_extension": ".py",
                },
            )

            print(
                f"  Bandit={scan_record['bandit_findings']} "
                f"BanditErrors={scan_record['bandit_errors']} "
                f"Semgrep={scan_record['semgrep_findings']} "
                f"SemgrepErrors={scan_record['semgrep_errors']} "
                f"TargetFiles={scan_record['target_files']} "
                f"SHA={commit_sha[:12]}"
            )
        except Exception as exc:
            scan_record["error"] = f"{type(exc).__name__}: {exc}"
            save_json(repo_raw_dir / "failure.json", scan_record)
            print(f"  FAILED: {scan_record['error']}")

            if args.fail_fast:
                scan_rows.append(scan_record)
                raise

        scan_rows.append(scan_record)

    for index, alert in enumerate(all_alerts, start=1):
        alert["alert_id"] = f"ALT-{index:06d}"

    enriched_alerts, canonical_findings = canonicalize_alerts(
        all_alerts,
        repository_locations,
    )

    scan_manifest = pd.DataFrame(scan_rows)
    scan_manifest.to_csv(
        processed_root / "scan_manifest.csv",
        index=False,
    )

    save_json(
        processed_root / "raw_alerts_unified.json",
        {
            "total_alerts": len(enriched_alerts),
            "alerts": enriched_alerts,
        },
    )

    alerts_df = pd.DataFrame(enriched_alerts)
    canonical_df = pd.DataFrame(canonical_findings)

    if not alerts_df.empty:
        alerts_df.to_csv(
            processed_root / "scanner_alerts.csv",
            index=False,
        )
        alerts_df.to_csv(
            processed_root / "alerts_unified.csv",
            index=False,
        )

    if not canonical_df.empty:
        canonical_df.to_csv(
            processed_root / "canonical_findings.csv",
            index=False,
        )

    if not alerts_df.empty:

        cwe_distribution = (
            alerts_df.groupby(["cwe_id", "scanner"])
            .size()
            .reset_index(name="alert_count")
        )
        cwe_distribution["percentage"] = (
            cwe_distribution["alert_count"] / len(alerts_df) * 100
        ).round(2)
        cwe_distribution.to_csv(
            result_root / "alert_distribution_by_cwe.csv",
            index=False,
        )

        domain_distribution = (
            alerts_df.groupby(["domain", "scanner"])
            .size()
            .reset_index(name="alert_count")
        )
        domain_distribution["percentage"] = (
            domain_distribution["alert_count"] / len(alerts_df) * 100
        ).round(2)
        domain_distribution.to_csv(
            result_root / "alert_distribution_by_domain.csv",
            index=False,
        )

        cohort_distribution = (
            alerts_df.groupby(["cohort", "scanner"])
            .size()
            .reset_index(name="alert_count")
        )
        cohort_distribution.to_csv(
            result_root / "alert_distribution_by_cohort.csv",
            index=False,
        )

        if not args.skip_slicing:
            slice_inputs = []
            for finding in canonical_findings:
                slice_inputs.append(
                    {
                        "alert_id": finding["finding_id"],
                        "repo_id": finding["repo_id"],
                        "repository": finding["repository"],
                        "commit_sha": finding["commit_sha"],
                        "scanner": finding["scanners"],
                        "rule_id": finding["rule_ids"],
                        "cwe_id": finding["cwe_id"],
                        "filename": finding["filename"],
                        "line_number": finding["statement_start"],
                    }
                )
            slices = generate_slices(
                slice_inputs,
                repository_locations,
            )
            save_json(
                processed_root / "sliced_contexts.json",
                {
                    "total_slices": len(slices),
                    "slices": slices,
                },
            )

    if not canonical_df.empty:
        canonical_cwe_distribution = (
            canonical_df.groupby(["cwe_id", "security_family"])
            .size()
            .reset_index(name="finding_count")
        )
        canonical_cwe_distribution["percentage"] = (
            canonical_cwe_distribution["finding_count"]
            / len(canonical_df)
            * 100
        ).round(2)
        canonical_cwe_distribution.to_csv(
            result_root / "canonical_distribution_by_cwe.csv",
            index=False,
        )

        canonical_domain_distribution = (
            canonical_df.groupby(["domain", "security_family"])
            .size()
            .reset_index(name="finding_count")
        )
        canonical_domain_distribution.to_csv(
            result_root / "canonical_distribution_by_domain.csv",
            index=False,
        )

        annotation_sample = proportional_sample(
            canonical_df,
            min(args.annotation_sample_size, len(canonical_df)),
            args.seed,
            "finding_id",
        )
        annotation_sample["annotator_1_label"] = "PENDING"
        annotation_sample["annotator_2_label"] = "PENDING"
        annotation_sample["adjudicated_label"] = "PENDING"
        annotation_sample["rationale"] = "PENDING"
        annotation_sample.to_csv(
            processed_root / "annotation_sample.csv",
            index=False,
        )

    successful = int((scan_manifest["status"] == "SUCCESS").sum())
    failed = int((scan_manifest["status"] == "FAILED").sum())
    bandit_errors_total = int(scan_manifest["bandit_errors"].sum())
    semgrep_errors_total = int(scan_manifest["semgrep_errors"].sum())
    target_files_total = int(scan_manifest["target_files"].sum())

    summary = {
        "run_id": args.run_id,
        "repositories_requested": len(manifest),
        "repositories_successful": successful,
        "repositories_failed": failed,
        "total_alerts": len(enriched_alerts),
        "total_scanner_alerts": len(enriched_alerts),
        "total_canonical_findings": len(canonical_findings),
        "cross_scanner_duplicate_alerts": len(enriched_alerts) - len(canonical_findings),
        "bandit_errors": bandit_errors_total,
        "semgrep_errors": semgrep_errors_total,
        "bandit_version": get_bandit_version(),
        "semgrep_version": get_semgrep_version(),
        "bandit_config": str(Path(args.bandit_config).resolve()),
        "bandit_config_sha256": bandit_config_hash,
        "semgrep_config": str(Path(args.semgrep_config).resolve()),
        "semgrep_config_sha256": semgrep_config_hash,
        "scanner_protocol_version": protocol.get("protocol_version"),
        "bandit_tests": get_bandit_tests(),
        "semgrep_rule_ids": get_semgrep_rule_ids(),
        "transport": args.transport,
        "scope": args.scope,
        "targeting_strategy": "shared_python_file_manifest",
        "finding_unit": "canonical_source_statement_plus_security_family",
        "raw_scanner_alerts_preserved": True,
        "target_file_extension": ".py",
        "excluded_directory_names": excluded_directories,
        "total_target_files": target_files_total,
    }

    save_json(result_root / "run_summary.json", summary)
    print(json.dumps(summary, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
    )
    parser.add_argument(
        "--run-id",
        default="real_scan",
    )
    parser.add_argument(
        "--transport",
        choices=["https", "ssh443"],
        default="https",
    )
    parser.add_argument(
        "--repo",
        action="append",
    )
    parser.add_argument(
        "--limit",
        type=int,
    )
    parser.add_argument(
        "--bandit-config",
        default=str(DEFAULT_BANDIT_CONFIG),
    )
    parser.add_argument(
        "--semgrep-config",
        default=str(DEFAULT_SEMGREP_CONFIG),
    )
    parser.add_argument(
        "--scope",
        choices=["production", "all"],
        default="production",
    )
    parser.add_argument(
        "--exclude",
        action="append",
    )
    parser.add_argument(
        "--refresh",
        action="store_true",
    )
    parser.add_argument(
        "--skip-slicing",
        action="store_true",
    )
    parser.add_argument(
        "--annotation-sample-size",
        type=int,
        default=300,
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
    )
    args = parser.parse_args()
    run_pipeline(args)


if __name__ == "__main__":
    main()
