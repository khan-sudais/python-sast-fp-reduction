import csv
import hashlib
import json
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
GROUND_TRUTH = DATA_DIR / "annotation_v6" / "final_ground_truth_v6.csv"
REPOSITORY_ROOT = DATA_DIR / "generated" / "repositories"
OUTPUT_DIR = DATA_DIR / "slicing_v6"
SLICES_JSONL = OUTPUT_DIR / "slices_audit_v6.jsonl"
METRICS_CSV = OUTPUT_DIR / "slicing_metrics_v6.csv"
SUMMARY_JSON = OUTPUT_DIR / "slicing_audit_v6.json"


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def repository_folder(repository):
    return repository.replace("/", "__")


def current_commit(repository_path):
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repository_path,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


def code_line_count(code):
    if not code:
        return 0
    return len(code.splitlines())


def main():
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from ast_slicer import PythonProgramSlicer

    if not GROUND_TRUTH.exists():
        raise FileNotFoundError(
            f"Final V6 ground truth not found: {GROUND_TRUTH}"
        )

    rows = read_csv(GROUND_TRUTH)

    if len(rows) != 300:
        raise RuntimeError(
            f"Expected 300 final ground-truth rows, found {len(rows)}"
        )

    finding_ids = [row["finding_id"] for row in rows]

    if len(set(finding_ids)) != 300:
        raise RuntimeError(
            "Final ground truth must contain 300 unique finding IDs"
        )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    records = []
    metrics = []
    missing_repositories = []
    missing_files = []
    commit_mismatches = []
    slice_errors = []
    variant_b_fallbacks = []
    variant_c_zero_callers = []
    variant_c_with_callers = []
    c_depth_counts = Counter()

    for index, row in enumerate(rows, start=1):
        finding_id = row["finding_id"]
        repository = row["repository"]
        expected_commit = row["commit_sha"]
        filename = row["filename"]
        target_line = int(row["line_number"])

        repository_path = (
            REPOSITORY_ROOT / repository_folder(repository)
        ).resolve()

        if not repository_path.exists():
            missing_repositories.append(
                {
                    "finding_id": finding_id,
                    "repository": repository,
                }
            )
            continue

        actual_commit = current_commit(repository_path)

        if actual_commit != expected_commit:
            commit_mismatches.append(
                {
                    "finding_id": finding_id,
                    "repository": repository,
                    "expected": expected_commit,
                    "actual": actual_commit,
                }
            )
            continue

        file_path = (repository_path / filename).resolve()

        try:
            file_path.relative_to(repository_path)
        except ValueError:
            missing_files.append(
                {
                    "finding_id": finding_id,
                    "file": filename,
                    "reason": "path_outside_repository",
                }
            )
            continue

        if not file_path.exists() or not file_path.is_file():
            missing_files.append(
                {
                    "finding_id": finding_id,
                    "file": filename,
                    "reason": "file_missing",
                }
            )
            continue

        try:
            slicer = PythonProgramSlicer(file_path)
            variant_a = slicer.extract_variant_a(target_line)
            variant_b = slicer.extract_variant_b(target_line)
            variant_c = slicer.extract_variant_c(
                target_line,
                max_depth=3,
            )
        except Exception as exc:
            slice_errors.append(
                {
                    "finding_id": finding_id,
                    "repository": repository,
                    "filename": filename,
                    "line_number": target_line,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
            )
            continue

        if variant_b.get("variant") != "B_INTRA_PROCEDURAL_SLICE":
            variant_b_fallbacks.append(finding_id)

        callers = variant_c.get("callers", [])
        call_depth = int(variant_c.get("call_depth", 0) or 0)
        c_depth_counts[call_depth] += 1

        if callers:
            variant_c_with_callers.append(finding_id)
        else:
            variant_c_zero_callers.append(finding_id)

        a_lines = code_line_count(variant_a.get("code", ""))
        b_lines = code_line_count(variant_b.get("code", ""))
        c_lines = code_line_count(variant_c.get("code", ""))

        records.append(
            {
                "annotation_row_id": f"GT-{index:03d}",
                "finding_id": finding_id,
                "repo_id": row["repo_id"],
                "repository": repository,
                "commit_sha": expected_commit,
                "filename": filename,
                "line_number": target_line,
                "security_family": row["security_family"],
                "variant_a": variant_a,
                "variant_b": variant_b,
                "variant_c": variant_c,
            }
        )

        metrics.append(
            {
                "annotation_row_id": f"GT-{index:03d}",
                "finding_id": finding_id,
                "repository": repository,
                "filename": filename,
                "line_number": target_line,
                "security_family": row["security_family"],
                "variant_a_lines": a_lines,
                "variant_b_lines": b_lines,
                "variant_c_lines": c_lines,
                "variant_b_fallback": str(
                    variant_b.get("variant")
                    != "B_INTRA_PROCEDURAL_SLICE"
                ).lower(),
                "variant_c_caller_count": len(callers),
                "variant_c_call_depth": call_depth,
            }
        )

    with SLICES_JSONL.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        for record in records:
            handle.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )

    metric_fields = [
        "annotation_row_id",
        "finding_id",
        "repository",
        "filename",
        "line_number",
        "security_family",
        "variant_a_lines",
        "variant_b_lines",
        "variant_c_lines",
        "variant_b_fallback",
        "variant_c_caller_count",
        "variant_c_call_depth",
    ]

    with METRICS_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=metric_fields,
        )
        writer.writeheader()
        writer.writerows(metrics)

    a_counts = [row["variant_a_lines"] for row in metrics]
    b_counts = [row["variant_b_lines"] for row in metrics]
    c_counts = [row["variant_c_lines"] for row in metrics]

    summary = {
        "slicing_audit_version": "v6",
        "ground_truth_rows": len(rows),
        "ground_truth_sha256": sha256(GROUND_TRUTH),
        "successful_slices": len(records),
        "missing_repository_count": len(missing_repositories),
        "missing_file_count": len(missing_files),
        "commit_mismatch_count": len(commit_mismatches),
        "slice_error_count": len(slice_errors),
        "variant_b_fallback_count": len(variant_b_fallbacks),
        "variant_c_with_callers_count": len(variant_c_with_callers),
        "variant_c_zero_callers_count": len(variant_c_zero_callers),
        "variant_c_call_depth_counts": {
            str(depth): count
            for depth, count in sorted(c_depth_counts.items())
        },
        "variant_a_lines": {
            "min": min(a_counts) if a_counts else None,
            "median": statistics.median(a_counts) if a_counts else None,
            "max": max(a_counts) if a_counts else None,
            "mean": statistics.mean(a_counts) if a_counts else None,
        },
        "variant_b_lines": {
            "min": min(b_counts) if b_counts else None,
            "median": statistics.median(b_counts) if b_counts else None,
            "max": max(b_counts) if b_counts else None,
            "mean": statistics.mean(b_counts) if b_counts else None,
        },
        "variant_c_lines": {
            "min": min(c_counts) if c_counts else None,
            "median": statistics.median(c_counts) if c_counts else None,
            "max": max(c_counts) if c_counts else None,
            "mean": statistics.mean(c_counts) if c_counts else None,
        },
        "variant_c_scope": "same_file_caller_expansion_only",
        "variant_c_is_cross_module": False,
        "variant_c_is_true_taint_analysis": False,
        "missing_repositories": missing_repositories,
        "missing_files": missing_files,
        "commit_mismatches": commit_mismatches,
        "slice_errors": slice_errors,
        "variant_b_fallback_finding_ids": variant_b_fallbacks,
        "outputs": {
            "slices_jsonl": str(SLICES_JSONL),
            "metrics_csv": str(METRICS_CSV),
            "summary_json": str(SUMMARY_JSON),
        },
    }

    SUMMARY_JSON.write_text(
        json.dumps(
            summary,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if (
        len(records) != 300
        or missing_repositories
        or missing_files
        or commit_mismatches
        or slice_errors
    ):
        sys.exit(1)


if __name__ == "__main__":
    main()
