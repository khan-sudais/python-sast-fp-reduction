import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "llm_v6"
RESULTS = DATA_DIR / "qwen_official_results_v6.jsonl"
MANIFEST = DATA_DIR / "llm_experiment_manifest_v6.jsonl"
MANIFEST_METADATA = DATA_DIR / "llm_experiment_manifest_v6_metadata.json"
PROTOCOL = PROJECT_ROOT / "config" / "llm_protocol_v6.json"
OUTPUT_CSV = DATA_DIR / "final_qwen_predictions_v6.csv"
OUTPUT_JSON = DATA_DIR / "final_qwen_predictions_v6.json"
OUTPUT_METADATA = DATA_DIR / "final_qwen_predictions_v6_metadata.json"
ALLOWED_LABELS = {"TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_text_sha256(path):
    text = path.read_text(encoding="utf-8")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def relative_path(path):
    return path.relative_to(PROJECT_ROOT).as_posix()


def read_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"Invalid JSONL at {path}:{line_number}: {exc}"
                ) from exc
    return rows


def project_path(value):
    return PROJECT_ROOT / Path(str(value).replace("\\", "/"))


def usage_values(row):
    usage = row.get("usage") or {}
    input_details = usage.get("input_tokens_details") or {}
    output_details = usage.get("output_tokens_details") or {}
    return {
        "input_tokens": int(usage.get("input_tokens", 0) or 0),
        "cached_tokens": int(input_details.get("cached_tokens", 0) or 0),
        "output_tokens": int(usage.get("output_tokens", 0) or 0),
        "reasoning_tokens": int(output_details.get("reasoning_tokens", 0) or 0),
        "total_tokens": int(usage.get("total_tokens", 0) or 0),
    }


def main():
    for path in [RESULTS, MANIFEST, MANIFEST_METADATA, PROTOCOL]:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    manifest_metadata = json.loads(
        MANIFEST_METADATA.read_text(encoding="utf-8")
    )
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))
    manifest = read_jsonl(MANIFEST)
    result_records = read_jsonl(RESULTS)

    if len(manifest) != 900:
        raise RuntimeError(
            f"Expected 900 manifest requests, found {len(manifest)}"
        )

    protocol_run_sha = manifest_metadata["protocol_sha256"]
    manifest_run_sha = manifest_metadata["manifest_sha256"]
    protocol_canonical_sha = canonical_text_sha256(PROTOCOL)
    manifest_canonical_sha = canonical_text_sha256(MANIFEST)

    if protocol_canonical_sha != manifest_metadata["protocol_canonical_sha256"]:
        raise RuntimeError(
            "Protocol canonical SHA-256 does not match frozen manifest metadata"
        )

    if manifest_canonical_sha != manifest_metadata["manifest_canonical_sha256"]:
        raise RuntimeError(
            "Manifest canonical SHA-256 does not match frozen manifest metadata"
        )

    manifest_by_id = {row["request_id"]: row for row in manifest}

    if len(manifest_by_id) != 900:
        raise RuntimeError("Manifest request IDs are not unique")

    success_records = [
        row for row in result_records
        if row.get("status") == "success"
    ]
    non_success_records = [
        row for row in result_records
        if row.get("status") != "success"
    ]

    success_by_id = defaultdict(list)

    for row in success_records:
        success_by_id[row.get("request_id")].append(row)

    duplicate_success_ids = sorted(
        request_id
        for request_id, rows in success_by_id.items()
        if len(rows) != 1
    )

    if duplicate_success_ids:
        raise RuntimeError(
            f"Duplicate successful request IDs: {duplicate_success_ids[:10]}"
        )

    missing_ids = sorted(set(manifest_by_id) - set(success_by_id))
    extra_ids = sorted(set(success_by_id) - set(manifest_by_id))

    if missing_ids:
        raise RuntimeError(
            f"Missing successful request IDs: {missing_ids[:10]}"
        )

    if extra_ids:
        raise RuntimeError(
            f"Unexpected successful request IDs: {extra_ids[:10]}"
        )

    if len(success_records) != 900:
        raise RuntimeError(
            f"Expected 900 successful results, found {len(success_records)}"
        )

    rows_out = []
    label_counts = Counter()
    variant_counts = Counter()
    returned_model_counts = Counter()
    response_status_counts = Counter()
    usage_totals = Counter()
    usage_by_variant = defaultdict(Counter)
    mismatches = []
    missing_raw = []

    ordered_ids = sorted(
        manifest_by_id,
        key=lambda request_id: int(
            manifest_by_id[request_id]["request_index"]
        ),
    )

    for request_id in ordered_ids:
        expected = manifest_by_id[request_id]
        result = success_by_id[request_id][0]

        for field in [
            "request_index",
            "finding_id",
            "variant_short",
            "variant_name",
        ]:
            if result.get(field) != expected[field]:
                mismatches.append(
                    {
                        "request_id": request_id,
                        "field": field,
                        "expected": expected[field],
                        "actual": result.get(field),
                    }
                )

        if result.get("protocol_sha256") != protocol_run_sha:
            mismatches.append(
                {
                    "request_id": request_id,
                    "field": "protocol_sha256",
                }
            )

        if result.get("manifest_sha256") != manifest_run_sha:
            mismatches.append(
                {
                    "request_id": request_id,
                    "field": "manifest_sha256",
                }
            )

        label = str(result.get("label", "")).strip().upper()
        rationale = str(result.get("rationale", "")).strip()
        evidence = result.get("evidence")

        if label not in ALLOWED_LABELS:
            raise RuntimeError(
                f"Invalid model label for {request_id}: {label}"
            )

        if not rationale:
            raise RuntimeError(
                f"Blank rationale for {request_id}"
            )

        if not isinstance(evidence, list):
            raise RuntimeError(
                f"Evidence is not a list for {request_id}"
            )

        raw_value = result.get("raw_response_file")

        if not raw_value:
            missing_raw.append(request_id)
            raw_sha = ""
        else:
            raw_path = project_path(raw_value)
            if not raw_path.exists():
                missing_raw.append(request_id)
                raw_sha = ""
            else:
                raw_sha = canonical_text_sha256(raw_path)

        usage = usage_values(result)

        for key, value in usage.items():
            usage_totals[key] += value
            usage_by_variant[expected["variant_short"]][key] += value

        label_counts[label] += 1
        variant_counts[expected["variant_short"]] += 1
        returned_model_counts[str(result.get("returned_model_id"))] += 1
        response_status_counts[str(result.get("response_status"))] += 1

        rows_out.append(
            {
                "request_id": request_id,
                "request_index": expected["request_index"],
                "finding_id": expected["finding_id"],
                "repository": expected["repository"],
                "commit_sha": expected["commit_sha"],
                "filename": expected["filename"],
                "line_number": expected["line_number"],
                "security_family": expected["security_family"],
                "cwe_id": expected["cwe_id"],
                "variant_short": expected["variant_short"],
                "variant_name": expected["variant_name"],
                "label": label,
                "rationale": rationale,
                "evidence": evidence,
                "response_id": result.get("response_id"),
                "returned_model_id": result.get("returned_model_id"),
                "response_status": result.get("response_status"),
                "input_tokens": usage["input_tokens"],
                "cached_tokens": usage["cached_tokens"],
                "output_tokens": usage["output_tokens"],
                "reasoning_tokens": usage["reasoning_tokens"],
                "total_tokens": usage["total_tokens"],
                "elapsed_seconds": result.get("elapsed_seconds"),
                "started_at": result.get("started_at"),
                "completed_at": result.get("completed_at"),
                "raw_response_file": raw_value,
                "raw_response_sha256": raw_sha,
            }
        )

    if mismatches:
        raise RuntimeError(
            f"Result/manifest mismatches detected: {mismatches[:10]}"
        )

    if missing_raw:
        raise RuntimeError(
            f"Missing raw response evidence for: {missing_raw[:10]}"
        )

    if variant_counts != Counter({"A": 300, "B": 300, "C": 300}):
        raise RuntimeError(
            f"Unexpected variant counts: {dict(variant_counts)}"
        )

    OUTPUT_JSON.write_text(
        json.dumps(rows_out, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )

    fields = [
        "request_id",
        "request_index",
        "finding_id",
        "repository",
        "commit_sha",
        "filename",
        "line_number",
        "security_family",
        "cwe_id",
        "variant_short",
        "variant_name",
        "label",
        "rationale",
        "evidence_json",
        "response_id",
        "returned_model_id",
        "response_status",
        "input_tokens",
        "cached_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "elapsed_seconds",
        "started_at",
        "completed_at",
        "raw_response_file",
        "raw_response_sha256",
    ]

    with OUTPUT_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fields,
            lineterminator="\n",
        )
        writer.writeheader()

        for row in rows_out:
            csv_row = {
                key: value
                for key, value in row.items()
                if key != "evidence"
            }
            csv_row["evidence_json"] = json.dumps(
                row["evidence"],
                ensure_ascii=False,
            )
            writer.writerow(csv_row)

    metadata = {
        "freeze_version": "v6",
        "provider": protocol["provider"],
        "provider_product": protocol.get("provider_product"),
        "region": protocol.get("region"),
        "configured_model_id": protocol["model_id"],
        "reasoning_effort": protocol["reasoning_effort"],
        "official_result_records_total": len(result_records),
        "successful_results": len(success_records),
        "non_success_attempt_records": len(non_success_records),
        "unique_successful_request_ids": len(success_by_id),
        "variant_counts": dict(sorted(variant_counts.items())),
        "label_counts": dict(sorted(label_counts.items())),
        "returned_model_counts": dict(
            sorted(returned_model_counts.items())
        ),
        "response_status_counts": dict(
            sorted(response_status_counts.items())
        ),
        "usage_totals": dict(usage_totals),
        "usage_by_variant": {
            variant: dict(usage_by_variant[variant])
            for variant in sorted(usage_by_variant)
        },
        "hash_policy": "canonical_lf_text_v1",
        "protocol_sha256": protocol_run_sha,
        "protocol_canonical_sha256": protocol_canonical_sha,
        "manifest_sha256": manifest_run_sha,
        "manifest_canonical_sha256": manifest_canonical_sha,
        "official_results_sha256": canonical_text_sha256(RESULTS),
        "final_predictions_csv_sha256": canonical_text_sha256(OUTPUT_CSV),
        "final_predictions_csv_canonical_sha256": canonical_text_sha256(OUTPUT_CSV),
        "final_predictions_json_sha256": canonical_text_sha256(OUTPUT_JSON),
        "final_predictions_json_canonical_sha256": canonical_text_sha256(OUTPUT_JSON),
        "raw_response_files_verified": len(rows_out),
        "raw_response_files_missing": 0,
        "result_manifest_mismatches": 0,
        "complete": True,
        "outputs": {
            "csv": relative_path(OUTPUT_CSV),
            "json": relative_path(OUTPUT_JSON),
            "metadata": relative_path(OUTPUT_METADATA),
        },
    }

    OUTPUT_METADATA.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
        newline="\n",
    )

    print(json.dumps(metadata, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
