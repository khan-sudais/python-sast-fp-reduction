import csv
import hashlib
import json
import random
from collections import Counter
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SLICES = DATA_DIR / "slicing_v6" / "slices_audit_v6.jsonl"
SAMPLE = DATA_DIR / "ground_truth_annotation_sample_v6.csv"
PROTOCOL = PROJECT_ROOT / "config" / "llm_protocol_v6.json"
OUTPUT_DIR = DATA_DIR / "llm_v6"
MANIFEST = OUTPUT_DIR / "llm_experiment_manifest_v6.jsonl"
METADATA = OUTPUT_DIR / "llm_experiment_manifest_v6_metadata.json"
FORBIDDEN_KEYS = {
    "label",
    "final_label",
    "adjudicated_label",
    "annotator_1_label",
    "annotator_2_label",
    "rationale",
    "final_rationale",
    "adjudication_rationale",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def make_user_prompt(record, source, variant_name, code):
    return (
        f"Finding ID: {record['finding_id']}\n"
        f"Security family: {record['security_family']}\n"
        f"CWE: {source.get('cwe_id', '')}\n"
        f"Repository file: {record['filename']}\n"
        f"Target line: {record['line_number']}\n"
        f"Flagged statement:\n{source.get('statement_code', '')}\n\n"
        f"Context variant: {variant_name}\n"
        f"Supplied code context:\n{code}"
    )


def main():
    if not SLICES.exists():
        raise FileNotFoundError(f"Missing slicing audit: {SLICES}")

    if not SAMPLE.exists():
        raise FileNotFoundError(f"Missing frozen V6 sample: {SAMPLE}")

    if not PROTOCOL.exists():
        raise FileNotFoundError(f"Missing LLM protocol: {PROTOCOL}")

    slice_records = read_jsonl(SLICES)
    source_rows = read_csv(SAMPLE)
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    if len(slice_records) != 300:
        raise RuntimeError(
            f"Expected 300 slicing records, found {len(slice_records)}"
        )

    if len(source_rows) != 300:
        raise RuntimeError(
            f"Expected 300 source rows, found {len(source_rows)}"
        )

    source_by_id = {
        row["finding_id"]: row
        for row in source_rows
    }

    requests = []
    variant_counts = Counter()

    variant_specs = [
        ("A", "variant_a"),
        ("B", "variant_b"),
        ("C", "variant_c"),
    ]

    for record in slice_records:
        finding_id = record["finding_id"]

        if finding_id not in source_by_id:
            raise RuntimeError(
                f"Frozen source row missing for {finding_id}"
            )

        source = source_by_id[finding_id]

        for variant_short, variant_key in variant_specs:
            variant = record[variant_key]
            variant_name = variant.get("variant", "")
            code = variant.get("code", "")

            if not code:
                raise RuntimeError(
                    f"Empty {variant_short} slice for {finding_id}"
                )

            user_prompt = make_user_prompt(
                record,
                source,
                variant_name,
                code,
            )

            request = {
                "finding_id": finding_id,
                "repository": record["repository"],
                "commit_sha": record["commit_sha"],
                "filename": record["filename"],
                "line_number": record["line_number"],
                "security_family": record["security_family"],
                "cwe_id": source.get("cwe_id", ""),
                "variant_short": variant_short,
                "variant_name": variant_name,
                "input_characters": len(user_prompt),
                "user_prompt": user_prompt,
            }

            if FORBIDDEN_KEYS.intersection(request):
                raise RuntimeError(
                    f"Ground-truth leakage key detected for {finding_id}"
                )

            requests.append(request)
            variant_counts[variant_short] += 1

    if len(requests) != 900:
        raise RuntimeError(
            f"Expected 900 requests, found {len(requests)}"
        )

    if variant_counts != Counter({"A": 300, "B": 300, "C": 300}):
        raise RuntimeError(
            f"Unexpected variant distribution: {dict(variant_counts)}"
        )

    rng = random.Random(int(protocol["request_order_seed"]))
    rng.shuffle(requests)

    for index, request in enumerate(requests, start=1):
        request["request_index"] = index
        request["request_id"] = f"LLM-V6-{index:04d}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with MANIFEST.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as handle:
        for request in requests:
            handle.write(
                json.dumps(
                    request,
                    ensure_ascii=False,
                )
                + "\n"
            )

    metadata = {
        "manifest_version": "v6",
        "requests": len(requests),
        "unique_findings": len(
            {request["finding_id"] for request in requests}
        ),
        "variant_counts": dict(sorted(variant_counts.items())),
        "request_order_seed": protocol["request_order_seed"],
        "ground_truth_fields_included": False,
        "slices_sha256": sha256(SLICES),
        "source_sample_sha256": sha256(SAMPLE),
        "protocol_sha256": sha256(PROTOCOL),
        "manifest_sha256": sha256(MANIFEST),
        "max_input_characters": max(
            request["input_characters"]
            for request in requests
        ),
        "outputs": {
            "manifest": str(MANIFEST),
            "metadata": str(METADATA),
        },
    }

    METADATA.write_text(
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
