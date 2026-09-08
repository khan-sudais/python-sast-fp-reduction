import json
import statistics
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SLICES = PROJECT_ROOT / "data" / "slicing_v6" / "slices_audit_v6.jsonl"
OUTPUT = PROJECT_ROOT / "data" / "slicing_v6" / "llm_context_profile_v6.json"
THRESHOLDS = [8000, 16000, 24000, 32000, 48000, 64000]


def read_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def percentile(values, p):
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * p
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def summarize(values):
    return {
        "min": min(values),
        "median": statistics.median(values),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "max": max(values),
        "mean": statistics.mean(values),
    }


def main():
    if not SLICES.exists():
        raise FileNotFoundError(f"Slicing audit not found: {SLICES}")

    records = read_jsonl(SLICES)

    if len(records) != 300:
        raise RuntimeError(
            f"Expected 300 slicing records, found {len(records)}"
        )

    variants = {
        "A": "variant_a",
        "B": "variant_b",
        "C": "variant_c",
    }

    report = {
        "profile_version": "v6",
        "records": len(records),
        "thresholds_characters": THRESHOLDS,
        "variants": {},
    }

    for short_name, key in variants.items():
        char_counts = []
        utf8_byte_counts = []
        line_counts = []
        target_marker_missing = 0
        over_thresholds = {
            str(threshold): 0
            for threshold in THRESHOLDS
        }

        largest = []

        for record in records:
            code = record[key].get("code", "")
            chars = len(code)
            utf8_bytes = len(code.encode("utf-8"))
            lines = len(code.splitlines())
            target_line = int(record["line_number"])

            char_counts.append(chars)
            utf8_byte_counts.append(utf8_bytes)
            line_counts.append(lines)

            for threshold in THRESHOLDS:
                if chars > threshold:
                    over_thresholds[str(threshold)] += 1

            marker = f"{target_line:4d}:"
            if key in {"variant_b", "variant_c"} and marker not in code:
                target_marker_missing += 1

            largest.append(
                {
                    "finding_id": record["finding_id"],
                    "repository": record["repository"],
                    "filename": record["filename"],
                    "line_number": target_line,
                    "characters": chars,
                    "utf8_bytes": utf8_bytes,
                    "lines": lines,
                }
            )

        largest.sort(
            key=lambda item: item["characters"],
            reverse=True,
        )

        report["variants"][short_name] = {
            "characters": summarize(char_counts),
            "utf8_bytes": summarize(utf8_byte_counts),
            "lines": summarize(line_counts),
            "over_threshold_counts": over_thresholds,
            "target_marker_missing_count": target_marker_missing,
            "largest_10": largest[:10],
        }

    OUTPUT.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
