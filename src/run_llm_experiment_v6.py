import argparse
import hashlib
import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "llm_v6"
MANIFEST = DATA_DIR / "llm_experiment_manifest_v6.jsonl"
MANIFEST_METADATA = DATA_DIR / "llm_experiment_manifest_v6_metadata.json"
PROTOCOL = PROJECT_ROOT / "config" / "llm_protocol_v6.json"
REQUEST_TIMEOUT_SECONDS = 600
TRANSPORT_RETRY_DELAYS = [2, 4, 8]
INVALID_OUTPUT_RETRY_DELAY = 2
ALLOWED_LABELS = {"TRUE_BUG", "FALSE_POSITIVE", "UNCERTAIN"}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def append_jsonl(path, record):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def dump_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")


def successful_ids(path):
    if not path.exists():
        return set()
    result = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("status") == "success":
                result.add(record["request_id"])
    return result


def select_smoke_requests(requests):
    selected = []
    seen = set()
    for request in sorted(requests, key=lambda item: int(item["request_index"])):
        variant = request["variant_short"]
        if variant in seen:
            continue
        selected.append(request)
        seen.add(variant)
        if seen == {"A", "B", "C"}:
            return selected
    raise RuntimeError(f"Could not select one smoke request for each variant: {sorted(seen)}")


def extract_output_text(response):
    parts = []
    for item in response.get("output", []):
        if item.get("type") != "message":
            continue
        for content in item.get("content", []):
            if content.get("type") == "output_text":
                parts.append(content.get("text", ""))
    return "".join(parts).strip()


def normalize_json_text(text):
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        if lines and lines[0].strip().lower() in {"```", "```json"}:
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        value = "\n".join(lines).strip()
    return value


def validate_prediction(value):
    if not isinstance(value, dict):
        raise ValueError("Output is not a JSON object")
    if set(value) != {"label", "rationale", "evidence"}:
        raise ValueError(f"Unexpected JSON keys: {sorted(value)}")
    label = str(value.get("label", "")).strip().upper()
    rationale = str(value.get("rationale", "")).strip()
    evidence = value.get("evidence")
    if label not in ALLOWED_LABELS:
        raise ValueError(f"Invalid label: {label}")
    if not rationale:
        raise ValueError("Blank rationale")
    if not isinstance(evidence, list):
        raise ValueError("Evidence must be a list")
    if not all(isinstance(item, str) for item in evidence):
        raise ValueError("Evidence contains a non-string value")
    return {"label": label, "rationale": rationale, "evidence": evidence}


def raw_file(raw_dir, request_id, attempt):
    return raw_dir / f"{request_id}_attempt_{attempt:02d}.json"


def http_post_json(url, api_key, body):
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "python-sast-fp-reduction-v6",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        data = response.read().decode("utf-8")
        return response.status, dict(response.headers), json.loads(data)


def retryable_status(status):
    return status in {408, 409, 429} or status >= 500


def execute_request(api_key, base_url, request, protocol, result_path, raw_dir, run_kind, protocol_sha, manifest_sha):
    transport_retries = 0
    invalid_retries = 0
    attempt = 0
    url = base_url.rstrip("/") + "/responses"

    while True:
        attempt += 1
        body = {
            "model": protocol["model_id"],
            "instructions": protocol["system_prompt"],
            "input": request["user_prompt"],
            "reasoning": {"effort": protocol["reasoning_effort"]},
            "max_output_tokens": int(protocol["max_output_tokens"]),
            "tools": [],
            "tool_choice": "none",
            "stream": False,
        }
        started_at = utc_now()
        started_clock = time.monotonic()

        try:
            status, headers, response = http_post_json(url, api_key, body)
            elapsed = time.monotonic() - started_clock
            raw_path = raw_file(raw_dir, request["request_id"], attempt)
            dump_json(
                raw_path,
                {
                    "run_kind": run_kind,
                    "request_id": request["request_id"],
                    "request_index": request["request_index"],
                    "attempt": attempt,
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "elapsed_seconds": elapsed,
                    "protocol_sha256": protocol_sha,
                    "manifest_sha256": manifest_sha,
                    "http_status": status,
                    "response_headers": {
                        key: value
                        for key, value in headers.items()
                        if key.lower() in {"content-type", "date", "request-id", "x-request-id"}
                    },
                    "request_body": body,
                    "response": response,
                },
            )

            if response.get("status") != "completed":
                raise ValueError(
                    f"Response status is {response.get('status')}: "
                    f"{response.get('incomplete_details') or response.get('error')}"
                )

            try:
                output_text = normalize_json_text(extract_output_text(response))
                prediction = validate_prediction(json.loads(output_text))
                append_jsonl(
                    result_path,
                    {
                        "run_kind": run_kind,
                        "request_id": request["request_id"],
                        "request_index": request["request_index"],
                        "finding_id": request["finding_id"],
                        "variant_short": request["variant_short"],
                        "variant_name": request["variant_name"],
                        "attempt": attempt,
                        "status": "success",
                        "label": prediction["label"],
                        "rationale": prediction["rationale"],
                        "evidence": prediction["evidence"],
                        "response_id": response.get("id"),
                        "returned_model_id": response.get("model"),
                        "response_status": response.get("status"),
                        "usage": response.get("usage"),
                        "started_at": started_at,
                        "completed_at": utc_now(),
                        "elapsed_seconds": elapsed,
                        "protocol_sha256": protocol_sha,
                        "manifest_sha256": manifest_sha,
                        "raw_response_file": str(raw_path.relative_to(PROJECT_ROOT)),
                    },
                )
                return True

            except Exception as exc:
                append_jsonl(
                    result_path,
                    {
                        "run_kind": run_kind,
                        "request_id": request["request_id"],
                        "request_index": request["request_index"],
                        "finding_id": request["finding_id"],
                        "variant_short": request["variant_short"],
                        "attempt": attempt,
                        "status": "invalid_output",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "response_id": response.get("id"),
                        "returned_model_id": response.get("model"),
                        "response_status": response.get("status"),
                        "usage": response.get("usage"),
                        "started_at": started_at,
                        "completed_at": utc_now(),
                        "elapsed_seconds": elapsed,
                        "protocol_sha256": protocol_sha,
                        "manifest_sha256": manifest_sha,
                        "raw_response_file": str(raw_path.relative_to(PROJECT_ROOT)),
                    },
                )
                max_invalid = int(protocol["retry_policy"]["invalid_structured_output_retries"])
                if invalid_retries < max_invalid:
                    invalid_retries += 1
                    time.sleep(INVALID_OUTPUT_RETRY_DELAY)
                    continue
                return False

        except KeyboardInterrupt:
            raise

        except urllib.error.HTTPError as exc:
            elapsed = time.monotonic() - started_clock
            response_body = exc.read().decode("utf-8", errors="replace")
            append_jsonl(
                result_path,
                {
                    "run_kind": run_kind,
                    "request_id": request["request_id"],
                    "request_index": request["request_index"],
                    "finding_id": request["finding_id"],
                    "variant_short": request["variant_short"],
                    "attempt": attempt,
                    "status": "api_error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "http_status": exc.code,
                    "response_body": response_body,
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "elapsed_seconds": elapsed,
                    "protocol_sha256": protocol_sha,
                    "manifest_sha256": manifest_sha,
                },
            )
            max_transport = int(protocol["retry_policy"]["transport_or_rate_limit_retries"])
            if retryable_status(exc.code) and transport_retries < max_transport:
                delay = TRANSPORT_RETRY_DELAYS[min(transport_retries, len(TRANSPORT_RETRY_DELAYS) - 1)]
                transport_retries += 1
                time.sleep(delay)
                continue
            return False

        except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
            elapsed = time.monotonic() - started_clock
            append_jsonl(
                result_path,
                {
                    "run_kind": run_kind,
                    "request_id": request["request_id"],
                    "request_index": request["request_index"],
                    "finding_id": request["finding_id"],
                    "variant_short": request["variant_short"],
                    "attempt": attempt,
                    "status": "transport_error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "elapsed_seconds": elapsed,
                    "protocol_sha256": protocol_sha,
                    "manifest_sha256": manifest_sha,
                },
            )
            max_transport = int(protocol["retry_policy"]["transport_or_rate_limit_retries"])
            if transport_retries < max_transport:
                delay = TRANSPORT_RETRY_DELAYS[min(transport_retries, len(TRANSPORT_RETRY_DELAYS) - 1)]
                transport_retries += 1
                time.sleep(delay)
                continue
            return False

        except Exception as exc:
            elapsed = time.monotonic() - started_clock
            append_jsonl(
                result_path,
                {
                    "run_kind": run_kind,
                    "request_id": request["request_id"],
                    "request_index": request["request_index"],
                    "finding_id": request["finding_id"],
                    "variant_short": request["variant_short"],
                    "attempt": attempt,
                    "status": "runner_error",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "started_at": started_at,
                    "completed_at": utc_now(),
                    "elapsed_seconds": elapsed,
                    "protocol_sha256": protocol_sha,
                    "manifest_sha256": manifest_sha,
                },
            )
            return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke-test", action="store_true")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    api_key = os.environ.get("DASHSCOPE_API_KEY")
    if not api_key:
        raise RuntimeError("DASHSCOPE_API_KEY is not set in the current environment")

    for path in [MANIFEST, MANIFEST_METADATA, PROTOCOL]:
        if not path.exists():
            raise FileNotFoundError(f"Required file not found: {path}")

    metadata = json.loads(MANIFEST_METADATA.read_text(encoding="utf-8"))
    protocol = json.loads(PROTOCOL.read_text(encoding="utf-8"))

    if protocol.get("provider") != "Alibaba Cloud Model Studio":
        raise RuntimeError(
            f"Expected Alibaba Cloud Model Studio protocol, found {protocol.get('provider')}"
        )

    protocol_sha = sha256(PROTOCOL)
    manifest_sha = sha256(MANIFEST)

    if protocol_sha != metadata["protocol_sha256"]:
        raise RuntimeError("Protocol SHA-256 does not match frozen manifest metadata")
    if manifest_sha != metadata["manifest_sha256"]:
        raise RuntimeError("Manifest SHA-256 does not match frozen manifest metadata")

    requests = read_jsonl(MANIFEST)
    if len(requests) != 900:
        raise RuntimeError(f"Expected 900 requests, found {len(requests)}")

    if args.smoke_test:
        selected = select_smoke_requests(requests)
        run_kind = "smoke"
        result_path = DATA_DIR / "qwen_smoke_results_v6.jsonl"
        raw_dir = DATA_DIR / "raw" / "qwen_smoke"
    else:
        if not args.yes:
            raise RuntimeError("Official paid run requires --yes")
        selected = sorted(requests, key=lambda item: int(item["request_index"]))
        run_kind = "official"
        result_path = DATA_DIR / "qwen_official_results_v6.jsonl"
        raw_dir = DATA_DIR / "raw" / "qwen_official"

    done = successful_ids(result_path)
    pending = [request for request in selected if request["request_id"] not in done]

    if args.limit is not None:
        if args.limit < 1:
            raise ValueError("--limit must be at least 1")
        pending = pending[:args.limit]

    base_url = os.environ.get("DASHSCOPE_BASE_URL", protocol["default_base_url"])

    run_metadata = {
        "run_kind": run_kind,
        "started_at": utc_now(),
        "provider": protocol["provider"],
        "provider_product": protocol["provider_product"],
        "region": protocol["region"],
        "model_id": protocol["model_id"],
        "reasoning_effort": protocol["reasoning_effort"],
        "max_output_tokens": protocol["max_output_tokens"],
        "request_timeout_seconds": REQUEST_TIMEOUT_SECONDS,
        "client": protocol["client"],
        "base_url": base_url,
        "protocol_sha256": protocol_sha,
        "manifest_sha256": manifest_sha,
        "selected_requests": len(selected),
        "already_successful": len(done),
        "pending_this_invocation": len(pending),
        "result_file": str(result_path.relative_to(PROJECT_ROOT)),
        "raw_directory": str(raw_dir.relative_to(PROJECT_ROOT)),
    }

    metadata_path = DATA_DIR / f"qwen_{run_kind}_run_metadata_v6.json"
    dump_json(metadata_path, run_metadata)
    print(json.dumps(run_metadata, indent=2))

    if not pending:
        print("No pending requests.")
        return

    success_count = 0
    failure_count = 0

    for position, request in enumerate(pending, start=1):
        print(
            f"[{position}/{len(pending)}] "
            f"{request['request_id']} "
            f"{request['variant_short']} "
            f"{request['finding_id']}"
        )
        ok = execute_request(
            api_key=api_key,
            base_url=base_url,
            request=request,
            protocol=protocol,
            result_path=result_path,
            raw_dir=raw_dir,
            run_kind=run_kind,
            protocol_sha=protocol_sha,
            manifest_sha=manifest_sha,
        )
        if ok:
            success_count += 1
        else:
            failure_count += 1

    run_metadata["completed_at"] = utc_now()
    run_metadata["invocation_success"] = success_count
    run_metadata["invocation_failed"] = failure_count
    run_metadata["total_successful_after_run"] = len(successful_ids(result_path))
    dump_json(metadata_path, run_metadata)
    print(json.dumps(run_metadata, indent=2))


if __name__ == "__main__":
    main()
