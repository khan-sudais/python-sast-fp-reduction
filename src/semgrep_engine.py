import argparse
import json
import os
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from scan_scope import chunk_paths, collect_python_targets


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "semgrep-python-security.yml"
PROTOCOL_FILE = PROJECT_ROOT / "config" / "scanner_protocol.json"


def get_semgrep_version():
    try:
        return version("semgrep")
    except PackageNotFoundError:
        return None


def get_semgrep_rule_ids():
    protocol = json.loads(PROTOCOL_FILE.read_text(encoding="utf-8"))
    return list(protocol["semgrep"]["rule_ids"])


def _find_semgrep():
    executable = shutil.which("semgrep")
    if executable:
        return executable

    candidates = [
        Path(sys.executable).parent / "semgrep",
        Path(sys.executable).parent / "semgrep.exe",
        Path(sys.executable).parent / "Scripts" / "semgrep",
        Path(sys.executable).parent / "Scripts" / "semgrep.exe",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise RuntimeError("Semgrep executable was not found")


def _resolve_targets(target, exclude):
    if isinstance(target, (list, tuple, set)):
        return sorted(
            {Path(value).resolve() for value in target},
            key=lambda value: str(value).casefold(),
        )

    return collect_python_targets(target, exclude)


def _normalize_rule_ids(report):
    allowed = set(get_semgrep_rule_ids())

    for item in report.get("results", []):
        check_id = str(item.get("check_id", ""))

        if check_id.startswith("config."):
            normalized = check_id[len("config."):]
            if normalized in allowed:
                item["check_id"] = normalized

    returned = {
        str(item.get("check_id", ""))
        for item in report.get("results", [])
    }
    unexpected = sorted(returned.difference(allowed))

    if unexpected:
        raise RuntimeError(
            "Semgrep returned findings outside the frozen rule set: "
            + ", ".join(unexpected)
        )


def _run_chunk(semgrep, targets, config_path):
    command = [
        semgrep,
        "scan",
        "--config",
        str(config_path),
        "--json",
        "--quiet",
        *[str(path) for path in targets],
    ]

    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Semgrep failed with exit code {result.returncode}\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )

    report = json.loads(result.stdout)
    _normalize_rule_ids(report)
    return report


def run_semgrep(
    target,
    output_json=None,
    config=None,
    exclude=None,
    include=None,
):
    config_path = Path(config or DEFAULT_CONFIG).resolve()

    if not config_path.exists():
        raise FileNotFoundError(f"Semgrep config does not exist: {config_path}")

    targets = _resolve_targets(target, exclude)

    report = {
        "version": get_semgrep_version(),
        "results": [],
        "errors": [],
        "paths": {"scanned": []},
        "target_files": len(targets),
    }

    if targets:
        semgrep = _find_semgrep()
        fixed_arguments = [
            semgrep,
            "scan",
            "--config",
            str(config_path),
            "--json",
            "--quiet",
        ]
        chunks = chunk_paths(targets, fixed_arguments=fixed_arguments)

        for chunk in chunks:
            chunk_report = _run_chunk(
                semgrep,
                chunk,
                config_path,
            )
            report["results"].extend(chunk_report.get("results", []))
            report["errors"].extend(chunk_report.get("errors", []))
            report["paths"]["scanned"].extend(
                chunk_report.get("paths", {}).get("scanned", [])
            )

    _normalize_rule_ids(report)

    if output_json is not None:
        report_path = Path(output_json).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return report


def scan_file(filepath, config=None):
    return run_semgrep(filepath, config=config)


def scan_directory(directory_path, config=None):
    return run_semgrep(directory_path, config=config)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("output_json")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--exclude", action="append")
    args = parser.parse_args()

    targets = collect_python_targets(args.target, args.exclude)
    rule_ids = get_semgrep_rule_ids()

    report = run_semgrep(
        targets,
        output_json=args.output_json,
        config=args.config,
    )

    print(
        json.dumps(
            {
                "semgrep_version": get_semgrep_version(),
                "rule_ids": rule_ids,
                "target_files": len(targets),
                "results": len(report.get("results", [])),
                "errors": len(report.get("errors", [])),
                "config": str(Path(args.config).resolve()),
                "output": str(Path(args.output_json).resolve()),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
