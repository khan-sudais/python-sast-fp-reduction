import argparse
import json
import os
import shutil
import subprocess
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from scan_scope import chunk_paths, collect_python_targets


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "bandit.yaml"
PROTOCOL_FILE = PROJECT_ROOT / "config" / "scanner_protocol.json"


def get_bandit_version():
    try:
        return version("bandit")
    except PackageNotFoundError:
        return None


def get_bandit_tests():
    protocol = json.loads(PROTOCOL_FILE.read_text(encoding="utf-8"))
    return list(protocol["bandit"]["tests"])


def _find_bandit():
    executable = shutil.which("bandit")
    if executable:
        return executable

    candidates = [
        Path(os.sys.executable).parent / "bandit",
        Path(os.sys.executable).parent / "bandit.exe",
        Path(os.sys.executable).parent / "Scripts" / "bandit.exe",
        Path(os.sys.executable).parent / "Scripts" / "bandit",
    ]

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise RuntimeError("Bandit executable was not found")


def _resolve_targets(target, exclude):
    if isinstance(target, (list, tuple, set)):
        return sorted(
            {Path(value).resolve() for value in target},
            key=lambda value: str(value).casefold(),
        )

    return collect_python_targets(target, exclude)


def _run_chunk(bandit, targets, config_path, selected_tests):
    handle = tempfile.NamedTemporaryFile(
        prefix="bandit_chunk_",
        suffix=".json",
        delete=False,
    )
    handle.close()
    report_path = Path(handle.name)

    command = [
        bandit,
        "-c",
        str(config_path),
        "-t",
        ",".join(selected_tests),
        "-f",
        "json",
        "-o",
        str(report_path),
        "--exit-zero",
        "-q",
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

    try:
        if not report_path.exists():
            raise RuntimeError(
                f"Bandit did not create a JSON report\n"
                f"Exit code: {result.returncode}\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        report = json.loads(report_path.read_text(encoding="utf-8"))

        if result.returncode != 0:
            raise RuntimeError(
                f"Bandit failed with exit code {result.returncode}\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        return report
    finally:
        report_path.unlink(missing_ok=True)


def run_bandit(target, output_json=None, exclude=None, config=None, tests=None):
    config_path = Path(config or DEFAULT_CONFIG).resolve()
    selected_tests = list(tests or get_bandit_tests())

    if not config_path.exists():
        raise FileNotFoundError(f"Bandit config does not exist: {config_path}")

    targets = _resolve_targets(target, exclude)

    report = {
        "results": [],
        "errors": [],
        "metrics": {},
        "target_files": len(targets),
    }

    if targets:
        bandit = _find_bandit()
        fixed_arguments = [
            bandit,
            "-c",
            str(config_path),
            "-t",
            ",".join(selected_tests),
            "-f",
            "json",
        ]
        chunks = chunk_paths(targets, fixed_arguments=fixed_arguments)

        for chunk in chunks:
            chunk_report = _run_chunk(
                bandit,
                chunk,
                config_path,
                selected_tests,
            )
            report["results"].extend(chunk_report.get("results", []))
            report["errors"].extend(chunk_report.get("errors", []))

    returned_ids = sorted(
        {str(item.get("test_id", "")) for item in report.get("results", [])}
    )
    unexpected = [item for item in returned_ids if item not in selected_tests]

    if unexpected:
        raise RuntimeError(
            "Bandit returned findings outside the frozen test set: "
            + ", ".join(unexpected)
        )

    if output_json is not None:
        report_path = Path(output_json).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return report


def scan_file(filepath, config=None, tests=None):
    return run_bandit(filepath, config=config, tests=tests)


def scan_directory(directory_path, config=None, tests=None):
    return run_bandit(directory_path, config=config, tests=tests)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("output_json")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG))
    parser.add_argument("--exclude", action="append")
    args = parser.parse_args()

    selected_tests = get_bandit_tests()
    targets = collect_python_targets(args.target, args.exclude)

    report = run_bandit(
        targets,
        output_json=args.output_json,
        config=args.config,
        tests=selected_tests,
    )

    print(
        json.dumps(
            {
                "bandit_version": get_bandit_version(),
                "tests": selected_tests,
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
