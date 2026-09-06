import argparse
import json
import os
import shutil
import subprocess
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def get_semgrep_version():
    try:
        return version("semgrep")
    except PackageNotFoundError:
        return None


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

    raise RuntimeError(
        "Semgrep executable was not found. Install the project requirements first."
    )


def run_semgrep(
    target,
    output_json=None,
    config="auto",
    exclude=None,
    include=None,
):
    target_path = Path(target).resolve()

    if not target_path.exists():
        raise FileNotFoundError(f"Target does not exist: {target_path}")

    semgrep = _find_semgrep()

    command = [
        semgrep,
        "scan",
        "--config",
        str(config),
        "--json",
        "--quiet",
    ]

    if include:
        values = include if isinstance(include, (list, tuple, set)) else [include]
        for value in values:
            command.extend(["--include", str(value)])

    if exclude:
        values = exclude if isinstance(exclude, (list, tuple, set)) else [exclude]
        for value in values:
            command.extend(["--exclude", str(value)])

    command.append(str(target_path))

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
            f"Semgrep failed with exit code {result.returncode}.\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        )

    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Semgrep produced invalid JSON.\n"
            f"stdout: {result.stdout.strip()}\n"
            f"stderr: {result.stderr.strip()}"
        ) from exc

    if output_json is not None:
        report_path = Path(output_json).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    return report


def scan_file(filepath, config="auto"):
    return run_semgrep(
        filepath,
        config=config,
        include=["*.py"],
    )


def scan_directory(directory_path, config="auto"):
    return run_semgrep(
        directory_path,
        config=config,
        include=["*.py"],
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("output_json")
    parser.add_argument("--config", default="auto")
    parser.add_argument("--include", action="append")
    parser.add_argument("--exclude", action="append")
    args = parser.parse_args()

    includes = args.include if args.include else ["*.py"]

    report = run_semgrep(
        args.target,
        output_json=args.output_json,
        config=args.config,
        exclude=args.exclude,
        include=includes,
    )

    print(
        json.dumps(
            {
                "semgrep_version": get_semgrep_version(),
                "results": len(report.get("results", [])),
                "errors": len(report.get("errors", [])),
                "includes": includes,
                "output": str(Path(args.output_json).resolve()),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
