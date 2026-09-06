import argparse
import json
import os
import shutil
import subprocess
import tempfile
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def get_bandit_version():
    try:
        return version("bandit")
    except PackageNotFoundError:
        return None


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

    raise RuntimeError(
        "Bandit executable was not found. Install the project requirements first."
    )


def run_bandit(target, output_json=None, exclude=None):
    target_path = Path(target).resolve()

    if not target_path.exists():
        raise FileNotFoundError(f"Target does not exist: {target_path}")

    bandit = _find_bandit()
    temporary_output = output_json is None

    if temporary_output:
        handle = tempfile.NamedTemporaryFile(
            prefix="bandit_",
            suffix=".json",
            delete=False,
        )
        handle.close()
        report_path = Path(handle.name)
    else:
        report_path = Path(output_json).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)

    command = [
        bandit,
        "-f",
        "json",
        "-o",
        str(report_path),
        "--exit-zero",
        "-q",
    ]

    if target_path.is_dir():
        command.append("-r")

    if exclude:
        if isinstance(exclude, (list, tuple, set)):
            exclude_value = ",".join(str(item) for item in exclude)
        else:
            exclude_value = str(exclude)
        command.extend(["-x", exclude_value])

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

    try:
        if not report_path.exists():
            raise RuntimeError(
                f"Bandit did not create a JSON report.\n"
                f"Exit code: {result.returncode}\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"Bandit produced invalid JSON at {report_path}: {exc}"
            ) from exc

        if result.returncode != 0:
            raise RuntimeError(
                f"Bandit failed with exit code {result.returncode}.\n"
                f"stdout: {result.stdout.strip()}\n"
                f"stderr: {result.stderr.strip()}"
            )

        return report
    finally:
        if temporary_output:
            report_path.unlink(missing_ok=True)


def scan_file(filepath):
    return run_bandit(filepath)


def scan_directory(directory_path):
    return run_bandit(directory_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("output_json")
    parser.add_argument("--exclude", action="append")
    args = parser.parse_args()

    report = run_bandit(
        args.target,
        output_json=args.output_json,
        exclude=args.exclude,
    )

    print(
        json.dumps(
            {
                "bandit_version": get_bandit_version(),
                "results": len(report.get("results", [])),
                "errors": len(report.get("errors", [])),
                "output": str(Path(args.output_json).resolve()),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
