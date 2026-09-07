import argparse
import json
from pathlib import Path

import pandas as pd

import batch_repository_scanner as scanner


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "curated_100_repositories_scoped_v6.csv"
CORPUS_PROTOCOL = PROJECT_ROOT / "config" / "corpus_protocol_v6.json"


def load_scoped_manifest(path, selected_repositories=None, limit=None):
    manifest_path = Path(path).resolve()

    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    dataframe = pd.read_csv(manifest_path)

    required = {
        "repo_id",
        "repository",
        "domain",
        "cohort",
        "frozen_commit_sha",
        "scan_subpath",
    }
    missing = required.difference(dataframe.columns)

    if missing:
        raise RuntimeError(
            "Scoped manifest is missing required columns: "
            + ", ".join(sorted(missing))
        )

    if selected_repositories:
        selected = set(selected_repositories)
        dataframe = dataframe[
            dataframe["repository"].astype(str).isin(selected)
        ]

    if limit is not None:
        dataframe = dataframe.head(limit)

    return dataframe.reset_index(drop=True)


def normalize_subpath(value):
    text = str(value or ".").strip().replace("\\", "/")

    if text in {"", ".", "./"}:
        return "."

    candidate = Path(text)

    if candidate.is_absolute():
        raise RuntimeError(f"scan_subpath must be relative: {text}")

    if ".." in candidate.parts:
        raise RuntimeError(f"scan_subpath cannot contain '..': {text}")

    return candidate.as_posix().strip("/") or "."


def checkout_frozen_commit(repository_path, expected_sha):
    current = scanner.run_git(["rev-parse", "HEAD"], cwd=repository_path)

    if current == expected_sha:
        return current

    exists = scanner.run_git(
        ["cat-file", "-t", expected_sha],
        cwd=repository_path,
    )

    if exists != "commit":
        raise RuntimeError(
            f"Frozen object is not a commit for {repository_path}: {expected_sha}"
        )

    scanner.run_git(
        ["checkout", "--detach", "--force", expected_sha],
        cwd=repository_path,
    )
    scanner.run_git(["reset", "--hard", expected_sha], cwd=repository_path)

    current = scanner.run_git(["rev-parse", "HEAD"], cwd=repository_path)

    if current != expected_sha:
        raise RuntimeError(
            f"Frozen checkout mismatch: expected {expected_sha}, got {current}"
        )

    return current


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--run-id", required=True)
    parser.add_argument(
        "--transport",
        choices=["https", "ssh443"],
        default="ssh443",
    )
    parser.add_argument("--repo", action="append")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--skip-slicing", action="store_true")
    parser.add_argument("--annotation-sample-size", type=int, default=300)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()

    if not CORPUS_PROTOCOL.exists():
        raise FileNotFoundError(f"Corpus protocol not found: {CORPUS_PROTOCOL}")

    protocol = json.loads(CORPUS_PROTOCOL.read_text(encoding="utf-8"))
    manifest = load_scoped_manifest(
        args.manifest,
        selected_repositories=args.repo,
        limit=args.limit,
    )

    if manifest.empty:
        raise RuntimeError("No repositories selected")

    manifest_by_repository = {
        str(row["repository"]): {
            "repo_id": str(row["repo_id"]),
            "frozen_commit_sha": str(row["frozen_commit_sha"]),
            "scan_subpath": normalize_subpath(row["scan_subpath"]),
        }
        for _, row in manifest.iterrows()
    }

    path_scopes = {}
    original_clone = scanner.clone_or_update_repository
    original_collect = scanner.collect_python_targets
    original_load_manifest = scanner.load_manifest

    def frozen_clone(repository, transport, refresh=False):
        if refresh:
            raise RuntimeError(
                "Refresh is disabled for frozen corpus runs"
            )

        if repository not in manifest_by_repository:
            raise RuntimeError(
                f"Repository is absent from scoped manifest: {repository}"
            )

        repository_path, _ = original_clone(
            repository,
            transport,
            refresh=False,
        )
        expected_sha = manifest_by_repository[repository][
            "frozen_commit_sha"
        ]

        try:
            commit_sha = checkout_frozen_commit(
                repository_path,
                expected_sha,
            )
        except RuntimeError as exc:
            if "Not a valid object name" not in str(exc):
                raise

            scanner.run_git(
                [
                    "fetch",
                    "--depth",
                    "1",
                    "origin",
                    expected_sha,
                ],
                cwd=repository_path,
            )
            commit_sha = checkout_frozen_commit(
                repository_path,
                expected_sha,
            )

        path_scopes[str(repository_path.resolve())] = (
            manifest_by_repository[repository]["scan_subpath"]
        )

        return repository_path, commit_sha

    def scoped_collect(repository_path, excluded_directories=None):
        repository_root = Path(repository_path).resolve()
        subpath = path_scopes.get(str(repository_root), ".")

        if subpath == ".":
            scan_root = repository_root
        else:
            scan_root = (repository_root / Path(subpath)).resolve()

        try:
            scan_root.relative_to(repository_root)
        except ValueError as exc:
            raise RuntimeError(
                f"Resolved scan root escaped repository: {scan_root}"
            ) from exc

        if not scan_root.exists() or not scan_root.is_dir():
            raise RuntimeError(
                f"Configured scan_subpath does not exist: {scan_root}"
            )

        return original_collect(
            scan_root,
            excluded_directories,
        )

    def scoped_load_manifest(path, selected_repositories=None, limit=None):
        return load_scoped_manifest(
            path,
            selected_repositories=selected_repositories,
            limit=limit,
        )

    scanner.clone_or_update_repository = frozen_clone
    scanner.collect_python_targets = scoped_collect
    scanner.load_manifest = scoped_load_manifest

    pipeline_args = argparse.Namespace(
        manifest=args.manifest,
        run_id=args.run_id,
        transport=args.transport,
        repo=args.repo,
        limit=args.limit,
        bandit_config=str(scanner.DEFAULT_BANDIT_CONFIG),
        semgrep_config=str(scanner.DEFAULT_SEMGREP_CONFIG),
        scope="production",
        exclude=None,
        refresh=False,
        skip_slicing=args.skip_slicing,
        annotation_sample_size=args.annotation_sample_size,
        seed=args.seed,
        fail_fast=args.fail_fast,
    )

    scanner.run_pipeline(pipeline_args)

    run_root = scanner.GENERATED_ROOT / args.run_id
    processed_root = run_root / "processed"
    result_root = scanner.RESULTS_ROOT / args.run_id

    scan_manifest_path = processed_root / "scan_manifest.csv"
    scan_manifest = pd.read_csv(scan_manifest_path)

    manifest_columns = manifest[
        [
            "repo_id",
            "repository",
            "frozen_commit_sha",
            "scan_subpath",
        ]
    ].copy()

    scan_manifest = scan_manifest.merge(
        manifest_columns,
        on=["repo_id", "repository"],
        how="left",
        validate="one_to_one",
    )
    scan_manifest["commit_matches_frozen"] = (
        scan_manifest["commit_sha"].astype(str)
        == scan_manifest["frozen_commit_sha"].astype(str)
    )

    if not scan_manifest["commit_matches_frozen"].all():
        bad = scan_manifest.loc[
            ~scan_manifest["commit_matches_frozen"],
            [
                "repo_id",
                "repository",
                "commit_sha",
                "frozen_commit_sha",
            ],
        ]
        raise RuntimeError(
            "One or more repositories do not match frozen commits:\n"
            + bad.to_string(index=False)
        )

    scan_manifest.to_csv(scan_manifest_path, index=False)
    manifest.to_csv(
        processed_root / "corpus_scope_manifest.csv",
        index=False,
    )

    for _, row in scan_manifest.iterrows():
        repo_id = str(row["repo_id"])
        raw_root = run_root / "raw" / repo_id
        subpath = normalize_subpath(row["scan_subpath"])

        for filename in ["target_manifest.json", "metadata.json"]:
            path = raw_root / filename

            if not path.exists():
                continue

            value = json.loads(path.read_text(encoding="utf-8"))
            value["frozen_commit_sha"] = str(row["frozen_commit_sha"])
            value["commit_matches_frozen"] = bool(
                row["commit_matches_frozen"]
            )
            value["scan_subpath"] = subpath
            value["repository_scope_policy"] = (
                "manifest_scan_subpath"
            )
            path.write_text(
                json.dumps(value, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

    summary_path = result_root / "run_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["corpus_protocol_version"] = protocol[
        "corpus_protocol_version"
    ]
    summary["repository_revision_policy"] = protocol[
        "repository_revision_policy"
    ]
    summary["repository_scope_policy"] = protocol[
        "repository_scope_policy"
    ]
    summary["all_commits_match_frozen_manifest"] = True
    summary["scoped_repositories"] = int(
        (manifest["scan_subpath"].astype(str) != ".").sum()
    )
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "run_id": args.run_id,
                "repositories": len(scan_manifest),
                "successful": int(
                    (scan_manifest["status"].astype(str) == "SUCCESS").sum()
                ),
                "all_commits_match_frozen_manifest": True,
                "scoped_repositories": int(
                    (manifest["scan_subpath"].astype(str) != ".").sum()
                ),
                "corpus_protocol_version": protocol[
                    "corpus_protocol_version"
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
