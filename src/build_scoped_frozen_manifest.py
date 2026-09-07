import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = PROJECT_ROOT / "data" / "frozen_100_repository_snapshot_v5.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "curated_100_repositories_scoped_v6.csv"
DEFAULT_METADATA = PROJECT_ROOT / "data" / "curated_100_repositories_scoped_v6.json"


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default=str(DEFAULT_SOURCE))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--metadata", default=str(DEFAULT_METADATA))
    args = parser.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    metadata_path = Path(args.metadata).resolve()

    if not source.exists():
        raise FileNotFoundError(f"Frozen repository snapshot not found: {source}")

    dataframe = pd.read_csv(source)

    required = {
        "repo_id",
        "repository",
        "domain",
        "cohort",
        "commit_sha",
    }
    missing = required.difference(dataframe.columns)

    if missing:
        raise RuntimeError(
            "Frozen snapshot is missing required columns: "
            + ", ".join(sorted(missing))
        )

    if len(dataframe) != 100:
        raise RuntimeError(f"Expected 100 repositories, found {len(dataframe)}")

    if dataframe["repo_id"].duplicated().any():
        raise RuntimeError("Duplicate repo_id values found")

    if dataframe["repository"].duplicated().any():
        raise RuntimeError("Duplicate repositories found")

    sha_ok = dataframe["commit_sha"].astype(str).str.fullmatch("[0-9a-f]{40}")

    if not sha_ok.all():
        raise RuntimeError("One or more frozen commit SHAs are invalid")

    scoped = dataframe.copy()
    scoped["frozen_commit_sha"] = scoped["commit_sha"].astype(str)
    scoped["scan_subpath"] = "."
    scoped["scope_reason"] = "repository_root"

    target = scoped["repo_id"].astype(str) == "R063"

    if int(target.sum()) != 1:
        raise RuntimeError("Expected exactly one R063 row")

    repository = str(scoped.loc[target, "repository"].iloc[0])

    if repository != "grpc/grpc":
        raise RuntimeError(
            f"R063 repository mismatch: expected grpc/grpc, found {repository}"
        )

    scoped.loc[target, "scan_subpath"] = "src/python"
    scoped.loc[target, "scope_reason"] = (
        "grpc/grpc is a monorepo; src/python preserves the Python project "
        "scope corresponding to the legacy grpc/grpc-python selection"
    )

    preferred = [
        "repo_id",
        "repository",
        "domain",
        "cohort",
        "frozen_commit_sha",
        "scan_subpath",
        "scope_reason",
    ]

    optional = [
        column
        for column in [
            "original_repository",
            "repair_action",
            "repair_reason",
            "remote_verified",
        ]
        if column in scoped.columns
    ]

    scoped = scoped[preferred + optional].sort_values("repo_id").reset_index(
        drop=True
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    scoped.to_csv(output, index=False)

    metadata = {
        "corpus_manifest_version": "v6",
        "source_snapshot": str(source),
        "source_snapshot_sha256": file_sha256(source),
        "output_manifest": str(output),
        "output_manifest_sha256": file_sha256(output),
        "repositories": len(scoped),
        "unique_repositories": int(scoped["repository"].nunique()),
        "revision_policy": "exact_frozen_commit_sha",
        "scope_policy": "manifest_scan_subpath",
        "default_scan_subpath": ".",
        "special_scope_count": int((scoped["scan_subpath"] != ".").sum()),
        "special_scopes": scoped.loc[
            scoped["scan_subpath"] != ".",
            [
                "repo_id",
                "repository",
                "frozen_commit_sha",
                "scan_subpath",
                "scope_reason",
            ],
        ].to_dict(orient="records"),
    }

    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "rows": len(scoped),
                "unique_repositories": int(scoped["repository"].nunique()),
                "special_scope_count": int(
                    (scoped["scan_subpath"] != ".").sum()
                ),
                "r063_scan_subpath": str(
                    scoped.loc[
                        scoped["repo_id"].astype(str) == "R063",
                        "scan_subpath",
                    ].iloc[0]
                ),
                "output": str(output),
                "metadata": str(metadata_path),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
