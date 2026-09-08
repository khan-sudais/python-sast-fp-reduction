import argparse
import json
import subprocess
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "data" / "curated_100_repositories.xlsx"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "curated_100_repositories_repaired.xlsx"
DEFAULT_REPAIRS = PROJECT_ROOT / "data" / "repository_manifest_repairs.csv"
DEFAULT_FAILED_OUTPUT = PROJECT_ROOT / "data" / "curated_17_repaired_repositories.xlsx"

REPAIRS = {
    "R013": ("ansible/ansible", "environment_fix", "Repository exists. Previous checkout failed only because Windows long paths were disabled."),
    "R043": ("jpadilla/pyjwt", "repository_move", "Original repository path no longer resolves. Current PyJWT repository is jpadilla/pyjwt."),
    "R044": ("googleapis/google-auth-library-python", "repository_move_archived", "Project repository moved from the old owner path. The current repository is archived but preserves the selected project source."),
    "R048": ("tlsfuzzer/python-ecdsa", "repository_move", "Original repository path no longer resolves. Current python-ecdsa repository is tlsfuzzer/python-ecdsa."),
    "R056": ("pycurl/pycurl", "repository_move", "Original repository path no longer resolves. Current PycURL repository is pycurl/pycurl."),
    "R063": ("grpc/grpc", "project_migration", "The former grpc-python project is maintained in grpc/grpc. Only Python files are targeted by the scanner protocol."),
    "R065": ("python-trio/trio", "repository_move", "Original repository path no longer resolves. Current Trio repository is python-trio/trio."),
    "R066": ("glamp/bashplotlib", "repository_move", "Original repository path no longer resolves. Current bashplotlib repository is glamp/bashplotlib."),
    "R073": ("edwardgeorge/virtualenv-clone", "repository_move", "Original repository path no longer resolves. Current virtualenv-clone repository is edwardgeorge/virtualenv-clone."),
    "R076": ("myusuf3/delorean", "repository_move", "Original repository path no longer resolves. Current Delorean repository is myusuf3/delorean."),
    "R079": ("sybrenstuvel/python-rsa", "repository_move_archived", "Original repository path no longer resolves. The historical repository is sybrenstuvel/python-rsa and is archived."),
    "R080": ("pyca/pyopenssl", "repository_move", "Original repository path no longer resolves. Current pyOpenSSL repository is pyca/pyopenssl."),
    "R081": ("mpdavis/python-jose", "same_domain_replacement", "Original google/jwt-verifier-python repository is unavailable. Replaced with a public Python JOSE/JWT implementation in the same Security, Cryptography & Auth domain."),
    "R082": ("adamchainz/django-cors-headers", "repository_move", "Original repository path no longer resolves. Current django-cors-headers repository is adamchainz/django-cors-headers."),
    "R086": ("python-attrs/cattrs", "same_domain_replacement", "The current PyYAML repository duplicates R027. Replaced with cattrs to preserve a unique Data Validation & Serialization holdout repository."),
    "R098": ("pyinvoke/invoke", "repository_move", "Original repository path no longer resolves. Current Invoke repository is pyinvoke/invoke."),
    "R100": ("pyreadline3/pyreadline3", "successor_replacement", "Original pyreadline repository is unavailable. pyreadline3 is the maintained successor project."),
}


def remote_url(repository, transport):
    if transport == "ssh443":
        return f"ssh://git@ssh.github.com:443/{repository}.git"
    return f"https://github.com/{repository}.git"


def verify_remote(repository, transport):
    result = subprocess.run(
        ["git", "ls-remote", "--exit-code", remote_url(repository, transport), "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return result.returncode == 0, result.stderr.strip()


def repair_manifest(input_path, output_path, repairs_path, failed_output, verify, transport):
    source = Path(input_path).resolve()
    output = Path(output_path).resolve()
    repairs_csv = Path(repairs_path).resolve()
    failed_xlsx = Path(failed_output).resolve()

    dataframe = pd.read_excel(source)

    required = {"repo_id", "repository", "domain", "cohort"}
    missing = sorted(required.difference(dataframe.columns))
    if missing:
        raise RuntimeError("Missing required manifest columns: " + ", ".join(missing))

    if len(dataframe) != 100:
        raise RuntimeError(f"Expected 100 manifest rows, found {len(dataframe)}")

    if dataframe["repo_id"].duplicated().any():
        raise RuntimeError("Duplicate repo_id values exist in the source manifest")

    dataframe["original_repository"] = dataframe["repository"].astype("string")
    dataframe["repair_action"] = pd.Series(
        ["unchanged"] * len(dataframe),
        index=dataframe.index,
        dtype="string",
    )
    dataframe["repair_reason"] = pd.Series(
        [""] * len(dataframe),
        index=dataframe.index,
        dtype="string",
    )
    dataframe["remote_verified"] = pd.Series(
        [pd.NA] * len(dataframe),
        index=dataframe.index,
        dtype="boolean",
    )
    dataframe["remote_verification_error"] = pd.Series(
        [""] * len(dataframe),
        index=dataframe.index,
        dtype="string",
    )

    audit_rows = []

    for repo_id, (replacement, action, reason) in REPAIRS.items():
        matches = dataframe.index[
            dataframe["repo_id"].astype(str) == repo_id
        ].tolist()

        if len(matches) != 1:
            raise RuntimeError(
                f"Expected exactly one manifest row for {repo_id}, found {len(matches)}"
            )

        index = matches[0]
        original = str(dataframe.at[index, "repository"])

        dataframe.at[index, "repository"] = replacement
        dataframe.at[index, "repair_action"] = action
        dataframe.at[index, "repair_reason"] = reason

        verified = pd.NA
        verification_error = ""

        if verify:
            ok, error = verify_remote(replacement, transport)
            verified = bool(ok)
            verification_error = error
            dataframe.at[index, "remote_verified"] = bool(ok)
            dataframe.at[index, "remote_verification_error"] = error

        audit_rows.append(
            {
                "repo_id": repo_id,
                "original_repository": original,
                "repaired_repository": replacement,
                "domain": str(dataframe.at[index, "domain"]),
                "cohort": str(dataframe.at[index, "cohort"]),
                "repair_action": action,
                "repair_reason": reason,
                "remote_verified": verified,
                "remote_verification_error": verification_error,
            }
        )

    duplicate_mask = (
        dataframe["repository"]
        .astype(str)
        .str.casefold()
        .duplicated(keep=False)
    )

    if duplicate_mask.any():
        duplicates = dataframe.loc[
            duplicate_mask,
            ["repo_id", "repository"],
        ].to_dict("records")

        raise RuntimeError(
            "Duplicate repositories remain after repair: "
            + json.dumps(duplicates, ensure_ascii=False)
        )

    failed_subset = dataframe[
        dataframe["repo_id"].astype(str).isin(REPAIRS)
    ].copy()

    output.parent.mkdir(parents=True, exist_ok=True)
    repairs_csv.parent.mkdir(parents=True, exist_ok=True)
    failed_xlsx.parent.mkdir(parents=True, exist_ok=True)

    dataframe.to_excel(output, index=False)

    audit_dataframe = pd.DataFrame(audit_rows)
    if verify:
        audit_dataframe["remote_verified"] = audit_dataframe[
            "remote_verified"
        ].astype("boolean")

    audit_dataframe.to_csv(repairs_csv, index=False)
    failed_subset.to_excel(failed_xlsx, index=False)

    failed_remote_count = 0

    if verify:
        failed_remote_count = int(
            (~audit_dataframe["remote_verified"].fillna(False)).sum()
        )

    print(
        json.dumps(
            {
                "source_manifest": str(source),
                "repaired_manifest": str(output),
                "repair_audit": str(repairs_csv),
                "repaired_subset": str(failed_xlsx),
                "rows": len(dataframe),
                "repairs": len(REPAIRS),
                "unique_repositories": int(
                    dataframe["repository"].nunique()
                ),
                "remote_verification_enabled": bool(verify),
                "remote_verification_failures": failed_remote_count,
                "transport": transport,
            },
            indent=2,
        )
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--repairs-output", default=str(DEFAULT_REPAIRS))
    parser.add_argument("--failed-output", default=str(DEFAULT_FAILED_OUTPUT))
    parser.add_argument("--verify-remotes", action="store_true")
    parser.add_argument(
        "--transport",
        choices=["https", "ssh443"],
        default="ssh443",
    )
    args = parser.parse_args()

    repair_manifest(
        args.input,
        args.output,
        args.repairs_output,
        args.failed_output,
        args.verify_remotes,
        args.transport,
    )


if __name__ == "__main__":
    main()
