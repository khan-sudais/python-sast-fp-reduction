import hashlib
from pathlib import Path


def _excluded_set(excluded_directory_names):
    return {
        str(value).strip().casefold()
        for value in excluded_directory_names or []
        if str(value).strip()
    }


def collect_python_targets(target, excluded_directory_names=None):
    target_path = Path(target).resolve()

    if not target_path.exists():
        raise FileNotFoundError(f"Target does not exist: {target_path}")

    if target_path.is_file():
        if target_path.suffix.casefold() != ".py":
            return []
        return [target_path]

    excluded = _excluded_set(excluded_directory_names)
    targets = []

    for path in target_path.rglob("*.py"):
        if not path.is_file():
            continue

        relative = path.relative_to(target_path)

        if any(part.casefold() in excluded for part in relative.parts[:-1]):
            continue

        targets.append(path.resolve())

    return sorted(
        targets,
        key=lambda item: item.relative_to(target_path).as_posix().casefold(),
    )


def relative_target_manifest(repository_root, targets):
    root = Path(repository_root).resolve()
    return [
        Path(target).resolve().relative_to(root).as_posix()
        for target in targets
    ]


def target_manifest_sha256(relative_paths):
    payload = "\n".join(relative_paths).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def chunk_paths(paths, fixed_arguments=None, max_characters=24000):
    fixed = sum(len(str(value)) + 1 for value in fixed_arguments or [])
    chunks = []
    current = []
    current_length = fixed

    for path in paths:
        value = str(Path(path).resolve())
        size = len(value) + 3

        if current and current_length + size > max_characters:
            chunks.append(current)
            current = []
            current_length = fixed

        current.append(Path(path).resolve())
        current_length += size

    if current:
        chunks.append(current)

    return chunks
