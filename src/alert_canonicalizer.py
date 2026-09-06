import ast
from collections import defaultdict
from pathlib import Path


RULE_FAMILIES = {
    ("Bandit", "B102"): "code-execution-exec",
    ("Bandit", "B108"): "hardcoded-temp-path",
    ("Bandit", "B301"): "unsafe-deserialization",
    ("Bandit", "B307"): "code-execution-eval",
    ("Bandit", "B324"): "weak-hash",
    ("Bandit", "B501"): "disabled-cert-validation",
    ("Bandit", "B602"): "subprocess-shell-true",
    ("Bandit", "B603"): "subprocess-execution",
    ("Bandit", "B608"): "dynamic-sql",
    ("Semgrep", "python.security.exec"): "code-execution-exec",
    ("Semgrep", "python.security.eval"): "code-execution-eval",
    ("Semgrep", "python.security.hardcoded-temp-path"): "hardcoded-temp-path",
    ("Semgrep", "python.security.unsafe-deserialization"): "unsafe-deserialization",
    ("Semgrep", "python.security.weak-hash"): "weak-hash",
    ("Semgrep", "python.security.disabled-cert-validation"): "disabled-cert-validation",
    ("Semgrep", "python.security.subprocess-shell-true"): "subprocess-shell-true",
    ("Semgrep", "python.security.subprocess-execution"): "subprocess-execution",
    ("Semgrep", "python.security.dynamic-sql"): "dynamic-sql",
}


def security_family(scanner, rule_id):
    return RULE_FAMILIES.get((str(scanner), str(rule_id)), f"{scanner}:{rule_id}")


def _parse_file(path):
    source = Path(path).read_text(encoding="utf-8", errors="ignore")
    return source, ast.parse(source, filename=str(path))


def _statement_span(tree, line_number):
    candidates = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.stmt):
            continue

        start = getattr(node, "lineno", None)
        end = getattr(node, "end_lineno", start)

        if start is None or end is None:
            continue

        if start <= line_number <= end:
            candidates.append((end - start, -start, start, end))

    if not candidates:
        return line_number, line_number

    _, _, start, end = min(candidates)
    return start, end


def _statement_code(source, start, end):
    lines = source.splitlines()
    start_index = max(0, start - 1)
    end_index = min(len(lines), end)
    return "\n".join(lines[start_index:end_index])


def canonicalize_alerts(alerts, repository_locations):
    parsed = {}
    enriched = []

    for alert in alerts:
        item = dict(alert)
        repository = str(item.get("repository", ""))
        filename = str(item.get("filename", ""))
        line_number = int(item.get("line_number", 0) or 0)
        repository_root = repository_locations.get(repository)

        item["security_family"] = security_family(
            item.get("scanner", ""),
            item.get("rule_id", ""),
        )

        statement_start = line_number
        statement_end = line_number
        statement_code = item.get("code_snippet", "")

        if repository_root and filename and line_number > 0:
            source_file = (Path(repository_root) / Path(filename)).resolve()
            cache_key = str(source_file)

            try:
                if cache_key not in parsed:
                    parsed[cache_key] = _parse_file(source_file)

                source, tree = parsed[cache_key]
                statement_start, statement_end = _statement_span(
                    tree,
                    line_number,
                )
                statement_code = _statement_code(
                    source,
                    statement_start,
                    statement_end,
                )
            except (OSError, SyntaxError, UnicodeError):
                pass

        item["statement_start"] = statement_start
        item["statement_end"] = statement_end
        item["statement_code"] = statement_code
        enriched.append(item)

    groups = defaultdict(list)

    for item in enriched:
        key = (
            str(item.get("repo_id", "")),
            str(item.get("repository", "")),
            str(item.get("commit_sha", "")),
            str(item.get("filename", "")),
            int(item.get("statement_start", 0) or 0),
            int(item.get("statement_end", 0) or 0),
            str(item.get("security_family", "")),
        )
        groups[key].append(item)

    canonical = []

    for index, key in enumerate(sorted(groups), start=1):
        items = groups[key]
        first = items[0]
        scanners = sorted({str(item.get("scanner", "")) for item in items})
        rule_ids = sorted({str(item.get("rule_id", "")) for item in items})
        alert_ids = sorted({str(item.get("alert_id", "")) for item in items})
        line_numbers = sorted(
            {int(item.get("line_number", 0) or 0) for item in items}
        )
        severities = sorted(
            {str(item.get("severity", "")) for item in items if str(item.get("severity", ""))}
        )
        confidences = sorted(
            {str(item.get("confidence", "")) for item in items if str(item.get("confidence", ""))}
        )
        messages = sorted(
            {str(item.get("message", "")) for item in items if str(item.get("message", ""))}
        )

        canonical.append(
            {
                "finding_id": f"FND-{index:06d}",
                "repo_id": first.get("repo_id", ""),
                "repository": first.get("repository", ""),
                "commit_sha": first.get("commit_sha", ""),
                "domain": first.get("domain", ""),
                "cohort": first.get("cohort", ""),
                "security_family": first.get("security_family", ""),
                "cwe_id": first.get("cwe_id", "CWE-UNKNOWN"),
                "filename": first.get("filename", ""),
                "statement_start": first.get("statement_start", 0),
                "statement_end": first.get("statement_end", 0),
                "line_number": first.get("statement_start", 0),
                "scanner_count": len(scanners),
                "scanners": "|".join(scanners),
                "rule_ids": "|".join(rule_ids),
                "raw_alert_count": len(items),
                "raw_alert_ids": "|".join(alert_ids),
                "reported_lines": "|".join(str(value) for value in line_numbers),
                "severity": "|".join(severities),
                "confidence": "|".join(confidences),
                "messages": " || ".join(messages),
                "statement_code": first.get("statement_code", ""),
            }
        )

    return enriched, canonical
