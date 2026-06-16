from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .registry import Registry


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def validate_registry(registry: Registry) -> ValidationResult:
    result = ValidationResult()
    _validate_unique(
        "repo_id",
        [repo.get("repo_id") for repo in registry.manifests["repositories"].get("repositories", [])],
        result,
    )
    _validate_unique(
        "vuln_id",
        [
            vuln.get("vuln_id")
            for vuln in registry.manifests["vulnerabilities"].get("vulnerabilities", [])
        ],
        result,
    )
    _validate_unique(
        "diff_id",
        [diff.get("diff_id") for diff in registry.manifests["diffs"].get("diffs", [])],
        result,
    )

    repos = registry.repositories
    vulnerabilities = registry.vulnerabilities

    for repo_id, repo in repos.items():
        repo_path = registry.root / repo["path"]
        if not repo_path.exists():
            result.errors.append(f"Repository path does not exist: {repo_id} -> {repo['path']}")
        relation = repo.get("relation")
        if relation:
            of_repo_id = relation.get("of_repo_id")
            if of_repo_id and of_repo_id not in repos:
                result.errors.append(f"Repository {repo_id} relation points to missing repo {of_repo_id}")
            for vuln_id in relation.get("fixes", []):
                if vuln_id not in vulnerabilities:
                    result.errors.append(f"Repository {repo_id} fixes missing vulnerability {vuln_id}")

    mapping_keys = {
        (
            item.get("domain_category"),
            item.get("issue_category"),
            item.get("issue_subcategory"),
        )
        for item in registry.mappings
    }

    for vuln_id, vuln in vulnerabilities.items():
        repo_id = vuln.get("repo_id")
        if repo_id not in repos:
            result.errors.append(f"Vulnerability {vuln_id} references missing repo {repo_id}")
            continue
        location = vuln.get("location", {})
        if location.get("start_line", 0) > location.get("end_line", 0):
            result.errors.append(f"Vulnerability {vuln_id} has start_line > end_line")
        rel_file = location.get("file")
        if rel_file:
            abs_file = registry.repo_abs_path(repo_id) / Path(rel_file)
            if not abs_file.exists():
                result.errors.append(f"Vulnerability {vuln_id} file does not exist: {rel_file}")
            else:
                line_count = len(abs_file.read_text(encoding="utf-8").splitlines())
                if location.get("end_line", 0) > line_count:
                    result.errors.append(
                        f"Vulnerability {vuln_id} end_line exceeds file length: "
                        f"{location.get('end_line')} > {line_count}"
                    )
        classification = vuln.get("classification", {})
        key = (
            classification.get("domain_category"),
            classification.get("issue_category"),
            classification.get("issue_subcategory"),
        )
        if key not in mapping_keys:
            result.warnings.append(f"Vulnerability {vuln_id} classification has no mapping: {key}")

    for diff_id, diff in registry.diffs.items():
        patch_path = registry.root / diff["patch_path"]
        if not patch_path.exists():
            result.errors.append(f"Diff patch does not exist: {diff_id} -> {diff['patch_path']}")
        context_repo_id = diff.get("context_repo_id")
        if context_repo_id not in repos:
            result.errors.append(f"Diff {diff_id} references missing context repo {context_repo_id}")
        if diff.get("kind") == "buggy_diff":
            _validate_vulnerability_refs(
                result,
                f"Diff {diff_id} target_vulnerabilities",
                diff.get("target_vulnerabilities", []),
                vulnerabilities,
            )
        elif diff.get("kind") == "fixed_diff":
            _validate_vulnerability_refs(
                result,
                f"Diff {diff_id} fixed_vulnerabilities",
                diff.get("fixed_vulnerabilities", []),
                vulnerabilities,
            )
        else:
            result.errors.append(f"Diff {diff_id} has unsupported kind: {diff.get('kind')}")

    for suite_id, suite in registry.suites.items():
        try:
            from .tasks import generate_tasks

            tasks = generate_tasks(registry, suite_ids=[suite_id])
        except Exception as exc:  # pragma: no cover - defensive diagnostic
            result.errors.append(f"Suite {suite_id} cannot be generated: {exc}")
            continue
        if not tasks:
            result.warnings.append(f"Suite {suite_id} resolves to zero tasks")

    return result


def _validate_unique(field_name: str, values: list[str | None], result: ValidationResult) -> None:
    seen: set[str] = set()
    for value in values:
        if not value:
            result.errors.append(f"Missing required id field: {field_name}")
            continue
        if value in seen:
            result.errors.append(f"Duplicate {field_name}: {value}")
        seen.add(value)


def _validate_vulnerability_refs(
    result: ValidationResult,
    label: str,
    refs: list[str],
    vulnerabilities: dict[str, dict],
) -> None:
    for vuln_id in refs:
        if vuln_id not in vulnerabilities:
            result.errors.append(f"{label} references missing vulnerability {vuln_id}")
