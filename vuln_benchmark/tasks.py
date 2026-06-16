from __future__ import annotations

from copy import deepcopy
from typing import Any

from .registry import Registry


def generate_tasks(registry: Registry, suite_ids: list[str] | None = None) -> list[dict[str, Any]]:
    suites = registry.suites
    selected_suites = [suites[suite_id] for suite_id in suite_ids] if suite_ids else list(suites.values())
    tasks: list[dict[str, Any]] = []
    next_number = 1

    for suite in selected_suites:
        base_tasks = _tasks_for_suite(registry, suite)
        repeat = int(suite.get("repeat", 1))
        for base_task in base_tasks:
            for repeat_index in range(1, repeat + 1):
                task = deepcopy(base_task)
                task["task_id"] = f"TASK-{next_number:06d}"
                task["repeat_index"] = repeat_index
                tasks.append(task)
                next_number += 1
    return tasks


def _tasks_for_suite(registry: Registry, suite: dict[str, Any]) -> list[dict[str, Any]]:
    mode = suite["mode"]
    if mode == "full_repo":
        return _full_repo_tasks(registry, suite)
    if mode == "diff":
        return _diff_tasks(registry, suite)
    if mode == "fixed_check":
        return _fixed_check_tasks(registry, suite)
    raise ValueError(f"Unsupported suite mode: {mode}")


def _base_task(suite: dict[str, Any], expectation: str) -> dict[str, Any]:
    return {
        "suite_id": suite["suite_id"],
        "mode": suite["mode"],
        "expectation": expectation,
        "vulnerability_hint": suite.get("vulnerability_hint", "none"),
        "scoring_scope": suite.get("scoring_scope", "target_only"),
    }


def _full_repo_tasks(registry: Registry, suite: dict[str, Any]) -> list[dict[str, Any]]:
    selection = suite.get("selection", {"scope": "all"})
    selected_vuln_ids = registry.selected_vulnerability_ids(selection)
    scope = selection.get("scope", "all")
    repo_ids = _selected_repo_ids(registry, selection, selected_vuln_ids)
    tasks: list[dict[str, Any]] = []

    for repo_id in repo_ids:
        repo_vuln_ids = {
            vuln["vuln_id"] for vuln in registry.vulnerabilities_for_repo(repo_id)
        }
        target_ids = sorted(repo_vuln_ids if scope == "all" else repo_vuln_ids & selected_vuln_ids)
        task = _base_task(suite, expectation="detect")
        task.update(
            {
                "repo_id": repo_id,
                "repo_path": registry.repo_rel_path(repo_id),
                "target_vulnerabilities": target_ids,
                "expected_absent_vulnerabilities": [],
            }
        )
        tasks.append(task)
    return tasks


def _diff_tasks(registry: Registry, suite: dict[str, Any]) -> list[dict[str, Any]]:
    selection = suite.get("selection", {"scope": "all"})
    selected_vuln_ids = registry.selected_vulnerability_ids(selection)
    scope = selection.get("scope", "all")
    explicit_diff_ids = set(selection.get("diff_ids", []))
    tasks: list[dict[str, Any]] = []

    for diff_id, diff in registry.diffs.items():
        if diff.get("kind") != "buggy_diff":
            continue
        target_ids = set(diff.get("target_vulnerabilities", []))
        if scope == "classification" and not target_ids.intersection(selected_vuln_ids):
            continue
        if scope == "explicit" and explicit_diff_ids and diff_id not in explicit_diff_ids:
            continue
        if scope == "explicit" and selected_vuln_ids and not target_ids.intersection(selected_vuln_ids):
            continue
        task = _base_task(suite, expectation="detect")
        task.update(
            {
                "diff_id": diff_id,
                "patch_path": diff["patch_path"],
                "context_repo_id": diff["context_repo_id"],
                "context_repo_path": registry.repo_rel_path(diff["context_repo_id"]),
                "target_vulnerabilities": sorted(target_ids & selected_vuln_ids)
                if scope in {"classification", "explicit"}
                else sorted(target_ids),
                "expected_absent_vulnerabilities": [],
            }
        )
        tasks.append(task)
    return tasks


def _fixed_check_tasks(registry: Registry, suite: dict[str, Any]) -> list[dict[str, Any]]:
    selection = suite.get("selection", {"scope": "all"})
    selected_vuln_ids = registry.selected_vulnerability_ids(selection)
    scope = selection.get("scope", "all")
    explicit_diff_ids = set(selection.get("fixed_diff_ids", [])) | set(selection.get("diff_ids", []))
    tasks: list[dict[str, Any]] = []

    for diff_id, diff in registry.diffs.items():
        if diff.get("kind") != "fixed_diff":
            continue
        fixed_ids = set(diff.get("fixed_vulnerabilities", []))
        if scope == "classification" and not fixed_ids.intersection(selected_vuln_ids):
            continue
        if scope == "explicit" and explicit_diff_ids and diff_id not in explicit_diff_ids:
            continue
        absent_ids = sorted(fixed_ids & selected_vuln_ids) if scope in {"classification", "explicit"} else sorted(fixed_ids)
        if selection.get("only_with_fix_artifact", False) and not absent_ids:
            continue
        task = _base_task(suite, expectation="fixed")
        task["mode"] = "diff"
        task["check_type"] = "fixed_check"
        task.update(
            {
                "diff_id": diff_id,
                "patch_path": diff["patch_path"],
                "context_repo_id": diff["context_repo_id"],
                "context_repo_path": registry.repo_rel_path(diff["context_repo_id"]),
                "target_vulnerabilities": [],
                "expected_absent_vulnerabilities": absent_ids,
            }
        )
        tasks.append(task)
    return tasks


def _selected_repo_ids(
    registry: Registry,
    selection: dict[str, Any],
    selected_vuln_ids: set[str],
) -> list[str]:
    scope = selection.get("scope", "all")
    if scope == "all":
        return sorted(registry.repositories)
    if scope == "explicit" and selection.get("repo_ids"):
        return sorted(selection["repo_ids"])
    repo_ids = {
        registry.vulnerabilities[vuln_id]["repo_id"]
        for vuln_id in selected_vuln_ids
        if vuln_id in registry.vulnerabilities
    }
    return sorted(repo_ids)

