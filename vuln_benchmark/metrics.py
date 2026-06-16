from __future__ import annotations

from collections import defaultdict
from statistics import mean
from typing import Any

from .registry import Registry


def aggregate(evaluations: list[dict[str, Any]], registry: Registry | None = None) -> dict[str, Any]:
    by_agent = _group_by(evaluations, lambda item: item["agent_id"])
    by_agent_mode = _group_by(
        evaluations,
        lambda item: f"{item['agent_id']}::{item['mode']}",
    )

    agent_summary = {
        agent_id: _summarize(items)
        for agent_id, items in sorted(by_agent.items())
    }
    mode_summary = {
        key: _summarize(items)
        for key, items in sorted(by_agent_mode.items())
    }
    for summary in agent_summary.values():
        summary["leaderboard_score"] = _score(summary)
    for summary in mode_summary.values():
        summary["leaderboard_score"] = _score(summary)

    return {
        "agents": agent_summary,
        "agent_modes": mode_summary,
        "leaderboards": _leaderboards(
            agent_summary,
            mode_summary,
            _classification_board(evaluations, registry) if registry else [],
        ),
    }


def _group_by(
    items: list[dict[str, Any]],
    key_fn,
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        grouped[key_fn(item)].append(item)
    return grouped


def _summarize(items: list[dict[str, Any]]) -> dict[str, Any]:
    tp = sum(len(item["tp"]) for item in items)
    fp = sum(len(item["fp"]) for item in items)
    fn = sum(len(item["fn"]) for item in items)
    duplicates = sum(len(item["duplicates"]) for item in items)
    invalid = sum(1 for item in items if item.get("invalid_output"))
    review_candidates = sum(len(item["review_candidates"]) for item in items)
    fixed_items = [item for item in items if item.get("fixed_check_passed") is not None]
    fixed_passed = sum(1 for item in fixed_items if item.get("fixed_check_passed"))
    durations = [
        float(item["duration_seconds"])
        for item in items
        if item.get("duration_seconds") is not None
    ]

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    return {
        "tasks": len(items),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "duplicates": duplicates,
        "invalid_outputs": invalid,
        "review_candidates": review_candidates,
        "precision": precision,
        "recall": recall,
        "f1": _f1(precision, recall),
        "fixed_check_pass_rate": _safe_div(fixed_passed, len(fixed_items)),
        "duration_mean": round(mean(durations), 6) if durations else None,
        "duration_p95": _percentile(durations, 0.95) if durations else None,
        "leaderboard_score": None,
    }


def _leaderboards(
    agent_summary: dict[str, dict[str, Any]],
    mode_summary: dict[str, dict[str, Any]],
    classification_board: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    boards = {
        "all_tasks_leaderboard": [
            _leaderboard_row(agent_id, summary)
            for agent_id, summary in agent_summary.items()
        ],
        "full_repo_leaderboard": _mode_board(mode_summary, "full_repo"),
        "diff_leaderboard": _mode_board(mode_summary, "diff"),
        "fixed_check_leaderboard": _mode_board(mode_summary, "fixed_check"),
        "classification_leaderboard": classification_board,
    }
    for rows in boards.values():
        if isinstance(rows, list):
            rows.sort(key=lambda item: item.get("leaderboard_score") or 0, reverse=True)
    return boards


def _mode_board(
    mode_summary: dict[str, dict[str, Any]],
    mode: str,
) -> list[dict[str, Any]]:
    rows = []
    suffix = f"::{mode}"
    for key, summary in mode_summary.items():
        if key.endswith(suffix):
            rows.append(_leaderboard_row(key.split("::", 1)[0], summary))
    return rows


def _leaderboard_row(agent_id: str, summary: dict[str, Any]) -> dict[str, Any]:
    row = dict(summary)
    row["agent_id"] = agent_id
    row["leaderboard_score"] = summary.get("leaderboard_score")
    return row


def _classification_board(
    evaluations: list[dict[str, Any]],
    registry: Registry,
) -> list[dict[str, Any]]:
    buckets: dict[str, dict[str, Any]] = {}
    for item in evaluations:
        if item.get("expectation") != "detect":
            continue
        target_ids = set(item.get("tp", [])) | set(item.get("fn", []))
        classes = {_classification_key(registry, vuln_id) for vuln_id in target_ids}
        if not classes and item.get("fp"):
            classes = {"clean_or_unmapped"}
        for class_key in classes:
            bucket_key = f"{item['agent_id']}::{class_key}"
            bucket = buckets.setdefault(
                bucket_key,
                {
                    "agent_id": item["agent_id"],
                    "classification": class_key,
                    "tasks": 0,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "duplicates": 0,
                    "invalid_outputs": 0,
                    "review_candidates": 0,
                    "fixed_check_pass_rate": None,
                    "duration_mean": None,
                    "duration_p95": None,
                },
            )
            bucket["tasks"] += 1
            bucket["tp"] += sum(
                1 for vuln_id in item.get("tp", []) if _classification_key(registry, vuln_id) == class_key
            )
            bucket["fn"] += sum(
                1 for vuln_id in item.get("fn", []) if _classification_key(registry, vuln_id) == class_key
            )
            bucket["fp"] += len(item.get("fp", []))
            bucket["duplicates"] += len(item.get("duplicates", []))
            bucket["invalid_outputs"] += 1 if item.get("invalid_output") else 0
            bucket["review_candidates"] += len(item.get("review_candidates", []))

    rows = []
    for bucket in buckets.values():
        precision = _safe_div(bucket["tp"], bucket["tp"] + bucket["fp"])
        recall = _safe_div(bucket["tp"], bucket["tp"] + bucket["fn"])
        bucket["precision"] = precision
        bucket["recall"] = recall
        bucket["f1"] = _f1(precision, recall)
        bucket["leaderboard_score"] = _score(bucket)
        rows.append(bucket)
    rows.sort(
        key=lambda item: (
            item["classification"],
            -(item.get("leaderboard_score") or 0),
            item["agent_id"],
        )
    )
    return rows


def _classification_key(registry: Registry, vuln_id: str) -> str:
    classification = registry.vulnerabilities[vuln_id]["classification"]
    return "/".join(
        [
            classification.get("domain_category", "unknown"),
            classification.get("issue_category", "unknown"),
            classification.get("issue_subcategory", "unknown"),
        ]
    )


def _score(summary: dict[str, Any]) -> float:
    recall = summary.get("recall")
    precision = summary.get("precision")
    fixed = summary.get("fixed_check_pass_rate")
    score = (
        0.50 * (recall if recall is not None else 1.0)
        + 0.25 * (precision if precision is not None else 1.0)
        + 0.10 * (fixed if fixed is not None else 1.0)
        + 0.10
        + 0.05
    )
    return round(score, 6)


def _safe_div(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 6)


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or precision + recall == 0:
        return None
    return round(2 * precision * recall / (precision + recall), 6)


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile)))
    return round(ordered[index], 6)
