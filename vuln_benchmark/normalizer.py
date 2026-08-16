from __future__ import annotations

import json
from typing import Any


def normalize_raw_output(raw_output: str, task: dict[str, Any], agent_id: str, registry) -> dict[str, Any]:
    try:
        payload = json.loads(raw_output)
    except json.JSONDecodeError:
        return _empty_result(task, agent_id, "parse_failed")

    if not isinstance(payload, dict):
        return _empty_result(task, agent_id, "invalid_output")

    status = payload.get("status", "success")
    findings = payload.get("findings", [])
    if status != "success":
        return _empty_result(task, agent_id, status)
    if not isinstance(findings, list):
        return _empty_result(task, agent_id, "invalid_output")

    normalized_findings: list[dict[str, Any]] = []
    for index, finding in enumerate(findings, start=1):
        if not isinstance(finding, dict):
            return _empty_result(task, agent_id, "invalid_output")
        # item = dict(finding)
        item = {
            "type": finding["type"],
            "cwe": get_cwe_by_type(finding["type"], registry.manifests),
            "file": finding["file"],
            "line": finding["line"],
            "start_line": finding["start_line"],
            "end_line": finding["end_line"],
            "function": finding["function"]
        }
        item.setdefault("finding_id", f"F-{index:03d}")
        if "end_line" not in item and "start_line" in item:
            item["end_line"] = item["start_line"]
        normalized_findings.append(item)

    return {
        "task_id": task["task_id"],
        "agent_id": agent_id,
        "status": "success",
        "findings": normalized_findings,
        "run_metadata": payload.get("run_metadata", {}),
    }

def get_cwe_by_type(type, manifests):
    classification_mapping = manifests["classification_mapping"]["mappings"]
    for category in classification_mapping:
        if type == category["issue_subcategory"]:
            return category["cwe"]
        if type in category["aliases"]:
            return category["cwe"]
    return []



def _empty_result(task: dict[str, Any], agent_id: str, status: str) -> dict[str, Any]:
    return {
        "task_id": task["task_id"],
        "agent_id": agent_id,
        "status": status,
        "findings": [],
        "run_metadata": {},
    }

