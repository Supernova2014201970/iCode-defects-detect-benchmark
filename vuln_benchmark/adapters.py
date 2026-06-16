from __future__ import annotations

import json
import time
from typing import Any

from .registry import Registry


class MockAgentAdapter:
    """Deterministic adapter used before real agents are connected."""

    def run(
        self,
        task: dict[str, Any],
        agent_config: dict[str, Any],
        tool_profile: dict[str, Any],
        registry: Registry,
    ) -> str:
        started = time.perf_counter()
        behavior = agent_config.get("behavior", "exact")
        if behavior == "invalid":
            return "this is not valid json"

        findings = _findings_for_behavior(behavior, task, registry)
        duration = round(time.perf_counter() - started, 6)
        payload = {
            "task_id": task["task_id"],
            "agent_id": agent_config["agent_id"],
            "status": "success",
            "findings": findings,
            "run_metadata": {
                "duration_seconds": duration,
                "cost": None,
                "input_tokens": None,
                "output_tokens": None,
            },
        }
        return json.dumps(payload, indent=2)


def get_adapter(adapter_name: str) -> MockAgentAdapter:
    if adapter_name == "adapters.mock":
        return MockAgentAdapter()
    raise ValueError(f"Unsupported adapter: {adapter_name}")


def _findings_for_behavior(
    behavior: str,
    task: dict[str, Any],
    registry: Registry,
) -> list[dict[str, Any]]:
    if behavior == "exact":
        if task.get("expectation") == "fixed":
            return []
        return [_finding_for_vulnerability(registry.vulnerabilities[vuln_id]) for vuln_id in task.get("target_vulnerabilities", [])]

    if behavior == "partial":
        if task.get("expectation") == "fixed":
            return []
        target_ids = list(task.get("target_vulnerabilities", []))
        if not target_ids:
            return []
        vulnerability = registry.vulnerabilities[target_ids[0]]
        if vulnerability["classification"]["issue_subcategory"] != "command_injection":
            return []
        finding = _finding_for_vulnerability(vulnerability)
        if finding["type"] == "command_injection":
            finding.pop("cwe", None)
            finding["type"] = "os_command_injection"
        return [finding]

    if behavior == "noisy":
        findings: list[dict[str, Any]] = []
        if task.get("expectation") == "fixed":
            for vuln_id in task.get("expected_absent_vulnerabilities", []):
                findings.append(_finding_for_vulnerability(registry.vulnerabilities[vuln_id]))
        else:
            findings.extend(
                _finding_for_vulnerability(registry.vulnerabilities[vuln_id])
                for vuln_id in task.get("target_vulnerabilities", [])
            )
        findings.append(_false_positive_finding(task))
        return findings

    return []


def _finding_for_vulnerability(vulnerability: dict[str, Any]) -> dict[str, Any]:
    location = vulnerability["location"]
    classification = vulnerability["classification"]
    finding: dict[str, Any] = {
        "type": classification["issue_subcategory"],
        "cwe": classification.get("cwe", []),
        "file": location["file"],
        "start_line": location["start_line"],
        "end_line": location["end_line"],
    }
    if location.get("function"):
        finding["function"] = location["function"]
    return finding


def _false_positive_finding(task: dict[str, Any]) -> dict[str, Any]:
    if task.get("context_repo_id") == "repo_002" or task.get("repo_id") == "repo_002":
        file_path = "src/app.py"
    else:
        file_path = "src/main/java/com/example/ExecController.java"
    return {
        "type": "sql_injection",
        "cwe": ["CWE-89"],
        "file": file_path,
        "function": "unused",
        "start_line": 1,
        "end_line": 1,
    }
