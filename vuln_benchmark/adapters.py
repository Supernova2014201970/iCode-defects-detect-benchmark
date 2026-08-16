from __future__ import annotations

import os
import sys
import json
import time
import subprocess
from typing import Any
from tenacity import retry, stop_after_attempt, wait_fixed

from .registry import Registry

def get_vuln(path):
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
        return data["vulnerabilities"]
    except Exception as e:
        print(f"打开文件错误: {path}", flush=True)
    return []

class MockAgentAdapter:
    """Deterministic adapter used before real agents are connected."""

    def run(
        self,
        task: dict[str, Any],
        agent_config: dict[str, Any],
        registry: Registry,
        root_path: str,
        raw_path: str
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
        ret_str = json.dumps(payload, indent=2)

        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(ret_str, encoding="utf-8")
        return ret_str
    
def run_agent(cmd, timeout_sec):
    try:
        print("\nstart run cmd: ", cmd, flush=True)
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )
        stdout, stderr = proc.communicate(timeout = timeout_sec)
        time.sleep(5)  # 等待agent写入文件，避免FileNotFoundError
        if proc.returncode != 0:
            print("---", proc.returncode, flush=True)
            print("out: ", stdout, flush=True)
            print("err: ", stderr, flush=True)
        return proc.returncode
    except subprocess.TimeoutExpired:
        print(f"命令执行超过 {timeout_sec} 秒，正在终止...", flush=True)
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    except Exception as e:
        print(f"执行命令时发生未知错误: {e}", file=sys.stderr, flush=True)
    raise Exception("throw exception ...")

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def run_agent_retry(cmd, timeout_sec):
    return run_agent(cmd, timeout_sec)

class AgentAdapter:

    def get_prompt(self, agent_config, task, root_path, format, jsonFile):
        prompt = agent_config["prompt"]
        if task["mode"] == "diff":
            prompt = agent_config["diff_prompt"]
            prompt = prompt.replace("patch", str(root_path / task["patch_path"]))
            prompt = prompt.replace("project", str(root_path / task["context_repo_path"]))
        elif task["mode"] == "fixed_check":
            prompt = agent_config["fix_prompt"]
            prompt = prompt.replace("patch", str(root_path / task["patch_path"]))
            prompt = prompt.replace("project", str(root_path / task["context_repo_path"]))
        else:
            prompt = prompt.replace("project", str(root_path / task["repo_path"]))

        return '"' + prompt.replace("format", str(format)).replace("jsonFile", str(jsonFile)) + '"'
    

    def run(
        self,
        task: dict[str, Any],
        agent_config: dict[str, Any],
        registry: Registry,
        root_path: str,
        raw_path: str
    ) -> str:
        started = time.perf_counter()
        behavior = agent_config.get("behavior", "exact")
        if behavior == "invalid":
            return "this is not valid json"

        raw_path.parent.mkdir(parents=True, exist_ok=True)
        format_file = root_path / f"manifests/format.json"

        
        prompt = self.get_prompt(agent_config, task, registry.repo_root, format_file, raw_path)

        command = list(agent_config["command"])
        command.append(prompt.replace("\\", "/"))
        try:
            run_agent_retry(command, agent_config["timeout_seconds"])
        except Exception as e:
            print("\nfailed cmd: ", command, flush=True)

        duration = round(time.perf_counter() - started, 6)
        status = "failed"
        findings = []
        if os.path.exists(raw_path):
            status = "success"
            findings = get_vuln(raw_path)
        payload = {
            "task_id": task["task_id"],
            "agent_id": agent_config["agent_id"],
            "status": status,
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
    if adapter_name == "chrys":
        return AgentAdapter()
    if adapter_name == "opencode":
        return AgentAdapter()
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
