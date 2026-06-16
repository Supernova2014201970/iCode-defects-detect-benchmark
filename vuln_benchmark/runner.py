from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .adapters import get_adapter
from .evaluator import evaluate_task
from .metrics import aggregate
from .normalizer import normalize_raw_output
from .registry import Registry
from .report import write_html_report
from .tasks import generate_tasks
from .validation import validate_registry


def run_benchmark(
    root: str | Path = ".",
    suite_ids: list[str] | None = None,
    agent_ids: list[str] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root).resolve()
    registry = Registry.load(root_path)
    validation = validate_registry(registry)
    if not validation.ok:
        raise RuntimeError("Manifest validation failed: " + "; ".join(validation.errors))

    run_id = run_id or datetime.now().strftime("run_%Y%m%d_%H%M%S")
    run_dir = root_path / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    tasks = generate_tasks(registry, suite_ids=suite_ids)
    _write_json(run_dir / "tasks.json", {"tasks": tasks})

    agents = _load_config(root_path / "configs" / "agents.json").get("agents", [])
    profiles = {
        item["profile_id"]: item
        for item in _load_config(root_path / "configs" / "tool_profiles.json").get("profiles", [])
    }
    if agent_ids:
        selected = set(agent_ids)
        agents = [agent for agent in agents if agent["agent_id"] in selected]
    if not agents:
        raise RuntimeError("No agents selected")

    evaluations: list[dict[str, Any]] = []
    for agent in agents:
        adapter = get_adapter(agent["adapter"])
        tool_profile = profiles[agent["tool_profile"]]
        for task in tasks:
            raw_output = adapter.run(task, agent, tool_profile, registry)
            raw_path = run_dir / "raw_outputs" / agent["agent_id"] / f"{task['task_id']}.txt"
            raw_path.parent.mkdir(parents=True, exist_ok=True)
            raw_path.write_text(raw_output, encoding="utf-8")

            normalized = normalize_raw_output(raw_output, task, agent["agent_id"])
            normalized_path = (
                run_dir
                / "normalized_outputs"
                / agent["agent_id"]
                / f"{task['task_id']}.json"
            )
            normalized_path.parent.mkdir(parents=True, exist_ok=True)
            _write_json(normalized_path, normalized)

            evaluations.append(evaluate_task(registry, task, normalized))

    summary = aggregate(evaluations, registry)
    metrics = {
        "run_id": run_id,
        "tasks": len(tasks),
        "agents": [agent["agent_id"] for agent in agents],
        "validation_warnings": validation.warnings,
        "summary": summary,
        "task_results": evaluations,
    }
    _write_json(run_dir / "metrics.json", metrics)
    _write_json(run_dir / "leaderboard.json", summary["leaderboards"])
    write_html_report(run_dir / "report.html", run_id, tasks, evaluations, summary)

    return {
        "run_id": run_id,
        "run_dir": str(run_dir),
        "task_count": len(tasks),
        "agent_count": len(agents),
        "metrics": metrics,
    }


def _load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
