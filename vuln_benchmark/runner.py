from __future__ import annotations

import json
try:
    from tqdm import tqdm
except ImportError:
    print("tqdm not found")
    def tqdm(iterable, **kwargs):
        return iterable
import multiprocessing
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


def executeSubTask(subTask):
    root_path = subTask["root_path"]
    run_dir = subTask["run_dir"]
    registry = subTask["registry"]
    agent = subTask["agent"]
    task = subTask["task"]

    raw_path = run_dir / "raw_outputs" / agent["agent_id"] / f"{task['task_id']}.json"
    adapter = get_adapter(agent["adapter"])

    raw_output = adapter.run(task, agent, registry, root_path, raw_path)

    normalized = normalize_raw_output(raw_output, task, agent["agent_id"], registry)
    normalized_path = run_dir / "normalized_outputs" / agent["agent_id"] / f"{task['task_id']}.json"
    normalized_path.parent.mkdir(parents=True, exist_ok=True)
    _write_json(normalized_path, normalized)

    return evaluate_task(registry, task, normalized)


def executeSubTaskMultiprocessing(SubTaskList):

    with multiprocessing.Pool(processes=1) as pool:
        #results = pool.map(executeSubTask, SubTaskList)
        results = list(tqdm(pool.imap_unordered(executeSubTask, SubTaskList), total=len(SubTaskList)))
    return results

def run_benchmark(
    root: str | Path = ".",
    repo_root: str | Path = "../defects-applications/",
    suite_ids: list[str] | None = None,
    agent_ids: list[str] | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    root_path = Path(root).resolve()
    registry = Registry.load(root_path, repo_root)
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
    sub_task_list = []
    for agent in agents:
        tool_profile = profiles[agent["tool_profile"]]
        for task in tasks:
            # 生成任务，加入列表
            sub_task = {
                "root_path": root_path,
                "run_dir": run_dir,
                "registry": registry,
                "agent": agent,
                "task": task
            }
            sub_task_list.append(sub_task)

    # 多线程执行任务
    print("start time: ", datetime.now())
    evaluations = executeSubTaskMultiprocessing(sub_task_list)

    print("end time: ", datetime.now())

    count = sum(1 for item in evaluations if item.get("status") != "success")
    print(f"sub_task failed for: {count}  out of: {len(sub_task_list)}")

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
