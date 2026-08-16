from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def write_html_report(
    path: Path,
    run_id: str,
    tasks: list[dict[str, Any]],
    evaluations: list[dict[str, Any]],
    summary: dict[str, Any],
) -> None:
    payload = {
        "run_id": run_id,
        "task_count": len(tasks),
        "summary": summary,
        "evaluations": evaluations,
    }
    escaped = html.escape(json.dumps(payload, indent=2))
    rows = "\n".join(
        _agent_row(agent_id, item)
        for agent_id, item in summary.get("agents", {}).items()
    )
    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vulnerability Benchmark Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #202124; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th, td {{ border: 1px solid #d0d7de; padding: 8px; text-align: left; }}
    th {{ background: #f6f8fa; }}
    pre {{ background: #f6f8fa; padding: 16px; overflow: auto; }}
  </style>
</head>
<body>
  <h1>Vulnerability Benchmark Report</h1>
  <p>Run ID: <strong>{html.escape(run_id)}</strong></p>
  <p>Tasks: {len(tasks)}</p>
  <h2>Agent Summary</h2>
  <table>
    <thead>
      <tr>
        <th>Agent</th><th>Tasks</th><th>TP</th><th>FP</th><th>FN</th><th>stable(vuln)</th><th>duration_mean</th>
        <th>Precision</th><th>pstdev(precision)</th><th>Recall</th><th>pstdev(recall)</th><th>F1</th><th>Fixed Pass</th><th>Score</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>
  <h2>Raw JSON</h2>
  <pre>{escaped}</pre>
</body>
</html>
"""
    path.write_text(content, encoding="utf-8")


def _agent_row(agent_id: str, item: dict[str, Any]) -> str:
    return (
        "<tr>"
        f"<td>{html.escape(agent_id)}</td>"
        f"<td>{item['tasks']}</td>"
        f"<td>{item['tp']}</td>"
        f"<td>{item['fp']}</td>"
        f"<td>{item['fn']}</td>"
        f"<td>{_fmt(item['stable'])}</td>"
        f"<td>{_fmt(item['duration_mean'])}</td>"
        f"<td>{_fmt(item['precision'])}</td>"
        f"<td>{_fmt(item['precision_pstdev'])}</td>"
        f"<td>{_fmt(item['recall'])}</td>"
        f"<td>{_fmt(item['recall_pstdev'])}</td>"
        f"<td>{_fmt(item['f1'])}</td>"
        f"<td>{_fmt(item['fixed_check_pass_rate'])}</td>"
        f"<td>{_fmt(item.get('leaderboard_score'))}</td>"
        "</tr>"
    )


def _fmt(value: Any) -> str:
    if value is None:
        return "N/A"
    return html.escape(str(value))

