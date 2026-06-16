from __future__ import annotations

import argparse
import json
from pathlib import Path

from .registry import Registry
from .runner import run_benchmark
from .tasks import generate_tasks
from .validation import validate_registry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vuln_benchmark")
    parser.add_argument("--root", default=".", help="Benchmark project root")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("validate", help="Validate manifests and assets")

    task_parser = subparsers.add_parser("generate-tasks", help="Generate tasks from suites")
    task_parser.add_argument("--suite", action="append", dest="suite_ids")

    run_parser = subparsers.add_parser("run", help="Run benchmark")
    run_parser.add_argument("--suite", action="append", dest="suite_ids")
    run_parser.add_argument("--agent", action="append", dest="agent_ids")
    run_parser.add_argument("--run-id")

    args = parser.parse_args(argv)
    root = Path(args.root)

    if args.command == "validate":
        registry = Registry.load(root)
        result = validate_registry(registry)
        for warning in result.warnings:
            print(f"WARNING: {warning}")
        for error in result.errors:
            print(f"ERROR: {error}")
        print("OK" if result.ok else "FAILED")
        return 0 if result.ok else 1

    if args.command == "generate-tasks":
        registry = Registry.load(root)
        tasks = generate_tasks(registry, suite_ids=args.suite_ids)
        print(json.dumps({"tasks": tasks}, indent=2))
        return 0

    if args.command == "run":
        result = run_benchmark(
            root=root,
            suite_ids=args.suite_ids,
            agent_ids=args.agent_ids,
            run_id=args.run_id,
        )
        print(json.dumps(result, indent=2))
        return 0

    return 1

