import unittest
from pathlib import Path

from vuln_benchmark.evaluator import evaluate_task
from vuln_benchmark.registry import Registry
from vuln_benchmark.tasks import generate_tasks


ROOT = Path(__file__).resolve().parents[1]


class EvaluatorTest(unittest.TestCase):
    def setUp(self):
        self.registry = Registry.load(ROOT)

    def test_alias_and_function_match_counts_as_tp(self):
        task = generate_tasks(self.registry, ["suite_command_injection_diff"])[0]
        normalized = {
            "task_id": task["task_id"],
            "agent_id": "agent",
            "status": "success",
            "findings": [
                {
                    "finding_id": "F-001",
                    "type": "os_command_injection",
                    "file": "src/main/java/com/example/ExecController.java",
                    "function": "runCommand",
                }
            ],
            "run_metadata": {},
        }
        result = evaluate_task(self.registry, task, normalized)
        self.assertEqual(result["tp"], ["VULN-000001"])
        self.assertEqual(result["fn"], [])

    def test_duplicate_does_not_count_as_fp_by_default(self):
        task = generate_tasks(self.registry, ["suite_command_injection_diff"])[0]
        finding = {
            "type": "command_injection",
            "cwe": ["CWE-78"],
            "file": "src/main/java/com/example/ExecController.java",
            "function": "runCommand",
        }
        normalized = {
            "task_id": task["task_id"],
            "agent_id": "agent",
            "status": "success",
            "findings": [dict(finding, finding_id="F-001"), dict(finding, finding_id="F-002")],
            "run_metadata": {},
        }
        result = evaluate_task(self.registry, task, normalized)
        self.assertEqual(result["tp"], ["VULN-000001"])
        self.assertEqual(len(result["duplicates"]), 1)
        self.assertEqual(result["fp"], [])

    def test_fixed_check_fails_when_absent_vulnerability_is_reported(self):
        task = generate_tasks(self.registry, ["suite_all_fixed_check"])[0]
        normalized = {
            "task_id": task["task_id"],
            "agent_id": "agent",
            "status": "success",
            "findings": [
                {
                    "finding_id": "F-001",
                    "type": "command_injection",
                    "cwe": ["CWE-78"],
                    "file": "src/main/java/com/example/ExecController.java",
                    "function": "runCommand",
                }
            ],
            "run_metadata": {},
        }
        result = evaluate_task(self.registry, task, normalized)
        self.assertFalse(result["fixed_check_passed"])
        self.assertEqual(result["fixed_failures"], ["VULN-000001"])


if __name__ == "__main__":
    unittest.main()

