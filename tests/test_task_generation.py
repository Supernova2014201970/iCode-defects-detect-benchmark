import unittest
from pathlib import Path

from vuln_benchmark.registry import Registry
from vuln_benchmark.tasks import generate_tasks


ROOT = Path(__file__).resolve().parents[1]


class TaskGenerationTest(unittest.TestCase):
    def setUp(self):
        self.registry = Registry.load(ROOT)

    def test_full_repo_all_generates_clean_and_vulnerable_tasks(self):
        tasks = generate_tasks(self.registry, ["suite_all_full_repo"])
        self.assertEqual(len(tasks), 4)
        clean_tasks = [task for task in tasks if not task["target_vulnerabilities"]]
        self.assertEqual({task["repo_id"] for task in clean_tasks}, {"repo_001_fixed", "repo_003_clean"})

    def test_diff_all_uses_buggy_diffs_only(self):
        tasks = generate_tasks(self.registry, ["suite_all_diff"])
        self.assertEqual({task["diff_id"] for task in tasks}, {"DIFF-000001", "DIFF-000002"})

    def test_fixed_check_uses_fixed_diff(self):
        tasks = generate_tasks(self.registry, ["suite_all_fixed_check"])
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["diff_id"], "DIFF-000001-FIX")
        self.assertEqual(tasks[0]["expected_absent_vulnerabilities"], ["VULN-000001"])


if __name__ == "__main__":
    unittest.main()

