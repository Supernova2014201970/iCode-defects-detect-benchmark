from pathlib import Path

from vuln_benchmark.runner import run_benchmark


if __name__ == "__main__":
    result = run_benchmark(Path(__file__).resolve().parents[1], run_id="run_mock_validation")
    print(result["run_dir"])

