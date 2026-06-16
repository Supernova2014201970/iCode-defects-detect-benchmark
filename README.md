# Vulnerability Benchmark MVP

This project is generated from `vulnerability-benchmark-spec.md`.

It implements an offline MVP for evaluating vulnerability detection agents:

- manifest loading and validation
- suite-to-task generation
- deterministic mock agent adapters
- JSON output normalization
- strict vulnerability matching
- metrics, leaderboard JSON, and HTML report generation

The repository includes simulated assets because the real defect dataset has not
been imported yet.

## Quick Start

Validate manifests:

```powershell
python -m vuln_benchmark validate
```

Run the simulated benchmark:

```powershell
python -m vuln_benchmark run --run-id run_mock_validation
```

Run unit tests:

```powershell
python -m unittest discover -s tests
```

Generated outputs are written under `runs/<run_id>/`.

