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

格式说明：python vuln_benchmark [-h] [--root ROOT] [--repo-root REPO_ROOT] {validate,generate-tasks,run} ...
例如：python -m vuln_benchmark --repo-root D:/Work/Coding/defects-applications run --run-id run_0

Validate manifests:

```powershell
python -m vuln_benchmark validate
```

check tasks:

```powershell
python -m vuln_benchmark generate-tasks
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


## 使用场景

### 全仓扫描

1.配置本次评测集，格式如下
```json
    {
      "suite_id": "suite_all_full_repo",
      "mode": "full_repo",
      "selection": {
        "scope": "all"
      },
      "repeat": 1,
      "vulnerability_hint": "none",
      "scoring_scope": "all_known"
    }
```

2.配置repositiories.json
```json
    {
      "repo_id": "repo_001",
      "path": "artifacts/repos/repo_001"
    }
```

3.配置待测agent，格式如下
```json
    {
      "agent_id": "chrys_default",
      "agent_type": "chrys",
      "model": "deterministic",
      "adapter": "chrys",
      "command": ["chrys", "run", "-a", "Code"],
      "prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的命令注入（Command Injection）风险。请对project项目进行深度扫描，挖掘其中的风险点，并将发现的所有风险严格按照format格式输出到项目目录下jsonFile中。",
      "behavior": "exact",
      "tool_profile": "static_readonly",
      "timeout_seconds": 7200,
      "max_output_bytes": 1048576
    }
```

### diff扫描

1.配置本次评测集，格式如下
```json
    {
      "suite_id": "suite_all_diff",
      "mode": "diff",
      "selection": {
        "scope": "all"
      },
      "repeat": 1,
      "vulnerability_hint": "none",
      "scoring_scope": "target_only"
    }
```

2.配置repositiories.json
```json
    {
      "repo_id": "repo_001",
      "path": "artifacts/repos/repo_001"
    }
```

3.配置待测agent，格式如下
```json
    {
      "agent_id": "chrys_default",
      "agent_type": "chrys",
      "model": "deterministic",
      "adapter": "chrys",
      "command": ["chrys", "run", "-a", "Code"],
      "prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的命令注入（Command Injection）风险。请对project项目进行深度扫描，挖掘其中的风险点，并将发现的所有风险严格按照format格式输出到项目目录下jsonFile中。",
      "diff_prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的命令注入（Command Injection）风险。请对git diff格式的patch包中代码变更内容及project目录下源代码信息进行深度分析，将本次变更引入的所有风险严格按照format格式输出到项目目录下jsonFile中。",
      "behavior": "exact",
      "tool_profile": "static_readonly",
      "timeout_seconds": 7200,
      "max_output_bytes": 1048576
    }
```

4.配置patch包及预期引入的告警
```json
    {
      "diff_id": "DIFF-000001",
      "patch_path": "artifacts/diffs/diff_001_bug.patch",
      "context_repo_id": "repo_001",
      "kind": "buggy_diff",
      "target_vulnerabilities": ["VULN-000001"]
    }
```

### fix扫描

1.配置本次评测集，格式如下
```json
    {
      "suite_id": "suite_all_fixed_check",
      "mode": "fixed_check",
      "selection": {
        "scope": "all",
        "only_with_fix_artifact": true
      },
      "repeat": 1,
      "vulnerability_hint": "none",
      "scoring_scope": "target_only"
    }
```

2.配置repositiories.json
```json
    {
      "repo_id": "repo_001",
      "path": "artifacts/repos/repo_001"
    },
    {
      "repo_id": "repo_001_fixed",
      "path": "artifacts/repos/repo_001_fixed",
      "relation": {
        "type": "fixed_version",
        "of_repo_id": "repo_001",
        "fixes": ["VULN-000001"]
      }
    }
```

3.配置待测agent，格式如下
```json
    {
      "agent_id": "chrys_default",
      "agent_type": "chrys",
      "model": "deterministic",
      "adapter": "chrys",
      "command": ["chrys", "run", "-a", "Code"],
      "prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的命令注入（Command Injection）风险。请对project项目进行深度扫描，挖掘其中的风险点，并将发现的所有风险严格按照format格式输出到项目目录下jsonFile中。",
      "diff_prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的命令注入（Command Injection）风险。请对git diff格式的patch包中代码变更内容及project目录下源代码信息进行深度分析，将本次变更引入的所有风险严格按照format格式输出到项目目录下jsonFile中。",
      "fix_prompt": "你是一个资深的代码安全审计专家，专注于发现后端代码中的SQL注入（SQL Injection）风险。请对git diff格式的patch包中代码变更内容及project目录下源代码信息进行深度分析，将未修复的所有风险严格按照format格式输出到项目目录下jsonFile中。",
       "behavior": "exact",
      "tool_profile": "static_readonly",
      "timeout_seconds": 7200,
      "max_output_bytes": 1048576
    }
```

4.配置patch包及预期告警
```json
    {
      "diff_id": "DIFF-000001-FIX",
      "patch_path": "artifacts/diffs/diff_001_fix.patch",
      "context_repo_id": "repo_001_fixed",
      "kind": "fixed_diff",
      "fixed_vulnerabilities": ["VULN-000001"]
    }
```

## 常见问题

1.chrys在window平台上并行化支持不太好，测试时尽量单进程运行

2.npm全局安装的opencode在window平台找不到命令问题可以修改agent.json中的command，指定路径
```
"command": ["C:/Users/h30033938/AppData/Roaming/npm/node_modules/opencode-ai/bin/opencode.exe", "run"]
```