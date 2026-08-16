from __future__ import annotations

from typing import Any

from .registry import Registry, normalize_type_token


def evaluate_task(
    registry: Registry,
    task: dict[str, Any],
    normalized_output: dict[str, Any],
) -> dict[str, Any]:
    status = normalized_output.get("status", "invalid_output")
    if task.get("expectation") == "fixed":
        return _evaluate_fixed_task(registry, task, normalized_output, status)
    return _evaluate_detection_task(registry, task, normalized_output, status)


def _evaluate_detection_task(
    registry: Registry,
    task: dict[str, Any],
    normalized_output: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    target_ids = list(task.get("target_vulnerabilities", []))
    result = _base_result(task, normalized_output)
    if status != "success":
        result["fn"] = target_ids
        result["invalid_output"] = True
        return result

    labels = [registry.vulnerabilities[vuln_id] for vuln_id in target_ids]
    matched: set[str] = set()

    for finding in normalized_output.get("findings", []):
        matched_vuln = _first_matching_label(registry, finding, labels)
        if not matched_vuln:
            result["fp"].append(finding)
            result["review_candidates"].append(finding)
            continue
        vuln_id = matched_vuln["vuln_id"]
        if vuln_id in matched:
            result["duplicates"].append(finding)
            if registry.scoring.get("duplicates", {}).get("count_duplicates_as_fp", False):
                result["fp"].append(finding)
            continue
        matched.add(vuln_id)
        result["tp"].append(vuln_id)

    result["fn"] = [vuln_id for vuln_id in target_ids if vuln_id not in matched]
    return result


def _evaluate_fixed_task(
    registry: Registry,
    task: dict[str, Any],
    normalized_output: dict[str, Any],
    status: str,
) -> dict[str, Any]:
    absent_ids = list(task.get("expected_absent_vulnerabilities", []))
    result = _base_result(task, normalized_output)
    result["fixed_check_passed"] = status == "success"
    if status != "success":
        result["invalid_output"] = True
        result["fixed_check_passed"] = False
        result["fixed_failures"] = absent_ids
        return result

    absent_labels = [registry.vulnerabilities[vuln_id] for vuln_id in absent_ids]
    failed_ids: set[str] = set()
    for finding in normalized_output.get("findings", []):
        matched_vuln = _first_matching_label(registry, finding, absent_labels)
        if matched_vuln:
            failed_ids.add(matched_vuln["vuln_id"])
        else:
            result["fp"].append(finding)
            result["review_candidates"].append(finding)

    result["fixed_failures"] = sorted(failed_ids)
    result["fixed_check_passed"] = not failed_ids
    return result


def _base_result(task: dict[str, Any], normalized_output: dict[str, Any]) -> dict[str, Any]:
    metadata = normalized_output.get("run_metadata", {})
    return {
        "task_id": task["task_id"],
        "suite_id": task["suite_id"],
        "repeat_index": task["repeat_index"],
        "agent_id": normalized_output.get("agent_id"),
        "mode": "fixed_check" if task.get("expectation") == "fixed" else task.get("mode"),
        "expectation": task.get("expectation"),
        "status": normalized_output.get("status", "invalid_output"),
        "tp": [],
        "fp": [],
        "fn": [],
        "duplicates": [],
        "review_candidates": [],
        "invalid_output": False,
        "fixed_check_passed": None,
        "fixed_failures": [],
        "duration_seconds": metadata.get("duration_seconds"),
        "cost": metadata.get("cost"),
        "input_tokens": metadata.get("input_tokens"),
        "output_tokens": metadata.get("output_tokens"),
    }


def _first_matching_label(
    registry: Registry,
    finding: dict[str, Any],
    labels: list[dict[str, Any]],
) -> dict[str, Any] | None:
    for label in labels:
        if _finding_matches_label(registry, finding, label):
            return label
    return None


def _finding_matches_label(
    registry: Registry,
    finding: dict[str, Any],
    label: dict[str, Any],
) -> bool:
    strict = registry.scoring.get("strict_match", {})
    if strict.get("require_type", True) and not _type_matches(registry, finding, label):
        return False
    if strict.get("require_file", True) and not _file_matches(finding, label):
        return False
    mode = strict.get("location_match_mode", "same_file_function_or_line")
    if mode == "same_file_and_line":
        return _line_matches(strict, finding, label)
    if mode == "same_file_function_and_line":
        return _function_matches(finding, label) and _line_matches(strict, finding, label)
    return _function_or_line_matches(strict, finding, label)


def _type_matches(registry: Registry, finding: dict[str, Any], label: dict[str, Any]) -> bool:
    label_tokens = registry.canonical_type_tokens(label["classification"])
    finding_tokens = {normalize_type_token(item) for item in finding.get("cwe", [])}
    if finding.get("type"):
        finding_tokens.add(normalize_type_token(finding["type"]))
    return bool(label_tokens.intersection(finding_tokens))


def _file_matches(finding: dict[str, Any], label: dict[str, Any]) -> bool:
    return _norm_path(finding.get("file")) == _norm_path(label.get("location", {}).get("file"))


def _function_or_line_matches(
    strict: dict[str, Any],
    finding: dict[str, Any],
    label: dict[str, Any],
) -> bool:
    require_line = strict.get("require_line", False)
    if _function_matches(finding, label) and not require_line:
        return True
    if strict.get("line_match_when_function_missing", True):
        return _line_matches(strict, finding, label)
    return False


def _function_matches(finding: dict[str, Any], label: dict[str, Any]) -> bool:
    finding_function = finding.get("function")
    label_function = label.get("location", {}).get("function")
    return bool(finding_function and label_function and finding_function == label_function)


def _line_matches(
    strict: dict[str, Any],
    finding: dict[str, Any],
    label: dict[str, Any],
) -> bool:
    if "start_line" not in finding:
        return False
    window = int(strict.get("line_window", 5))
    finding_start = int(finding["start_line"])
    finding_end = int(finding.get("end_line", finding_start))
    location = label.get("location", {})
    label_start = int(location["start_line"])
    label_end = int(location["end_line"])
    return finding_start <= label_end + window and finding_end >= label_start - window


def _norm_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().lower()

