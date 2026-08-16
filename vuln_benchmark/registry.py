from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MANIFEST_FILES = {
    "repositories": "repositories.json",
    "diffs": "diffs.json",
    # "vulnerabilities": "vulnerabilities.json",
    "classification_mapping": "classification_mapping.json",
    "issue_assets": "issue_assets.json",
    "suites": "suites.json",
    "scoring": "scoring.json",
    "format": "format.json"
}


@dataclass(frozen=True)
class Registry:
    root: Path
    repo_root: Path
    manifests: dict[str, Any]

    @classmethod
    def load(cls, root: str | Path, repo_root: str | Path) -> "Registry":
        root_path = Path(root).resolve()
        manifest_dir = root_path / "manifests"
        manifests: dict[str, Any] = {}
        # 解析配置文件
        for key, filename in MANIFEST_FILES.items():
            path = manifest_dir / filename
            with path.open("r", encoding="utf-8") as handle:
                manifests[key] = json.load(handle)

        # 遍历仓库，汇总告警信息
        vuln_list = []
        vuln_dict = {}
        for item in manifests["repositories"].get("repositories", []):
            json_file = str(repo_root / item["path"]) + ".json"
            if not Path(json_file).exists():
                continue
            with open(json_file, "r", encoding="utf-8") as f:
                json_data = json.load(f)
                vuln_list.extend(json_data["vulnerabilities"])
        vuln_dict["vulnerabilities"] = vuln_list
        manifests["vulnerabilities"] = vuln_dict

        return cls(root=root_path, repo_root=repo_root, manifests=manifests)

    @property
    def repositories(self) -> dict[str, dict[str, Any]]:
        return {
            item["repo_id"]: item
            for item in self.manifests["repositories"].get("repositories", [])
        }

    @property
    def vulnerabilities(self) -> dict[str, dict[str, Any]]:
        return {
            item["vuln_id"]: item
            for item in self.manifests["vulnerabilities"].get("vulnerabilities", [])
        }

    @property
    def diffs(self) -> dict[str, dict[str, Any]]:
        return {item["diff_id"]: item for item in self.manifests["diffs"].get("diffs", [])}

    @property
    def suites(self) -> dict[str, dict[str, Any]]:
        return {
            item["suite_id"]: item
            for item in self.manifests["suites"].get("suites", [])
        }

    @property
    def mappings(self) -> list[dict[str, Any]]:
        return self.manifests["classification_mapping"].get("mappings", [])

    @property
    def scoring(self) -> dict[str, Any]:
        return self.manifests["scoring"]

    def repo_abs_path(self, repo_id: str) -> Path:
        return self.repo_root / self.repositories[repo_id]["path"]

    def repo_rel_path(self, repo_id: str) -> str:
        return self.repositories[repo_id]["path"]

    def patch_abs_path(self, diff_id: str) -> Path:
        return self.repo_root / self.diffs[diff_id]["patch_path"]

    def vulnerabilities_for_repo(self, repo_id: str) -> list[dict[str, Any]]:
        return [
            vuln
            for vuln in self.vulnerabilities.values()
            if vuln.get("repo_id") == repo_id
        ]

    def classification_matches(
        self,
        classification: dict[str, Any],
        selector: dict[str, Any],
    ) -> bool:
        for field in ("domain_category", "issue_category", "issue_subcategory"):
            selected = selector.get(field)
            if selected and classification.get(field) != selected:
                return False
        selected_cwe = set(selector.get("cwe", []))
        if selected_cwe and not selected_cwe.intersection(classification.get("cwe", [])):
            return False
        return True

    def selected_vulnerability_ids(self, selection: dict[str, Any]) -> set[str]:
        scope = selection.get("scope", "all")
        if scope == "all":
            return set(self.vulnerabilities)
        if scope == "explicit":
            return set(selection.get("vulnerability_ids", []))
        if scope == "classification":
            return {
                vuln_id
                for vuln_id, vuln in self.vulnerabilities.items()
                if self.classification_matches(vuln["classification"], selection)
            }
        raise ValueError(f"Unsupported selection scope: {scope}")

    def canonical_type_tokens(self, classification: dict[str, Any]) -> set[str]:
        tokens = {
            normalize_type_token(classification.get("issue_subcategory", "")),
            *[normalize_type_token(cwe) for cwe in classification.get("cwe", [])],
        }
        for mapping in self.mappings:
            if (
                mapping.get("domain_category") == classification.get("domain_category")
                and mapping.get("issue_category") == classification.get("issue_category")
                and mapping.get("issue_subcategory")
                == classification.get("issue_subcategory")
            ):
                tokens.add(normalize_type_token(mapping.get("issue_subcategory", "")))
                tokens.update(normalize_type_token(alias) for alias in mapping.get("aliases", []))
                tokens.update(normalize_type_token(cwe) for cwe in mapping.get("cwe", []))
        return {token for token in tokens if token}


def normalize_type_token(value: Any) -> str:
    return str(value).strip().lower().replace("-", "_").replace(" ", "_")

