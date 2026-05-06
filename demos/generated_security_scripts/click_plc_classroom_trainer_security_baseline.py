#!/usr/bin/env python3
"""Defensive baseline security validation script for CLICK PLC classroom trainer.

Authorized use only. This script performs non-destructive checks against
exported configurations and operator-supplied service inventory data.
It does not connect to or write to PLC, HMI, or field devices.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


TARGET_NAME = 'CLICK PLC classroom trainer'
TARGET_SLUG = 'click_plc_classroom_trainer'
LOCAL_SIGNALS = ['network segmentation']
REFERENCE_LINKS = ['https://www.nozominetworks.com/blog/breaking-the-encryption-analyzing-the-automationdirect-click-plus-plc-protocol', 'https://community.automationdirect.com/s/internal-database-security-advisory/a4GDp000000oojmMAA/sa00019', 'https://www.youtube.com/watch?v=6Ifj-R-s3jM', 'https://www.cybersecurity-help.cz/vdb/SB2021061704', 'https://www.cisa.gov/news-events/ics-advisories/icsa-23-201-01', 'https://www.linkedin.com/pulse/list-30-best-practices-secure-plc-programming-zohaib-jahan-supdf', 'https://www.youtube.com/watch?v=yMVz73Hvm_g', 'https://cache.industry.siemens.com/dl/files/842/109925842/att_1262081/v1/ONE_IndustrialCybersecurity_config_man_0124_en-US.pdf']
SELECTED_MODULES = [{'module_id': 'default_accounts_review', 'title': 'Default account review', 'rationale': 'Defaults and shared credentials are high-risk in PLC environments.', 'config_checks': [{'kind': 'dict_value_empty', 'path': 'accounts.default_accounts', 'severity': 'FAIL', 'message': 'default accounts are present'}], 'text_checks': [{'kind': 'forbidden_substring', 'needles': ['default password', 'admin:admin', 'admin/admin'], 'severity': 'WARN', 'message': 'text export mentions a default credential pattern'}], 'inventory_checks': []}, {'module_id': 'password_policy', 'title': 'Password policy strength', 'rationale': 'Classroom systems should still demonstrate strong password policy configuration.', 'config_checks': [{'kind': 'min_int', 'path': 'accounts.password_policy.min_length', 'min': 12, 'severity': 'FAIL', 'message': 'password minimum length is below 12'}, {'kind': 'bool_true', 'path': 'accounts.password_policy.complexity_enabled', 'severity': 'WARN', 'message': 'password complexity is not enabled'}], 'text_checks': [], 'inventory_checks': []}, {'module_id': 'segmentation_and_subnets', 'title': 'Segmentation and management subnet restrictions', 'rationale': 'OT access should be narrowed to approved management paths.', 'config_checks': [{'kind': 'bool_true', 'path': 'network.segmentation.enabled', 'severity': 'WARN', 'message': 'network segmentation is not enabled'}, {'kind': 'non_empty', 'path': 'network.allowed_management_subnets', 'severity': 'WARN', 'message': 'allowed management subnets are not defined'}], 'text_checks': [], 'inventory_checks': []}, {'module_id': 'web_transport_security', 'title': 'Web management transport security', 'rationale': 'If a web interface exists, plaintext transport should be flagged.', 'config_checks': [{'kind': 'bool_requires_true', 'path': 'services.web.enabled', 'requires_path': 'services.tls.enabled', 'severity': 'WARN', 'message': 'web management is enabled without TLS'}], 'text_checks': [], 'inventory_checks': [{'kind': 'service_exposure', 'services': ['http', 'telnet'], 'severity': 'WARN', 'message': 'plaintext management service appears in inventory'}, {'kind': 'public_exposure', 'severity': 'FAIL', 'message': 'public or internet exposure appears in inventory'}]}, {'module_id': 'industrial_protocol_review', 'title': 'Industrial protocol exposure review', 'rationale': 'Protocol availability should be documented and protected, especially Modbus-related paths.', 'config_checks': [{'kind': 'bool_requires_true', 'path': 'services.modbus.enabled', 'requires_path': 'services.modbus.secure_transport', 'severity': 'WARN', 'message': 'Modbus is enabled without a documented secure transport or tunnel flag'}], 'text_checks': [], 'inventory_checks': [{'kind': 'port_presence', 'ports': ['502'], 'severity': 'WARN', 'message': 'Modbus-related service appears in the service inventory'}]}, {'module_id': 'firmware_and_diagnostics', 'title': 'Firmware and diagnostic evidence capture', 'rationale': 'Version and diagnostic state should be captured in exported evidence for review.', 'config_checks': [{'kind': 'non_empty', 'path': 'controller.firmware_version', 'severity': 'WARN', 'message': 'controller firmware version is not captured in exports'}], 'text_checks': [{'kind': 'required_substring', 'needles': ['firmware', '_firmware_version', 'error', 'watchdog'], 'severity': 'INFO', 'message': 'project text includes firmware/diagnostic indicators for follow-up review'}], 'inventory_checks': []}]


def load_structured_file(path: Path) -> Any:
    suffix = path.suffix.lower()
    text = path.read_text(encoding="utf-8", errors="ignore")
    if suffix == ".json":
        return json.loads(text)
    return text


def get_nested(data: Any, dotted_key: str) -> Any:
    current = data
    for part in dotted_key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def check_config_exports(config_dir: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    for path in sorted(config_dir.glob("*")):
        if path.suffix.lower() not in {".json", ".txt", ".cfg", ".conf", ".yaml", ".yml"}:
            continue
        try:
            data = load_structured_file(path)
        except Exception as exc:
            findings.append({"severity": "WARN", "file": path.name, "check": "read", "detail": str(exc)})
            continue

        if isinstance(data, dict):
            for module in SELECTED_MODULES:
                for check in module.get("config_checks", []):
                    findings.extend(run_config_check(path.name, data, module["module_id"], check))
        else:
            lowered = str(data).lower()
            for module in SELECTED_MODULES:
                for check in module.get("text_checks", []):
                    findings.extend(run_text_check(path.name, lowered, module["module_id"], check))
    return findings


def check_service_inventory(inventory_file: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not inventory_file.exists():
        return findings

    with inventory_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            for module in SELECTED_MODULES:
                for check in module.get("inventory_checks", []):
                    findings.extend(run_inventory_check(inventory_file.name, row, module["module_id"], check))
    return findings


def run_config_check(file_name: str, data: dict[str, Any], module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    kind = check.get("kind")
    path = check.get("path", "")
    value = get_nested(data, path) if path else None
    severity = check.get("severity", "WARN")
    message = check.get("message", "check failed")

    if kind == "dict_value_empty" and value:
        findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": message})
    elif kind == "min_int":
        if value is None:
            findings.append({"severity": "WARN", "file": file_name, "check": f"{module_id}:{path}", "detail": "recommended setting missing"})
        elif int(value) < int(check.get("min", 0)):
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": f"{message} (found {value})"})
    elif kind == "bool_true" and value is not True:
        findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": message})
    elif kind == "non_empty" and not value:
        findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": message})
    elif kind == "bool_requires_non_empty":
        required_value = get_nested(data, check.get("requires_path", ""))
        if value is True and not required_value:
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": message})
    elif kind == "bool_requires_true":
        required_value = get_nested(data, check.get("requires_path", ""))
        if value is True and required_value is not True:
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{path}", "detail": message})
    return findings


def run_text_check(file_name: str, lowered_text: str, module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    needles = [needle.lower() for needle in check.get("needles", [])]
    severity = check.get("severity", "WARN")
    message = check.get("message", "text pattern matched")
    kind = check.get("kind")
    if kind == "forbidden_substring" and any(needle in lowered_text for needle in needles):
        findings.append({"severity": severity, "file": file_name, "check": module_id, "detail": message})
    elif kind == "required_substring" and any(needle in lowered_text for needle in needles):
        findings.append({"severity": severity, "file": file_name, "check": module_id, "detail": message})
    return findings


def run_inventory_check(file_name: str, row: dict[str, str], module_id: str, check: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    host = row.get("host", "unknown")
    port = str(row.get("port", "") or "")
    service = (row.get("service", "") or "").lower()
    exposure = (row.get("exposure", "") or "").lower()
    severity = check.get("severity", "WARN")
    message = check.get("message", "inventory pattern matched")
    kind = check.get("kind")

    if kind == "service_exposure":
        services = {item.lower() for item in check.get("services", [])}
        if service in services or port in services:
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{host}", "detail": message})
    elif kind == "public_exposure":
        if exposure in {"internet", "public"}:
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{host}", "detail": message})
    elif kind == "port_presence":
        ports = {str(item) for item in check.get("ports", [])}
        if port in ports:
            findings.append({"severity": severity, "file": file_name, "check": f"{module_id}:{host}", "detail": message})
    return findings


def write_report(findings: list[dict[str, str]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {TARGET_NAME}",
        "Authorized defensive baseline results",
        "",
        "Signals from source material:",
        *[f"- {item}" for item in LOCAL_SIGNALS],
        "",
        "Selected modules:",
        *[f"- {module['module_id']} | {module['title']}" for module in SELECTED_MODULES],
        "",
        "Reference links:",
        *[f"- {link}" for link in REFERENCE_LINKS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS: no baseline issues detected by the generated checks.")
    for finding in findings:
        lines.append(
            f"- {finding['severity']} | {finding['file']} | {finding['check']} | {finding['detail']}"
        )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run defensive baseline checks for authorized security validation.")
    parser.add_argument("--config-dir", default="config_exports", help="Directory containing exported configs.")
    parser.add_argument("--inventory-csv", default="service_inventory.csv", help="CSV with host,port,service,exposure columns.")
    parser.add_argument("--output", default=f"{TARGET_SLUG}_security_report.txt", help="Output report path.")
    args = parser.parse_args()

    findings = []
    findings.extend(check_config_exports(Path(args.config_dir)))
    findings.extend(check_service_inventory(Path(args.inventory_csv)))
    write_report(findings, Path(args.output))


if __name__ == "__main__":
    main()
