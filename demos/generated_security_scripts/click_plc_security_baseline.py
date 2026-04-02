#!/usr/bin/env python3
"""Defensive baseline security validation script for CLICK PLC.

Authorized use only. This script performs non-destructive checks against
exported configurations and operator-supplied service inventory data.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


TARGET_NAME = 'CLICK PLC'
TARGET_SLUG = 'click_plc'
LOCAL_SIGNALS = ['default credentials', 'network segmentation', 'remote administration', 'unencrypted management']
REFERENCE_LINKS = ['https://www.reddit.com/r/PLC/comments/141hi90/click_plc_password/', 'https://community.automationdirect.com/s/question/0D53u000038WdV3CAK/resolved-click-v300-forced-password', 'https://www.plctalk.net/forums/threads/plc-direct-password.27544/', 'https://www.directautomation.com.au/media/catalog/category/CL-CLICK-PLC-Overview.pdf', 'https://cdn.automationdirect.com/static/helpfiles/click/Content/279.htm', 'https://www.automationdirect.com/videos/video?videoToPlay=eiORDSJ8LZs', 'https://www.cisa.gov/news-events/ics-advisories/icsa-21-166-02', 'https://www.tecon.cz/pdf/c2userm.pdf']


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
    required_keys = [
        "accounts",
        "services",
        "network",
    ]
    recommended_paths = [
        "accounts.default_accounts",
        "accounts.password_policy.min_length",
        "network.allowed_management_subnets",
        "network.segmentation.enabled",
        "services.remote_admin.enabled",
        "services.web.enabled",
        "services.modbus.enabled",
        "services.tls.enabled",
    ]

    for path in sorted(config_dir.glob("*")):
        if path.suffix.lower() not in {".json", ".txt", ".cfg", ".conf", ".yaml", ".yml"}:
            continue
        try:
            data = load_structured_file(path)
        except Exception as exc:
            findings.append({"severity": "WARN", "file": path.name, "check": "read", "detail": str(exc)})
            continue

        if isinstance(data, dict):
            for key in required_keys:
                if key not in data:
                    findings.append({"severity": "WARN", "file": path.name, "check": key, "detail": "missing top-level section"})
            for dotted in recommended_paths:
                if get_nested(data, dotted) is None:
                    findings.append({"severity": "WARN", "file": path.name, "check": dotted, "detail": "missing recommended setting"})

            min_length = get_nested(data, "accounts.password_policy.min_length")
            if isinstance(min_length, int) and min_length < 12:
                findings.append({"severity": "FAIL", "file": path.name, "check": "password length", "detail": f"min length {min_length} < 12"})

            default_accounts = get_nested(data, "accounts.default_accounts")
            if default_accounts:
                findings.append({"severity": "FAIL", "file": path.name, "check": "default accounts", "detail": f"present: {default_accounts}"})

            remote_admin = get_nested(data, "services.remote_admin.enabled")
            allowed_subnets = get_nested(data, "network.allowed_management_subnets")
            if remote_admin and not allowed_subnets:
                findings.append({"severity": "WARN", "file": path.name, "check": "remote admin restrictions", "detail": "enabled without allowed_management_subnets"})

            tls_enabled = get_nested(data, "services.tls.enabled")
            web_enabled = get_nested(data, "services.web.enabled")
            if web_enabled and not tls_enabled:
                findings.append({"severity": "WARN", "file": path.name, "check": "web transport", "detail": "web enabled without tls.enabled"})
        else:
            lowered = str(data).lower()
            if "password" in lowered and "default" in lowered:
                findings.append({"severity": "WARN", "file": path.name, "check": "plaintext review", "detail": "mentions default password"})
            if "telnet" in lowered or "http://" in lowered:
                findings.append({"severity": "WARN", "file": path.name, "check": "plaintext protocols", "detail": "mentions insecure management protocol"})
    return findings


def check_service_inventory(inventory_file: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if not inventory_file.exists():
        return findings

    with inventory_file.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            host = row.get("host", "unknown")
            port = row.get("port", "")
            service = (row.get("service", "") or "").lower()
            exposure = (row.get("exposure", "") or "").lower()

            if port in {"23", "80"} or service in {"telnet", "http"}:
                findings.append({"severity": "WARN", "file": inventory_file.name, "check": f"host {host}", "detail": f"insecure management service {service or port}"})
            if exposure in {"internet", "public"}:
                findings.append({"severity": "FAIL", "file": inventory_file.name, "check": f"host {host}", "detail": "publicly exposed management path"})
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
