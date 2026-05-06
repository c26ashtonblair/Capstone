#!/usr/bin/env python3
"""Offline PLC config/policy audit helper.

Input: JSON files exported from PLC/HMI/SCADA config management tools.
This script performs defensive checks only.
"""

from pathlib import Path
import json

CONFIG_DIR = Path("config_exports")

REQUIRED = [
    "password_policy.min_length",
    "password_policy.complexity_enabled",
    "network.segmentation.enabled",
    "network.allowed_management_subnets",
    "services.modbus_tcp.enabled",
    "services.web_admin.enabled",
]


def get_nested(data, dotted):
    node = data
    for part in dotted.split('.'):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def evaluate(doc):
    findings = []
    for key in REQUIRED:
        value = get_nested(doc, key)
        if value is None:
            findings.append(("MISSING", key, "Not present"))

    min_len = get_nested(doc, "password_policy.min_length")
    if isinstance(min_len, int) and min_len < 12:
        findings.append(("FAIL", "password_policy.min_length", f"{min_len} < 12"))

    default_accounts = get_nested(doc, "accounts.default_accounts") or []
    if default_accounts:
        findings.append(("FAIL", "accounts.default_accounts", f"Found default accounts: {default_accounts}"))

    modbus_enabled = get_nested(doc, "services.modbus_tcp.enabled")
    modbus_tls = get_nested(doc, "services.modbus_tcp.secure_transport")
    if modbus_enabled and not modbus_tls:
        findings.append(("WARN", "services.modbus_tcp.secure_transport", "Modbus enabled without secure transport/tunnel"))

    return findings


def main():
    if not CONFIG_DIR.exists():
        raise SystemExit("Create config_exports/ with JSON exports first.")

    for path in sorted(CONFIG_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = evaluate(data)
        print(f"\n=== {{path.name}} ===")
        if not findings:
            print("PASS: No policy issues detected by baseline checks.")
            continue
        for sev, key, msg in findings:
            print(f"{{sev}} | {{key}} | {{msg}}")


if __name__ == "__main__":
    main()
