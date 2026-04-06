#!/usr/bin/env python3
"""Post-change verification helper for CLICK PLC classroom trainer.

Authorized use only. This script validates recorded post-change evidence and
does not send write operations to PLC or HMI systems.
It is designed for offline evidence review only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


TARGET_NAME = 'CLICK PLC classroom trainer'
LOCAL_SIGNALS = ['network segmentation']
REQUIRED_EXPECTATIONS = {
    "default_accounts_disabled": True,
    "password_min_length": 12,
    "management_subnets_defined": True,
    "secure_transport_enabled": True,
}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def verify(data: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if data.get("default_accounts_disabled") is not True:
        findings.append("FAIL | default_accounts_disabled | expected true")
    if int(data.get("password_min_length", 0) or 0) < REQUIRED_EXPECTATIONS["password_min_length"]:
        findings.append("FAIL | password_min_length | expected >= 12")
    if data.get("management_subnets_defined") is not True:
        findings.append("FAIL | management_subnets_defined | expected true")
    if data.get("secure_transport_enabled") is not True:
        findings.append("WARN | secure_transport_enabled | expected true when supported")
    return findings


def write_report(output: Path, findings: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {TARGET_NAME}",
        "Post-change verification report",
        "",
        "Signals:",
        *[f"- {item}" for item in LOCAL_SIGNALS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS | supplied post-change evidence satisfies the baseline checks")
    else:
        lines.extend(f"- {finding}" for finding in findings)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate supplied post-change evidence without changing PLC or HMI settings.")
    parser.add_argument("--evidence-json", default="post_change_observations.json", help="JSON with post-change observation fields.")
    parser.add_argument("--output", default="click_plc_classroom_trainer_post_change_verification.txt", help="Output report path.")
    args = parser.parse_args()

    data = load_json(Path(args.evidence_json))
    findings = verify(data)
    write_report(Path(args.output), findings)


if __name__ == "__main__":
    main()
