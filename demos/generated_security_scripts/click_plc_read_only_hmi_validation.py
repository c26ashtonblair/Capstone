#!/usr/bin/env python3
"""Read-only HMI/PLC validation helper for CLICK PLC.

Authorized use only. This script does not send write operations. It records
operator-supplied observations and validates them against a defensive baseline.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


TARGET_NAME = 'CLICK PLC'
LOCAL_SIGNALS = ['default credentials', 'network segmentation', 'remote administration', 'unencrypted management']
REFERENCE_LINKS = ['https://www.reddit.com/r/PLC/comments/141hi90/click_plc_password/', 'https://community.automationdirect.com/s/question/0D53u000038WdV3CAK/resolved-click-v300-forced-password', 'https://www.plctalk.net/forums/threads/plc-direct-password.27544/', 'https://www.directautomation.com.au/media/catalog/category/CL-CLICK-PLC-Overview.pdf', 'https://cdn.automationdirect.com/static/helpfiles/click/Content/279.htm', 'https://www.automationdirect.com/videos/video?videoToPlay=eiORDSJ8LZs', 'https://www.cisa.gov/news-events/ics-advisories/icsa-21-166-02', 'https://www.tecon.cz/pdf/c2userm.pdf']
EXPECTED_CHECKS = [
    "default accounts disabled",
    "strong password policy configured",
    "management access restricted to approved subnets",
    "unused services disabled",
    "secure transport enabled where supported",
]


def evaluate_observations(observation_csv: Path) -> list[str]:
    findings: list[str] = []
    if not observation_csv.exists():
        return ["WARN | observations | file missing; no read-only HMI observations were provided"]

    with observation_csv.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        reader = csv.DictReader(handle)
        observed = list(reader)

    for check in EXPECTED_CHECKS:
        matched = next((row for row in observed if (row.get("check") or "").strip().lower() == check), None)
        if not matched:
            findings.append(f"WARN | {check} | not captured")
            continue
        status = (matched.get("status") or "").strip().lower()
        detail = (matched.get("detail") or "").strip() or "no detail provided"
        if status not in {"pass", "ok", "true", "yes"}:
            findings.append(f"FAIL | {check} | {detail}")
    return findings


def write_report(output: Path, findings: list[str]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"Target: {TARGET_NAME}",
        "Read-only HMI validation report",
        "",
        "Signals:",
        *[f"- {item}" for item in LOCAL_SIGNALS],
        "",
        "Reference links:",
        *[f"- {link}" for link in REFERENCE_LINKS],
        "",
        "Expected checks:",
        *[f"- {item}" for item in EXPECTED_CHECKS],
        "",
        "Findings:",
    ]
    if not findings:
        lines.append("- PASS | all supplied read-only checks matched the expected baseline")
    else:
        lines.extend(f"- {finding}" for finding in findings)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate operator-recorded HMI observations without changing settings.")
    parser.add_argument("--observations", default="hmi_read_only_observations.csv", help="CSV with check,status,detail columns.")
    parser.add_argument("--output", default="click_plc_read_only_hmi_report.txt", help="Output report path.")
    args = parser.parse_args()

    findings = evaluate_observations(Path(args.observations))
    write_report(Path(args.output), findings)


if __name__ == "__main__":
    main()
