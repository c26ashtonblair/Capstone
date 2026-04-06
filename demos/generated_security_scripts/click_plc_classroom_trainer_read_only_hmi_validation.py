#!/usr/bin/env python3
"""Read-only HMI/PLC validation helper for CLICK PLC classroom trainer.

Authorized use only. This script does not send write operations. It records
operator-supplied observations and validates them against a defensive baseline.
It is intended for offline evidence review, not direct PLC control.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


TARGET_NAME = 'CLICK PLC classroom trainer'
LOCAL_SIGNALS = ['network segmentation']
REFERENCE_LINKS = ['https://www.nozominetworks.com/blog/breaking-the-encryption-analyzing-the-automationdirect-click-plus-plc-protocol', 'https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-02', 'https://community.automationdirect.com/s/internal-database-security-advisory/a4GDp000000oojmMAA/sa00019', 'https://www.compliance-labs.com/topic/nist-sp-800-82/plc-security-boost-your-defenses-with-top-20-secure-practices/', 'https://fluchsfriction.medium.com/one-year-of-top-20-secure-plc-coding-practices-c2f0042ad4a2', 'https://www.cisa.gov/news-events/ics-advisories/icsa-25-266-01', 'https://support.rockwellautomation.com/app/answers/answer_view/a_id/546987/~/rockwell-automation-customer-hardening-guidelines', 'https://www.linkedin.com/pulse/proactive-steps-you-can-take-protect-plcs-from-cyber-attacks-kpasc']
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
    parser.add_argument("--output", default="click_plc_classroom_trainer_read_only_hmi_report.txt", help="Output report path.")
    args = parser.parse_args()

    findings = evaluate_observations(Path(args.observations))
    write_report(Path(args.output), findings)


if __name__ == "__main__":
    main()
