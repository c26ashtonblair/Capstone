# Generated Security Test Plan: CLICK PLC classroom trainer

This plan is limited to authorized, defensive validation. It excludes exploitation, destructive testing, and automated writes to PLC/HMI systems.

## Priorities

- Validate controls related to network segmentation.

## Recommended Sequence

1. Review local configuration and implementation files for obvious security assumptions.
2. Review `web_research_sources.json` and trim any irrelevant public results before classroom use.
3. Run the offline baseline checker against exported configs and service inventory data.
4. Review `proposed_hmi_change_set.json` with a trained operator and confirm each value is appropriate for the classroom system.
5. Complete `pre_change_checklist.md` before any manual HMI work.
6. Follow `operator_execution_runbook.md` to apply the approved changes manually through the HMI.
7. If needed, use `rollback_plan.md` to restore the previous settings.
8. Run the post-change verification script to confirm the approved settings are present.

## Offline Boundary

- Do not point the generated scripts at live PLC write interfaces.
- Do not add protocol write operations, forcing commands, or ladder-logic download steps.
- Treat exported project/config files as the primary automation input for proposed changes.

## Generated Artifacts

- `click_plc_classroom_trainer_security_baseline.py`
- `proposed_hmi_change_set.json`
- `pre_change_checklist.md`
- `operator_execution_runbook.md`
- `rollback_plan.md`
- `click_plc_classroom_trainer_post_change_verification.py`
- `offline_generation_manifest.json`
- `web_research_sources.json`

## Selected Modules

- `default_accounts_review` | Default account review
- `password_policy` | Password policy strength
- `segmentation_and_subnets` | Segmentation and management subnet restrictions
- `industrial_protocol_review` | Industrial protocol exposure review
- `firmware_and_diagnostics` | Firmware and diagnostic evidence capture

## Web Sources

- Analyzing the AutomationDirect CLICK Plus PLC Protocol | https://www.nozominetworks.com/blog/breaking-the-encryption-analyzing-the-automationdirect-click-plus-plc-protocol
- AutomationDirect CLICK Programmable Logic Controller | https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-02
- Internal Database Security Advisory: SA-00019 | https://community.automationdirect.com/s/internal-database-security-advisory/a4GDp000000oojmMAA/sa00019
- Boost Your Defenses with Top 20 Secure Practices | https://www.compliance-labs.com/topic/nist-sp-800-82/plc-security-boost-your-defenses-with-top-20-secure-practices/
- One Year of Top 20 Secure PLC Coding Practices | https://fluchsfriction.medium.com/one-year-of-top-20-secure-plc-coding-practices-c2f0042ad4a2
- AutomationDirect CLICK PLUS | https://www.cisa.gov/news-events/ics-advisories/icsa-25-266-01
- Rockwell Automation Customer Hardening Guidelines | https://support.rockwellautomation.com/app/answers/answer_view/a_id/546987/~/rockwell-automation-customer-hardening-guidelines
- Proactive Steps You Can Take To Protect PLCs From ... | https://www.linkedin.com/pulse/proactive-steps-you-can-take-protect-plcs-from-cyber-attacks-kpasc
- Features of the CLICK PLUS PLC | https://www.automationdirect.com/clickplcs/clickplus/features?srsltid=AfmBOoql_VNdYAyeUPwiq_pe47GqxAIxCIrHhByB9JC8ozx_rJzycM5K
- Control Systems Security | PLC Cyber Security - Acscm.com | https://www.acscm.com/blog/protecting-controls-in-the-digital-age-plc-cyber-security-essentials/
