# Operator Execution Runbook: CLICK PLC classroom trainer

This runbook is human-in-the-loop only. It is intended for approved manual changes and explicitly excludes automated writes through HMI, PLC, or protocol interfaces.

## Preconditions

- Confirm `pre_change_checklist.md` is complete.
- Confirm `proposed_hmi_change_set.json` has been reviewed and annotated with accepted/rejected items.
- Confirm a current project backup and screenshot/export of relevant HMI settings.
- Confirm rollback owner, operator, and sign-off owner.

## Execution Sequence

- Review settings related to network segmentation.

## Manual Procedure Template

1. Open `proposed_hmi_change_set.json` and work through settings one at a time.
2. On the HMI, navigate to the setting indicated by `location_hint`.
3. Record the current value in the change log before editing.
4. Manually apply the approved value only after confirming it matches the accepted proposal.
5. Capture a screenshot or export showing the new value.
6. Pause after each setting to confirm the classroom system remains healthy and expected alarms/status remain normal.
7. When all accepted settings are complete, run the post-change verification script and attach the output to the exercise record.

## Reference Links

- https://www.nozominetworks.com/blog/breaking-the-encryption-analyzing-the-automationdirect-click-plus-plc-protocol
- https://community.automationdirect.com/s/internal-database-security-advisory/a4GDp000000oojmMAA/sa00019
- https://www.youtube.com/watch?v=6Ifj-R-s3jM
- https://www.cybersecurity-help.cz/vdb/SB2021061704
- https://www.cisa.gov/news-events/ics-advisories/icsa-23-201-01
- https://www.linkedin.com/pulse/list-30-best-practices-secure-plc-programming-zohaib-jahan-supdf
- https://www.youtube.com/watch?v=yMVz73Hvm_g
- https://cache.industry.siemens.com/dl/files/842/109925842/att_1262081/v1/ONE_IndustrialCybersecurity_config_man_0124_en-US.pdf
