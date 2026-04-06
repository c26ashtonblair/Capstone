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
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-022-02
- https://community.automationdirect.com/s/internal-database-security-advisory/a4GDp000000oojmMAA/sa00019
- https://www.compliance-labs.com/topic/nist-sp-800-82/plc-security-boost-your-defenses-with-top-20-secure-practices/
- https://fluchsfriction.medium.com/one-year-of-top-20-secure-plc-coding-practices-c2f0042ad4a2
- https://www.cisa.gov/news-events/ics-advisories/icsa-25-266-01
- https://support.rockwellautomation.com/app/answers/answer_view/a_id/546987/~/rockwell-automation-customer-hardening-guidelines
- https://www.linkedin.com/pulse/proactive-steps-you-can-take-protect-plcs-from-cyber-attacks-kpasc
