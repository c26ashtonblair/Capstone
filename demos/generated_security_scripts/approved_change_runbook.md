# Approved Change Runbook: CLICK PLC

This runbook is human-in-the-loop only. It is intended for approved manual changes and explicitly excludes automated writes through HMI, PLC, or protocol interfaces.

## Preconditions

- Confirm written authorization and maintenance window approval.
- Confirm a current project backup and screenshot/export of relevant HMI settings.
- Confirm rollback owner, test owner, and sign-off owner.
- Confirm the read-only validation report has been collected.

## Recommended Change Themes

- Review settings related to default credentials.
- Review settings related to network segmentation.
- Review settings related to remote administration.
- Review settings related to unencrypted management.

## Manual Procedure Template

1. Record the current value of the target setting in the change log.
2. Apply the approved value manually through the vendor-supported interface.
3. Capture screenshots or exports of the updated value.
4. Verify system state remains healthy and expected alarms/status remain normal.
5. Run the post-change verification script and attach the output to the change ticket.

## Rollback Template

1. Restore the previously recorded setting value.
2. Reapply the saved project or backup if a single-setting rollback is insufficient.
3. Re-run read-only validation and post-change verification to confirm restoration.

## Reference Links

- https://www.reddit.com/r/PLC/comments/141hi90/click_plc_password/
- https://community.automationdirect.com/s/question/0D53u000038WdV3CAK/resolved-click-v300-forced-password
- https://www.plctalk.net/forums/threads/plc-direct-password.27544/
- https://www.directautomation.com.au/media/catalog/category/CL-CLICK-PLC-Overview.pdf
- https://cdn.automationdirect.com/static/helpfiles/click/Content/279.htm
- https://www.automationdirect.com/videos/video?videoToPlay=eiORDSJ8LZs
- https://www.cisa.gov/news-events/ics-advisories/icsa-21-166-02
- https://www.tecon.cz/pdf/c2userm.pdf
