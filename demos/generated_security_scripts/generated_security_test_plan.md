# Generated Security Test Plan: CLICK PLC

This plan is limited to authorized, defensive validation. It excludes exploitation and destructive testing.

## Priorities

- Validate controls related to default credentials.
- Validate controls related to network segmentation.
- Validate controls related to remote administration.
- Validate controls related to unencrypted management.

## Recommended Sequence

1. Review local configuration and implementation files for obvious security assumptions.
2. Run the offline baseline checker against exported configs and service inventory data.
3. Run the read-only HMI validation script to collect current settings and evidence without making changes.
4. Use the approved change runbook for human-reviewed, manual changes only.
5. Run the post-change verification script to confirm the approved settings are present.

## Generated Artifacts

- `click_plc_security_baseline.py`
- `click_plc_read_only_hmi_validation.py`
- `approved_change_runbook.md`
- `click_plc_post_change_verification.py`

## Web Sources

- Click PLC Password | https://www.reddit.com/r/PLC/comments/141hi90/click_plc_password/
- [!RESOLVED!] Click V3.00 FORCED PASSWORD | https://community.automationdirect.com/s/question/0D53u000038WdV3CAK/resolved-click-v300-forced-password
- plc direct password | PLCtalk - Interactive Q & A | https://www.plctalk.net/forums/threads/plc-direct-password.27544/
- CLICK and CLICK Plus PLCs | https://www.directautomation.com.au/media/catalog/category/CL-CLICK-PLC-Overview.pdf
- User Account Setup | https://cdn.automationdirect.com/static/helpfiles/click/Content/279.htm
- C-more Micro HMI Password Protection from AutomationDirect ... | https://www.automationdirect.com/videos/video?videoToPlay=eiORDSJ8LZs
- Automation Direct CLICK PLC CPU Modules | https://www.cisa.gov/news-events/ics-advisories/icsa-21-166-02
- CLICK PLUS Hardware User Manual (C2-USER-M) | https://www.tecon.cz/pdf/c2userm.pdf
- Passwords with PLCnext | https://engineer.plcnext.help/latest/PasswordsPLCnext.htm
- CLICK PLC Hardware User Manual (C0-USER-M) | https://cdn.automationdirect.com/static/manuals/c0userm/c0userm.pdf
