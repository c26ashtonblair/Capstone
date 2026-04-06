# Pre-Change Checklist: CLICK PLC classroom trainer

Complete this checklist before a trained operator makes any manual HMI changes.

- Confirm the PLC is the classroom/test unit and not connected to production equipment.
- Record the current value of every setting listed in `proposed_hmi_change_set.json`.
- Capture screenshots or exports of each HMI page that will be edited.
- Confirm a recent backup or restorable project file is available.
- Confirm who is acting as operator, reviewer, and rollback owner.
- Review the selected modules and remove any proposed change that does not fit the lesson or platform.
- Confirm post-change evidence collection steps are ready before starting.

## Modules In Scope

- `default_accounts_review` | Default account review
- `password_policy` | Password policy strength
- `segmentation_and_subnets` | Segmentation and management subnet restrictions
- `industrial_protocol_review` | Industrial protocol exposure review
- `firmware_and_diagnostics` | Firmware and diagnostic evidence capture
