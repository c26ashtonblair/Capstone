# Rollback Plan: CLICK PLC classroom trainer

Use this plan if a manual HMI change produces unexpected behavior.

1. Stop applying additional settings immediately.
2. Restore the most recent recorded pre-change value for the affected setting.
3. If the setting cannot be restored individually, reload the saved classroom backup or project export using the vendor-supported process.
4. Confirm the system returns to the pre-change state using screenshots, exports, and status indicators.
5. Re-run the post-change verification script against the restored evidence and note which values were rolled back.
6. Document the rollback trigger, affected setting, and final restored state.
