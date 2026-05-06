#!/usr/bin/env bash
set -euo pipefail

# Defensive OT network exposure audit script (authorized environments only)
# Usage: OT_SUBNET=10.10.0.0/24 bash network_exposure_audit.sh

: "${OT_SUBNET:?Set OT_SUBNET (example: 10.10.0.0/24)}"

OUT_DIR="audit_output"
mkdir -p "$OUT_DIR"

# Non-intrusive host discovery
nmap -sn "$OT_SUBNET" -oN "$OUT_DIR/01_host_discovery.txt"

# Conservative TCP service inventory for common ICS/management ports
nmap -sT -Pn -n --open -p 21,22,23,80,443,502,44818,102,789,2455 "$OT_SUBNET" -oN "$OUT_DIR/02_service_inventory.txt"

# Banner/version hints without exploit scripts
nmap -sV -Pn -n --version-light -p 502,44818,102 "$OT_SUBNET" -oN "$OUT_DIR/03_ics_protocol_hints.txt"

cat <<'EOF' > "$OUT_DIR/04_manual_review_checklist.txt"
Manual Review Checklist
- Confirm PLC programming ports are reachable only from approved engineering stations.
- Confirm no internet-routable exposure for PLC management interfaces.
- Confirm firewall ACLs enforce least privilege between IT and OT zones.
- Confirm all default credentials are removed and unique account policies are in place.
EOF

printf "Audit complete. Outputs in %s\n" "$OUT_DIR"
