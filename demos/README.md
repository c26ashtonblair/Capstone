# `<PLC_MODEL>` PLC Security Assessment
*Authorized Hardware Security Research – README*


---

## Table of Contents
1. [Project Overview](#1-project-overview)  
2. [Scope & Rules of Engagement](#2-scope--rules-of-engagement)  
3. [Legal, Safety & Ethics](#3-legal-safety--ethics)  
4. [High‑Level Methodology (Non‑Actionable)](#4-high-level-methodology-non-actionable)  
5. [Lab Environment & Reproducibility](#5-lab-environment--reproducibility)  
6. [Sample PLC Vulnerability Report](#6-sample-plc-vulnerability-report)  
7. [Responsible Disclosure Process](#7-responsible-disclosure-process)  
8. [Appendices & References](#8-appendices--references)  
9. [FAQ](#9-faq)  
10. [Contribution Guidelines](#10-contribution-guidelines)  
11. [Acknowledgements](#11-acknowledgements)

---

## 1. Project Overview

**Name:** `"<PLC_MODEL> PLC Security Assessment"`  
**Short description:** Defensive hardware security research to identify, validate, and remediate confidentiality, integrity, and availability issues in the `<PLC_MODEL>` PLC family.

**Goals**
- Identify design and implementation weaknesses that threaten PLC security.  
- Produce reproducible, defensible experiments for mitigation verification.  
- Deliver actionable remediation guidance to the vendor and site operators.  
- Publish non‑sensitive findings under an agreed disclosure policy.

---

## 2. Scope & Rules of Engagement

| Item | Description |
|---|---|
| **Target device(s)** | `<PLC_MODEL>` series; serial numbers `SN-<XXXXXX>` … `SN-<YYYYYY>` (**only** those listed here). |
| **Timeframe** | `<YYYY-MM-DD>` – `<YYYY-MM-DD>`. |
| **Testing types permitted** | Risk assessment; static firmware review; configuration review; controlled lab testing; fuzzing/emulation (where authorized). |
| **Out‑of‑scope / Forbidden** | Testing without written consent; any activity that could damage production equipment or compromise process safety; data exfiltration beyond what is necessary to demonstrate a vulnerability; public disclosure of exploit steps or payloads. |
| **Authorization** | Attach a signed copy of the owner’s authorization. See `LEGAL/authorization_template.pdf`. |
| **Contact** | `<OWNER_NAME>`, `<OWNER_ROLE>`, `<owner@email.com>` (PGP: `0xDEADBEEF`). |

---

## 3. Legal, Safety & Ethics

| Topic | Guidance |
|---|---|
| **Legal compliance** | Comply with applicable laws and regulations (e.g., ITAR/EAR, GDPR) and facility/industry safety rules (e.g., OSHA, IEC 61508). |
| **Responsible disclosure** | Follow the process in [Section 7](#7-responsible-disclosure-process). |
| **Safety** | Isolate PLCs from live production; use lock‑out/tag‑out; current‑limited supplies (≤ 3 A); test enclosure/Faraday cage as appropriate; adhere to site procedures for control‑system equipment. |
| **Privacy & data handling** | Minimize collection of PII; store redacted logs encrypted (e.g., AES‑256); restrict access to authorized personnel. |

---

## 4. High‑Level Methodology (Non‑Actionable)

1. **Threat Modeling & Architecture Review**  
   Map PLC architecture, field‑bus interfaces (e.g., Modbus/TCP, EtherNet/IP, PROFINET), HMI, and data flows.

2. **Design & Firmware Review**  
   Static analysis of firmware binaries, startup scripts, and configuration files to identify insecure defaults, weak cryptography, and boot‑integrity gaps.

3. **Behavioral & Functional Testing**  
   Controlled tests of authentication, update mechanisms, safety‑logic behavior, and network behavior; record expected vs. observed results.

4. **Emulation / Sandbox Testing**  
   Reproduce PLC behavior with a simulator/emulator (e.g., vendor emulator, OpenPLC, or a custom sandbox) in an isolated lab.

5. **Side‑Channel & Physical Robustness Assessment**  
   Evaluate protections around debug interfaces (UART/JTAG), power filtering, tamper evidence, and basic fault‑tolerance characteristics.

6. **Mitigation & Verification**  
   Propose hardening measures (e.g., strong auth, signed updates, field‑bus lockdown) and verify them in the lab.

> Raw exploit code or step‑by‑step exploitation instructions are **not** included in this repository and must **never** be published publicly.

---

## 5. Lab Environment & Reproducibility

| Folder | Purpose |
|---|---|
| `lab/` | Minimal test harness (scripts, network‑bus mockups, clean firmware images). |
| `configs/` | Sanitized PLC network & safety‑logic configs (no secrets). |
| `simulations/` | Dummy inputs for field‑bus simulators. |
| `logs/` | Redacted logs tied to findings. |
| `reports/` | Machine‑readable JSON/CSV summaries of findings. |

**Key tools that can be part of the harness**

| PLC field‑bus | Recommended emulator / simulator |
|---|---|
| Modbus/TCP | Modbus‑TCP server; custom Python emulation |
| EtherNet/IP | OpENer / vendor emulator |
| PROFINET | Profinet‑Simulator / vendor test harness |
| *(Add/remove protocols as required)* | |

---

## 6. Sample PLC Vulnerability Report

<details>
<summary><strong>Click to expand</strong></summary>

### Initial Confidential Report

**Title**  
Unsecured Modbus/TCP Gateway on `<PLC_MODEL>` – CVSS 7.3

**Severity**  
**CVSS v3.1 Base Score**: 7.3 (High)

**Discovery Date**  
`2025-10-12`

**Device Details**  
- **Manufacturer**: `<MANUFACTURER>`  
- **Model**: `<PLC_MODEL>`  
- **Serial**: `SN-<XXXXX>`  
- **Field‑bus**: Modbus/TCP (port 502) exposed to the process network

**Impact Statement**  
The Modbus/TCP service is enabled on the PLC’s default configuration and does **not** enforce authentication. An attacker who gains network connectivity can send arbitrary Modbus requests, read/write PLC memory, and potentially bypass safety logic.  
*Business Impact*: Risk of accidental shutdown or unsafe release of controlled material.  
*Technical Impact*: Potential remote code execution (RCE) in the PLC runtime; disclosure of process parameters.

**Evidence (Redacted)**  
- `logs/modbus_scan.txt` – shows successful connection on port 502.  
- `logs/firmware_bin_analysis.txt` – indicates hard‑coded Modbus port and disabled authentication flag.  
- `simulations/modbus_read_example.py` – benign script that reads PLC data via Modbus (no harmful side effects).

**Remediation Recommendations**

| Category | Suggested Fix | Verification |
|---|---|---|
| **Network** | Disable Modbus/TCP if not needed; if required, enable authentication and encryption. | Verify service is inaccessible from non‑authorized VLANs. |
| **Firmware** | Remove hard‑coded Modbus port; enable authentication features. | In emulator, confirm Modbus rejects unauthenticated access. |
| **Configuration** | Enforce signed updates for PLC program/config files. | Lab deploy: unsigned uploads are rejected. |

**Verification Checklist**  
- [ ] Modbus/TCP requires authentication or is disabled.  
- [ ] Firmware update requires a valid signature.  
- [ ] Safety‑logic status flags are protected from unauthorized writes.  
- [ ] Field‑bus interfaces are segmented and monitored.

---

### Vulnerability Report – `<Device ID>`

**Executive Summary**
- **Asset**: `<PLC_MODEL>`, SN: `<SN>`  
- **Version**: `<Firmware Version>`  
- **Date discovered**: `<YYYY‑MM‑DD>`  
- **Severity**: High (CVSS 7.8)  
- **Risk**: Unauthenticated Modbus/TCP access allows unauthorized commands and data access.

**Detailed Findings**

| Section | Description | Evidence | Remediation |
|---|---|---|---|
| 2.1 | **Weak default credentials** | Default `admin:admin` active. | Change credentials; enforce password policy. |
| 2.2 | **Unencrypted Modbus/TCP** | Clear‑text payloads observed in lab capture. | Enable encryption/tunneling; restrict to secure VLANs. |
| 2.3 | **Missing boot‑integrity check** | Firmware lacks signed hash check. | Implement signed bootloader and signed firmware. |

**Recommendations**
- Apply a hardened firmware image with signed boot and signed updates.  
- Disable or restrict Modbus/TCP from non‑PLC subnets.  
- Enforce strong passwords and remove defaults.  
- Implement network segmentation and firewall rules for the PLC subnet.

**Mitigation Validation**

| Test | Expected Result | Observed Result | Pass/Fail |
|---|---|---|---|
| Firmware signing | Signed image validated at boot. | `Pass` | `Pass` |
| Modbus/TCP authentication | Default creds fail; auth required. | `Pass` | `Pass` |
| Network segmentation | No Modbus from outside PLC subnet. | `Pass` | `Pass` |

</details>

---

## 7. Responsible Disclosure Process

| Step | Description |
|---|---|
| **Initial notification** | Send a confidential report to the vendor within 48 h of discovery (secure email/portal). |
| **Vendor confirmation** | Await acknowledgement and a ticket/CASE ID. |
| **Patch release** | Collaborate on patch/hardened firmware. |
| **Public release** | After public fix or after 90 days (whichever is sooner), release a sanitized advisory. |

---

## 8. Appendices & References

- **Glossary**: *(link to glossary)*  
- **Reference Standards**:  
  - IEC 61508 – Functional safety of E/E/PE safety‑related systems.  
  - NIST SP 800‑82 – Guide to Industrial Control Systems (ICS) Security.  
  - ISO/IEC 27001 – Information Security Management.  
- **Contact Matrix**:  
  - **Vendor**: `<vendor@domain>`  
  - **Site Security Lead**: `<site.lead@domain>`  
  - **Security Researcher**: `<researcher@domain>`

---

## 9. FAQ

| Question | Answer |
|---|---|
| *Is it legal to publish the findings?* | Only non‑sensitive information is published after a vendor fix or agreed embargo. |
| *Can I share this repo publicly?* | Yes: share **README.md** and **redacted reports** only. Keep raw firmware/logs/scripts private. |
| *How do I keep logs secure?* | Store in `logs/` as encrypted JSON; share decryption keys only with authorized parties. |
| *What if I discover an unpatched issue?* | File a confidential report and follow [Section 7](#7-responsible-disclosure-process). |

---

## Demo Entry Point

`web_search_tool.py` can now be used as a defensive security-script generation agent.

Example:

```bash
python3 demos/web_search_tool.py \
  --target "CLICK PLC" \
  --context-file demos/docs/click_security_notes.md \
  --context-file demos/docs/warning.txt \
  --query "CLICK PLC firmware hardening" \
  --output-dir demos/generated_security_scripts
```

Outputs:
- `security_research_brief.md`
- `generated_security_test_plan.md`
- `<target>_security_baseline.py`

The generated script is limited to authorized, non-destructive baseline checks against exported configuration data and operator-supplied inventory files.

---

## 10. Contribution Guidelines

- Create a new branch per device or test.  
- Keep `lab/`, `configs/`, and `simulations/` clean and version‑controlled.  
- Place outputs in `reports/` (JSON/CSV).  
- **Do not** commit raw firmware, sensitive logs, or PII—use redacted placeholders.

---

## 11. Acknowledgements

- Thanks to the **Vendor Security Team**, **Site Operations**, and the **Academic Research Group** for collaboration.  
- Built on foundational work in industrial control security and open‑source protocol simulators (Modbus‑TCP, EtherNet/IP, PROFINET).

---

### 📌 Remember

> **All findings are confidential until the vendor publishes a fix** (or the agreed embargo expires).  
> **Never** share raw logs, firmware binaries, or device‑specific details outside authorized channels.

---

> **Stay safe and professional.**  
> — *`<PLC_MODEL>` Security Research Team*
