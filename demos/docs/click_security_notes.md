# CLICK PLC Security Notes  

---

## 1. Scope & Assumptions

These notes apply to typical CLICK PLC deployments that:

- Use **serial (RS-232 / RS-485)** and/or **Ethernet** connections for programming and HMI/SCADA integration.
- Store the **ladder program in non-volatile memory** (FLASH) and use **SRAM** for runtime data, backed by a supercapacitor for short-term retention.
- Are installed in industrial environments where **physical access is controllable but not perfect** (e.g., cabinets, panels, plant floor).

The goal is to identify **conceptual risk areas** and **defensive design considerations**, not to describe attacks or exploitation procedures.

---

## 2. Network Exposure Risks

### 2.1 Unrestricted Access to Communication Ports

**Risk description**  
CLICK PLCs may expose multiple communication interfaces:

- RS-232 ports for programming and monitoring  
- RS-485 ports for multi-drop industrial networks  
- Ethernet ports on certain models for programming and network integration  

If these ports are **logically and physically accessible** from untrusted networks (or shared with corporate IT networks), an attacker could:

- Interact with the PLC programming protocol
- Observe or interfere with control traffic
- Attempt unauthorized configuration changes

**Why this matters**  
The documentation describes ports and their intended use but does **not inherently guarantee isolation**, segmentation, or robust access control. If the PLC is reachable from a flat or poorly segmented network, it becomes part of the attack surface.

**Defensive considerations (high-level)**

- Place PLC networks behind **firewalls and industrial DMZs**.  
- Use **network segmentation** to separate control networks from corporate / internet-facing networks.  
- Limit access to programming ports to **known engineering stations** on controlled subnets.  
- Prefer **unidirectional or tightly controlled data paths** from control networks outward (e.g., for historian / monitoring only).

---

## 3. Default Configuration & Password Risk Areas

> These points are **general risk patterns** for industrial controllers. Consult vendor-provided security guidance and release notes for explicit, model-specific settings.

### 3.1 Reliance on Default or Weak Credentials

**Risk description**  
If a CLICK PLC or its associated software (programming tool, HMI, SCADA interface) ships with:

- Default passwords  
- Weak recommended passwords  
- Optional security features that are **disabled by default**

and operators leave these unchanged, an attacker with network or local access may be able to authenticate or modify the system with minimal effort.

**Why this matters**  
Documentation that focuses on wiring, mounting, ports, and memory behavior but does **not emphasize strong credential policies or access control** can lead to deployments where:

- Passwords are never changed from defaults  
- Shared credentials are used across many PLCs  
- Password length/complexity requirements are not enforced

**Defensive considerations (high-level)**

- Change any **default passwords** on PLCs, programming tools, and related HMIs/SCADA systems during commissioning.  
- Enforce **unique, strong credentials** per system or role.  
- Store credentials in a **central, audited vault** rather than ad hoc notes.  
- Periodically **review and rotate** passwords as part of maintenance.

---

### 3.2 Unhardened Default Network Services

**Risk description**  
CLICK PLCs that support Ethernet may expose one or more services (e.g., programming protocol, status monitoring, diagnostic services) when first powered up and configured with basic network settings.

If those services are **enabled by default** and reachable from untrusted networks, they expand the attack surface:

- Unauthenticated or weakly authenticated services  
- Plaintext protocols susceptible to eavesdropping  
- Lack of rate-limiting or lockout features

**Why this matters**  
Hardware manuals often describe **how to use** communication features but not how to **securely expose** them. Without a deliberate hardening checklist, deployments may leave all default services exposed.

**Defensive considerations (high-level)**

- Enable only the **minimal set of required services**.  
- Avoid exposing PLC services directly to **routable, shared, or internet-connected segments**.  
- Place remote access behind **VPNs or jump hosts** with strong auth and monitoring.  
- Use **firewall rules** to restrict which hosts and ports can talk to the PLC.

---

## 4. Program & Data Integrity Risks

### 4.1 Non-Volatile Program Storage

**Risk description**  
CLICK PLCs store ladder logic and project files in **non-volatile FLASH**. Once a program is downloaded, it persists across power cycles.

If an attacker gains authorized-looking access (e.g., via compromised engineering workstation or exposed programming interface), they can:

- Modify logic in subtle ways
- Embed unsafe states or logic bombs that survive power cycles
- Alter process interlocks or safety-related behaviors

**Why this matters**  
The persistence of control logic means that a **single successful unauthorized change** can have **long-term operational impact** until the program is audited and replaced.

**Defensive considerations (high-level)**

- Treat the **engineering workstation** and programming tool as **high-value assets**; harden them and restrict who can log in.  
- Maintain **version-controlled, signed, and reviewed copies** of ladder programs.  
- Use **change management**: every program change should be documented, peer-reviewed, and verified.  
- Periodically **re-download a known-good program** and compare against what’s running.

---

### 4.2 Volatile Runtime Data (SRAM + Supercapacitor)

**Risk description**  
Runtime data (registers, flags, counters) is kept in **SRAM** backed by a **supercapacitor** for short-term power loss. After a longer power outage, SRAM may clear and revert to default or initialization states.

While not a “vulnerability” in itself, this behavior can interact with security and safety:

- Unexpected reset of security-relevant flags or interlocks  
- Loss of diagnostic indicators that could be used in incident response  
- Reliance on **volatile** settings that are not persisted across power events

**Defensive considerations (high-level)**

- Design ladder logic so that **safe defaults** are assumed after power-up or SRAM loss.  
- Store critical configuration and security-related states in **non-volatile and auditable forms** where possible.  
- Include **power-cycle behavior** in safety and security testing.

---

## 5. Physical Access & Tamper Risk

### 5.1 Uncontrolled Access to Panels and Cabinets

**Risk description**  
If control cabinets and panels housing CLICK PLCs are:

- Unlocked  
- Located in publicly accessible or poorly monitored areas  
- Shared with third-party vendors without clear controls

then an attacker with physical access could:

- Connect to programming or communication ports  
- Replace or rewire I/O  
- Power-cycle or replace modules

**Why this matters**  
Many PLC architectures implicitly assume **trusted physical access**. A strong network security design can be undermined if attackers can directly reach the hardware.

**Defensive considerations (high-level)**

- Use **locked, labeled, and monitored** control cabinets.  
- Limit keys / access badges to **authorized personnel** only.  
- Include **physical inspections** in routine security audits.  
- Document all maintenance and access events for traceability.

---

## 6. Monitoring, Logging & Incident Response Gaps

### 6.1 Limited Native Logging

**Risk description**  
CLICK PLCs and similar devices often have **limited onboard logging** of:

- Configuration changes  
- Programming uploads/downloads  
- Authentication or access attempts  

Without centralized monitoring, unauthorized changes can go **undetected**.

**Defensive considerations (high-level)**

- Where possible, use the engineering workstation, SCADA system, or surrounding infrastructure to **log configuration changes** and operator actions.  
- Mirror important events to a **central logging or SIEM system**.  
- Establish a **baseline configuration** and periodically verify PLC state against it.  
- Incorporate PLCs into the organization’s **incident response plan** (who checks what, where logs come from, etc.).

---

## 7. Summary: Key Risk Themes for CLICK PLC Deployments

When reviewing CLICK PLC installations from a security perspective, focus on:

1. **Network Exposure**
   - Who can reach the PLC’s ports (serial and Ethernet)?
   - Are control networks segmented and firewalled?

2. **Defaults & Credentials**
   - Are any default passwords or “out-of-the-box” settings still in use?
   - Is there a consistent password policy and rotation schedule?

3. **Program & Data Integrity**
   - How are ladder programs stored, versioned, and audited?
   - Can you detect unauthorized changes?

4. **Physical Access**
   - Who can physically touch the PLC and its wiring?
   - Are cabinets controlled and monitored?

5. **Monitoring & Response**
   - How would you know if something changed on the PLC?
   - Is there a playbook for investigating and restoring a known-good state?

These notes are intended to **guide defensive hardening and structured assessment**, and should always be applied in coordination with vendor guidance, safety requirements, and organizational policy.