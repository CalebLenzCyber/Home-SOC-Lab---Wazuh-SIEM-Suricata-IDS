markdown# Home SOC Lab — Wazuh SIEM & Suricata IDS (with SOAR Automation)

A self-built security operations lab simulating a small enterprise network, engineered to gain hands-on experience with SIEM deployment, custom detection engineering, SOAR playbooks, and network security monitoring.

**Status:** Active / Ongoing  

---

## 🔎 Project Overview
This lab simulates an enterprise security environment on a 3-node Proxmox VE cluster with segmented VLAN networking. It centers on a Wazuh SIEM that aggregates and correlates logs from Windows and Linux endpoints, extended with a Suricata network intrusion detection sensor for traffic-level visibility. 

The goal was to go beyond basic installation metrics and practice the full **detection and automation lifecycle**: simulating real attacks, identifying gaps in default rulesets, authoring custom correlation rules, engineering automated active response containment, and tuning out false positives against live traffic.

---

## 📊 Lab Architecture & Environment

Use code with caution.[Attacker Machine]Kali Linux VM(IP: 192.168.20.26)│▼ (Hydra Brute-Force Attacks)[Cisco Managed Switch] ───(SPAN Mirror Port)───► [Suricata IDS Sensor]│                                                 │ (eve.json via Agent)├─► [Linux Endpoint: Ubuntu Server] ◄─────────────┤ (IP: 192.168.20.25)└─► [Windows Endpoint: Windows 11] ◄──────────────┘ (IP: 192.168.20.21)
| Component | Technical Details |
| :--- | :--- |
| **Virtualization** | Proxmox VE 3-node cluster (`NODEFOUR`, `NODETHREE`, `NODETWO`) |
| **Networking** | Cisco managed switch, segmented VLAN (`192.168.20.0/24`), SPAN port mirroring |
| **SIEM / SOAR** | Wazuh (Manager, Indexer, Dashboard) |
| **Network IDS** | Suricata, fed via switch SPAN port |
| **Endpoints** | Windows 11 Enterprise (`PXMX-WIN11`), Ubuntu Server (`linuxsrv-01`), Kali Linux (`nodetwokali`) |
| **Remote Access** | Tailscale (Subnet routing into the lab VLAN) |

---

## 🛠️ Core Engineering Phases

### 1. Wazuh SIEM Deployment & Base Pipeline
Deployed and configured a central Wazuh manager. Installed and enrolled Wazuh agents on Windows and Linux endpoints to aggregate authentication logs, file integrity monitoring (FIM) events, and security configuration assessments (SCA) into a centralized dashboard.

### 2. Attack Simulation & Gap Analysis
Used **Hydra** to execute brute-force attacks against SSH (Linux) and RDP (Windows) targets to validate real out-of-the-box detection capabilities. This exposed a major discrepancy in default logging visibility:

| Target Protocol | Built-In Coverage Quality | Observations / Rule Details |
| :--- | :--- | :--- |
| **Linux SSH (Port 22)** | **Strong Layered Detection** | Triggered built-in rulesets (`5760`, `2501`, `2502`, `5758`, `40111`) cascading into frequency-based correlation alerts. Maps directly to **MITRE ATT&CK T1110 (Brute Force)**. |
| **Windows RDP (Port 3389)** | **Weak Single-Event Detection** | Generated flat, un-correlated Rule `60122` (Event ID 4625) failures. Did not group repeated failures into an actionable high-severity incident. |

---

### 3. Real-Time SOAR Playbook Engineering
To remediate threats automatically, a real-time Security Orchestration, Automation, and Response (SOAR) playbook was engineered inside the Wazuh manager's global configuration array (`/var/ossec/etc/ossec.conf`). The playbook architecture is split into three core phases:

#### Phase I: The Command Block (The Instructions)
Defines the executable tools available on the endpoint agents. The `<executable>` tells the manager what script to look for within the agent's internal workspace bin path (`/var/ossec/active-response/bin/`).
```xml
<ossec_config>
  <!-- Command Definition for Linux Active Response -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop.sh</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Command Definition for Windows Active Response -->
  <command>
    <name>win-firewall-drop</name>
    <executable>netsh.exe</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
```

#### Phase II: The Active Response Block (The Trigger)
Maps the defined tools to distinct alert thresholds and routing rules. 
```xml
  <!-- Active Response Trigger for Linux Agents -->
  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>2502,5551,5712,5716,5720</rules_id>
    <timeout>600</timeout>
  </active-response>

  <!-- Active Response Trigger for Windows Agents -->
  <active-response>
    <command>win-firewall-drop</command>
    <location>local</location>
    <rules_id>60122</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
```
* `<location>local`: Enforces that the mitigation script executes *only* on the specific agent compromised, preventing network-wide denial of service bugs.
* `<timeout>600`: Configures a 10-minute containment window before self-healing cleanups lift the block.

---

### 4. Active Response Validation & Execution Flow

#### Linux Containment Workflow
1. **Telemetry Generation:** Hydra flooded the target with bad credentials over SSH:
   ```bash
   hydra -I -l siemuser -P /usr/share/wordlists/rockyou.txt -t 4 ssh://192.168.20.25
   ```
2. **Log Forwarding:** The local agent monitored `/var/log/auth.log` and shipped raw data to the manager.
3. **Classification:** The manager matched telemetry against the core engine and flagged **Rule ID 5551** (*PAM: Multiple failed logins in a small period of time*).
4. **Mitigation Execution:** The manager verified the SOAR ruleset, parsed the attacker's IP (`192.168.20.26`), and instructed the agent to run `firewall-drop.sh add 192.168.20.26`.
5. **Verification:** Checking the live kernel state via `sudo iptables -L INPUT -n -v` confirmed the active network drop:
   ```text
   DROP all -- 192.168.20.26 0.0.0.0/0
   ```
6. **Self-Healing:** After 10 minutes, the manager dispatched a cleanup instruction, running `firewall-drop.sh delete 192.168.20.26` to safely restore network normal operations.

#### Windows Containment Workflow
1. **Telemetry Generation:** Hydra targeted the Windows endpoint via the Remote Desktop Protocol:
   ```bash
   hydra -I -l <user> -P /usr/share/wordlists/rockyou.txt -t 2 rdp://192.168.20.21
   ```
2. **Classification:** High-velocity Windows Event ID 4625 (Logon Failure) logs mapped directly to Wazuh **Rule ID 60122**.
3. **Mitigation Execution:** The manager intercepted the match, fired the playbook, and logged alert **Rule ID 657** (*Active response: active-response/bin/netsh.exe - add*).
4. **Verification:** Running advanced filtering inside PowerShell verified that the Advanced Windows Defender Firewall dynamically isolated the source threat:
   ```powershell

   ![PowerShell Advanced Firewall Verification Output](screenshots/powershell_output.png)

   Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Active Response*" -or $_.Name -like "*Wazuh*" } | Get-NetFirewallAddressFilter
   # Output -> RemoteAddress: 192.168.20.26
   ```

##### Dashboard Verification Log Trail
```text
[Timestamp]                  [Agent Name]    [Rule Description]                                          [Level]  [Rule ID]
Jul 28, 2026 @ 20:18:13.480  PXMX-WIN11      Active response: active-response/bin/netsh.exe - add        3        657
Jul 28, 2026 @ 20:18:11.631  PXMX-WIN11      Active response: active-response/bin/netsh.exe - add        3        657
Jul 28, 2026 @ 20:18:11.552  PXMX-WIN11      Active response: active-response/bin/netsh.exe - add        3        657
Jul 28, 2026 @ 20:18:10.195  PXMX-WIN11      Logon Failure - Unknown user or bad password                5        60122
```

---

### 5. Network IDS Deployment & Routing Workarounds (Suricata)
Deployed Suricata on a dedicated network sensor fed via a switch SPAN port. Engineering this required overcoming specific hardware and architectural limitations:
* Configured the SPAN session at the Cisco switch level and validated mirror integrity.
* Configured the sensor's network interface to **promiscuous mode**.
* **The Single-NIC Constraint:** A SPAN destination port is receive-only, meaning a single-NIC sensor can ingest traffic but cannot report alerts to the SIEM. I resolved this by provisioning a second NIC dedicated to management/reporting and adjusting kernel routing metrics to prevent subnet routing conflicts between the two interfaces.

### 6. Wazuh–Suricata Integration & Troubleshooting
Ingested Suricata's `eve.json` output into Wazuh as a live log source. During implementation, diagnosed and resolved a multi-layer agent enrollment failure by troubleshooting system logs chronologically:
1. Fixed a missing `<auth>` configuration block preventing the enrollment service from initializing.
2. Resolved an SSL certificate file ownership mismatch preventing the authentication service from reading its private key.
3. Fixed a malformed empty XML tag causing the service to crash silently.
*All issues were isolated using systemd diagnostics and manual foreground execution rather than guesswork.*

### 7. Alert Tuning & False Positive Reduction
Authored a custom Suricata rule to detect port-scanning behavior, then iteratively tuned it against network noise:
* **v1 (Broad):** Triggered on any single SYN packet. Generated massive false positives on routine network traffic.
* **v2 (Thresholded):** Added a frequency threshold (`detection_filter`). Reduced noise, but still false-positived on a legitimate management UI polling infrastructure hosts at high frequency. 
* **v3 (Optimized):** Authored explicit `pass` rules to allow-list trusted infrastructure traffic before reaching the detection rule. Validated using before-and-after log analysis, confirming false positives were eliminated while genuine scan traffic remained visible.

---

## 💡 Key Takeaways
* **Default rulesets have gaps.** Out-of-the-box configurations are rarely sufficient. The Windows RDP gap demonstrated the necessity of proactive detection gap analysis and custom correlation rule writing.
* **Volume-based detection requires context.** Naive thresholds cannot distinguish a busy legitimate management tool from an attacker. Tuning requires deep environment context.
* **Context-Aware Parsing Boundaries:** Automation playbooks depend entirely on fields extracted by decoders. Local system violations (like `sudo` typos via rule 5404) lack a network `srcip`, forcing network mitigation scripts to abort safely to protect platform availability. Targeting explicit network rules prevents this mismatch.
* **Infrastructure underpins security.** A significant portion of security engineering involves solving system administration, routing, and configuration blockers. Resolving these prerequisites is highly reflective of real-world enterprise SOC engineering.
