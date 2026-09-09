# Home SOC Lab — Wazuh SIEM & Suricata IDS

A self-built security operations lab simulating a small enterprise network, built to gain hands-on experience with SIEM deployment, detection engineering, and network security monitoring.

**Status:** Active / ongoing

---

## Overview

This lab simulates a small enterprise security environment on a 3-node Proxmox VE cluster with segmented VLAN networking. It centers on a Wazuh SIEM that aggregates and correlates logs from Windows and Linux endpoints, extended with a Suricata network intrusion detection sensor for traffic-level visibility. The goal was to go beyond "install and run" and actually practice the full detection lifecycle: simulate real attacks, find gaps in default detection coverage, write custom rules to close them, tune those rules against real traffic, and validate results with before/after data.

## Environment

| Component | Details |
|---|---|
| Virtualization | Proxmox VE, 3-node cluster (NODEFOUR, NODETHREE, NODETWO) |
| Networking | Cisco managed switch, segmented VLAN (192.168.20.0/24), SPAN port mirroring |
| SIEM | Wazuh (manager, indexer, dashboard) |
| Network IDS | Suricata, fed via switch SPAN port |
| Endpoints | Windows 11 (target/agent), Ubuntu Server (target/agent), Kali Linux (attacker box) |
| Remote access | Tailscale (subnet routing into the lab VLAN) |

## What's Been Built

### 1. Wazuh SIEM Deployment
Deployed and configured a Wazuh manager with agents on Windows and Linux endpoints, aggregating authentication logs, file integrity events, and security configuration assessments into a central dashboard.

### 2. Attack Simulation & Detection Validation
Used Hydra to run brute-force attacks against SSH (Linux) and RDP (Windows) targets to test real detection coverage rather than assuming default rulesets were adequate.

- **Linux/SSH:** Confirmed Wazuh's built-in ruleset (rules 5760, 2501, 2502, 5758, 40111) provides strong layered detection, culminating in frequency-based correlation alerts.
- **Windows/RDP:** Found that the default ruleset (rule 60122) does *not* correlate repeated authentication failures into an actionable alert — a real, documented detection gap.

### 3. Custom Detection Rule (Wazuh)
Closed the Windows RDP gap by authoring a custom correlation rule using `frequency`/`timeframe` attributes, `if_matched_sid`, and `same_source_ip` matching — validated against live brute-force traffic until it fired correctly.

### 4. Automated Response
Configured Wazuh Active Response on both Windows and Linux endpoints to automatically block the attacking IP address when brute-force detection rules fire, completing a full **detect → alert → auto-contain** loop.

### 5. Network IDS Deployment (Suricata)
Deployed Suricata on a dedicated sensor, fed via a switch SPAN port mirroring traffic from all three Proxmox nodes. This required:

- Configuring the SPAN session at the switch level and validating mirror integrity
- Setting the sensor's network interface to promiscuous mode
- Solving a real architectural constraint: a SPAN destination port is receive-only, so a single-NIC sensor can capture traffic but can't report findings anywhere. Solved by adding a second NIC dedicated to reporting, and correcting kernel routing metrics so both interfaces could coexist on the same subnet without conflict.

### 6. Wazuh–Suricata Integration
Wired Suricata's `eve.json` output into Wazuh as a live log source. Diagnosed and resolved a multi-layer agent enrollment failure by working through:

- A missing `<auth>` block preventing the enrollment service from running at all
- An SSL certificate ownership mismatch preventing the auth service from reading its own key
- A malformed empty XML tag causing the service to crash silently

Each issue was isolated using service logs, manual foreground execution, and systemd diagnostics rather than guesswork.

### 7. Custom Detection Rule (Suricata) & Alert Tuning
Authored a custom Suricata rule to detect port-scanning behavior, then iteratively tuned it:

- **v1:** Fired on any single SYN packet — far too broad, false-positived on routine traffic
- **v2:** Added a frequency threshold (detection_filter) — reduced noise, but still false-positived on legitimate high-frequency infrastructure traffic (a management UI polling repeatedly), because busy legitimate hosts and an actual scanning attacker can produce statistically similar packet volume
- **v3:** Added explicit `pass` rules to allow-list known-good infrastructure traffic before it reaches the detection rule — validated with before/after alert log comparisons showing the false positives eliminated while real scan traffic was still caught

## Key Takeaways

- **Default rulesets have real gaps.** Assuming out-of-the-box detection coverage is adequate is a mistake — the Windows RDP gap here is a documented, reproducible example.
- **Volume-based detection alone isn't enough.** A naive threshold can't distinguish a busy legitimate host from an attacker if both produce similar traffic volume; effective tuning requires understanding *what's actually happening* on the network, not just adjusting numbers.
- **Infrastructure problems block security problems.** A meaningful amount of this project was solving mundane infrastructure issues (permissions, XML config, routing, NIC constraints) that had nothing to do with detection logic but were prerequisites for any of it to work — a realistic reflection of actual SOC/security engineering work.

## Next Steps

- Integrate Microsoft 365 (Entra ID / Exchange audit logs) as an additional Wazuh log source
- Map existing detections to MITRE ATT&CK technique IDs
- Build a comparative dashboard (Windows vs. Linux vs. network-layer detection activity)
- Continue alert tuning practice across the existing Wazuh ruleset

---

*This lab is built and maintained independently for hands-on cybersecurity skill development.*
