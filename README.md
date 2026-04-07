# Case Study: Offensive Exploitation & Defensive Monitoring (VulnNet: Active)

## 📌 Project Overview
This project documents a comprehensive security assessment of the "VulnNet: Active" environment. The goal was to demonstrate a complete attack chain—from initial access via service misconfiguration to local privilege escalation—while simultaneously analyzing the detection capabilities of a SIEM (Wazuh).

## 🛠️ Tools Used
- **Offensive:** Kali Linux, Redis-cli, Responder, John the Ripper, PrintSpoofer.
- **Defensive:** Wazuh SIEM, Windows Sysmon, Event Viewer.

## 🔴 Offensive Methodology
1. **Initial Recon:** Identified an open Redis port (6379) allowing unauthorized access.
2. **Credential Theft:** Used `config set dir` to point to a malicious SMB share, forcing the server to authenticate against my **Responder** instance.
3. **Cracking:** Captured the NTLMv2 hash for `VULNNET\enterprise-security` and cracked it via wordlist attack.
![vulnet](https://github.com/user-attachments/assets/c9c92be8-621e-4c15-8e99-dc19b5d7cacd)

5. **Privilege Escalation:** Exploited `SeImpersonatePrivilege` using **PrintSpoofer** to gain `nt authority\system` access.

## 🔵 Defensive Analysis (Wazuh/Sysmon)
The attack was monitored in a lab environment to validate alert triggers:
- **Alert:** "A member has been added to a local group with the security function enabled."
- **Analysis:** Detected the transition of a standard user to the `Builtin\Administrators` group.
- **Telemetry:** Sysmon Event ID 11 (FileCreate) and Event ID 1 (Process Creation) were used to correlate the malicious PowerShell script execution.
![local_admin_member](https://github.com/user-attachments/assets/faf5c729-b2f5-4de7-8822-4ebc3725e1e0)

## 🛡️ Mitigation Recommendations
- **Redis Hardening:** Enable `requirepass` and bind the service to localhost.
- **IAM:** Follow the Principle of Least Privilege (PoLP) and audit the `SeImpersonatePrivilege` assignments.
- **Monitoring:** Implement real-time alerts for any changes to sensitive local/domain groups.
![member_add](https://github.com/user-attachments/assets/b108df60-12d0-49dd-9604-bf73405b8f57)

```
<rule id="100050" level="12">
  <if_sid>61603</if_sid>
  <field name="sysmon.command_line">net user</field>
  <field name="sysmon.command_line">/add</field>
  <description>CRITICAL WARNING: An unauthorized local administrator (administrator) account has been created in the system!</description>
  <mitre>
    <id>T1136.001</id>
  </mitre>
</rule>
```
---

---

## 🛡️ Case Study 2: Proactive Vulnerability Management & GRC Alignment

### 🚨 Objective
Moving beyond reactive threat monitoring, this phase establishes an automated Vulnerability Management pipeline using Wazuh. The goal is to identify underlying weaknesses (like the ones exploited in Phase 1) before attackers do, and translate technical CVEs into actionable GRC (Governance, Risk, and Compliance) reports for audit readiness (e.g., ISO 27001: A.12.6.1).

### 🔍 Phase 1: Automated Asset & Vulnerability Discovery
I configured and activated Wazuh's native `<vulnerability-detection>` module to perform continuous, agent-based scanning. The SIEM automatically synchronized with the National Vulnerability Database (NVD) to audit the endpoint's OS and installed applications, providing a comprehensive risk posture overview.

![vul_dashboard](https://github.com/user-attachments/assets/90671c41-3567-482d-9fb9-dfd1bffd0d55)

### 🔴 Phase 2: Threat Triage & Risk Scoring
Instead of relying solely on automated patching, I manually triaged the discovered vulnerabilities. I specifically prioritized flaws with a **CVSS Score of 9.8 (Critical)**, indicating a high likelihood of exploitation (such as Remote Code Execution or privilege escalation vectors similar to the PrintSpoofer exploit).

![cve](https://github.com/user-attachments/assets/a2b3fdcf-5ce9-4243-9ffb-55622a90ab5c)

![cve_skore](https://github.com/user-attachments/assets/7485523e-6175-434d-813a-83ff378b1774)

### 📋 Phase 3: Root Cause Analysis & GRC Bridge
To bridge the gap between SOC Operations and IT Auditing, I performed Root Cause Analysis (RCA) on the critical CVEs to pinpoint the exact failing assets (e.g., outdated software versions or missing security rollups). 

By identifying the exact conditions causing the vulnerability, I can generate precise remediation tickets for IT teams. This ensures the organization maintains compliance with **ISO 27001 (Management of Technical Vulnerabilities)** and adheres to the Principle of Least Privilege (PoLP) and continuous patching policies.

![cve_detaylar](https://github.com/user-attachments/assets/0a443f0e-baee-4c97-a5f3-f9fa571c337b)

---

## 🎯 Case Study 3: Advanced Threat Hunting - Living Off The Land (LolBins)

### 🚨 Objective
Modern attackers often bypass traditional antivirus solutions by utilizing legitimate, pre-installed Windows binaries (LolBins) to execute malicious operations. This phase demonstrates the ability to simulate a "Living Off The Land" attack using `certutil.exe` and engineer custom SIEM rules to detect and alert on this evasive behavior.

### 🔴 Phase 1: The Evasion Simulation (Red Team)
I simulated an "Ingress Tool Transfer" attack by abusing the legitimate Windows Certificate Services tool (`certutil.exe`) to download a payload from an external server. 

Initially, the Endpoint Protection Platform (Windows Defender) successfully intercepted the payload execution, demonstrating solid prevention mechanisms. However, in a real-world scenario where EPP is bypassed or disabled, we need deep visibility.

![cmd_defender](https://github.com/user-attachments/assets/f9a77599-1e46-48c7-8636-06622026960d)

### 🔍 Phase 2: Deep Telemetry with Sysmon
To catch the evasive behavior, I configured Windows Sysmon to monitor detailed Process Creation (Event ID 1) telemetry. Even when using legitimate tools, the raw command-line arguments reveal the attacker's true intent.

![event_properties](https://github.com/user-attachments/assets/8fd861f4-3fbf-42ec-8fa6-fe08b7b65824)

### 🔵 Phase 3: Custom SIEM Engineering (Blue Team)
Relying on raw logs is not scalable. I engineered a custom XML detection rule in the Wazuh Manager to automatically parse Sysmon logs and trigger a "Level 12 - Critical" alert whenever `certutil.exe` is executed with the `-urlcache` parameter. 

This custom rule successfully mapped the behavior to the **MITRE ATT&CK Framework (T1105 & T1218)**, instantly translating raw telemetry into actionable Threat Intelligence.

![log_rulelevel](https://github.com/user-attachments/assets/c964f228-61af-484f-af69-319bcba94273)

![command_line](https://github.com/user-attachments/assets/e4b25133-ecce-4111-b25c-8d9cc87fc006)

---

## ☢️ Case Study 4: Automated SOC-to-Compliance Pipeline (Data Exfiltration)

### 🚨 Objective
Modern cybersecurity requires bridging the gap between technical SOC operations and Governance, Risk, and Compliance (GRC). This phase demonstrates how to detect a critical Data Exfiltration attempt and automatically map the incident to global regulatory frameworks (KVKK, GDPR, PCI-DSS, ISO 27001) in real-time.

### 🔴 Phase 1: The Exfiltration Simulation (Red Team)
To simulate a real-world breach, I established a Command and Control (C2) listener on a Kali Linux instance. Using a "Living off the Land" technique, I executed a PowerShell payload (`Invoke-WebRequest`) on the Windows endpoint to exfiltrate highly sensitive, simulated customer financial data (`credit_cards.txt`) directly to the C2 server.

### 🔵 Phase 2: GRC-Enriched Threat Detection (Blue Team)
Detecting the breach is only half the battle; reporting its business impact is the other. I engineered a highly specific, regex-powered XML rule in the Wazuh SIEM. 

When the SIEM caught the Sysmon Event ID 1 telemetry containing the exfiltration command, it didn't just trigger a Level 13 Critical Alert. The custom rule automatically tagged the alert with the specific compliance frameworks violated by this data leak: **GDPR, KVKK, PCI-DSS, and ISO 27001**. 

![command_line1](https://github.com/user-attachments/assets/eb0433b2-4886-4ca4-87e9-3a332ebbb878)

![rule_100052](https://github.com/user-attachments/assets/d4cc34da-a7b0-4013-85dc-b05e8312cfd4)

This automated tagging drastically reduces incident response time and provides immediate, audit-ready context for C-Level executives and compliance teams.
