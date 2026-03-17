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
