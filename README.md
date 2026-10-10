# 🛡️ Meridian | Healthcare Web Portal Threat Hunt

<img width="850" alt="image" src="https://github.com/user-attachments/assets/21e2b34a-6584-4329-b85e-63755c71036f" />


**Single-host intrusion investigation · Azure Log Analytics · Kusto Query Language (KQL)**

**Analyst:** Katy Senia  
**Environment:** Simulated healthcare web portal, Cyber Range threat hunt  
**Incident date:** February 6, 2026 (UTC)  
**Investigation type:** Threat hunting, intrusion reconstruction and incident response analysis

> **Lab disclaimer:** This project documents a simulated cybersecurity incident. All systems, accounts, IP addresses and findings refer to the lab scenario, not a real healthcare breach.

 ## 📄 Threat Hunt Report

The original 18-page investigation report contains the KQL results and supporting telemetry:

- [Full Investigation Report (PDF)](https://drive.google.com/file/d/17C5tLCQojZ3PBcWDJfArlVIxj-zdXYlC/view?usp=drive_link)

## 🎯 Project Overview

This investigation reconstructs a multi-stage intrusion against the Meridian healthcare web portal using Azure Log Analytics and KQL. The hunt follows reconnaissance, path traversal, credential and SSH access, privilege escalation, persistence, command-and-control attempts, database activity, detection gaps and incident response.

The goal was to follow the activity across different logs, separate confirmed findings from assumptions and identify what still needed remediation.

### 🧰 Tools and Skills

- **Platforms:** Microsoft Azure Log Analytics
- **Query language:** Kusto Query Language (KQL)
- **Telemetry:** Web access, authentication, audit, Defender, MySQL and process snapshots
- **Investigation techniques:** Timeline reconstruction, log correlation, threat hunting, root-cause analysis, evidence validation
- **Framework:** MITRE ATT&CK mapping

## 🧭 Table of Contents

- [Investigation Summary](#-investigation-summary)
- [Data Sources and Time Handling](#-data-sources-and-time-handling)
- [Investigation Findings](#-investigation-findings)
- [Attack Chain and ATT&CK Context](#-attack-chain-and-attck-context)
- [Lessons Learned](#-lessons-learned)
- [Conclusion](#-conclusion)
- [Supporting Evidence](#-supporting-evidence)

## 📌 Investigation Summary

| Item | Finding |
| --- | --- |
| Attacker IP | `10.1.134.57` |
| Vulnerable endpoint | `config_viewer.php` |
| Files accessed | `/etc/passwd`, `database.conf` |
| Compromised account | `svc_backup` (successful SSH authentication) |
| Privilege escalation | `/tmp/rootbash -p` (effective UID 0) |
| Persistent backdoor | `/opt/meridian/scripts/health_check` |
| C2 destination | `10.1.134.57:43212` |
| Application data involved | Patient records in `meridian_patients` |
| Tampered configuration | `backup.conf` |
| Detection gap | Automated removal of `sysmon.service` |
| Memory acquisition | AVML → `/tmp/evidence/memory.lime` |
| Outstanding response action | Manual termination and removal of `health_check` |

## 🕒 Data Sources and Time Handling

| Log table | Investigative purpose |
| --- | --- |
| `MeridianAccess_CL` | HTTP requests, URL paths, status codes and user agents |
| `MeridianAuth_CL` | SSH and authentication events |
| `MeridianAudit_CL` | Process execution and UID context |
| `MeridianDefender_CL` | Detections, blocked traffic and automated sweeps |
| `MeridianMySQL_CL` | Database activity |
| `MeridianNetwork_CL` | Socket and network snapshots |
| `MeridianSnapshot_CL` | Process snapshots and beacon details |

**Important timestamp distinction:** `TimeGenerated` represented log ingestion time, not the actual incident time. The investigation used `EventTime_t` for chronological filtering and ordering.

## 🔎 Investigation Findings

### 1. 🔭 Reconnaissance

#### 1.1 The Recon Playbook

**Investigation question:** Which tools did the attacker use during reconnaissance?

**Finding:** Nmap, curl, WhatWeb and gobuster

**Evidence interpretation:** The attacker progressed from scanning to manual web requests, technology fingerprinting and automated content enumeration. The large Gobuster request count was consistent with wordlist-based discovery.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAccess_CL
| where isnotempty(EventTime_t)
| summarize FirstSeen=min(EventTime_t), Requests=count() by UserAgent_s, ClientIp_s
| order by FirstSeen asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/ffcf16c8-e8c2-480f-bc55-45df0513db06" />

### 2. 🚪 Initial Access

#### 2.1 The Traversal Point

**Investigation question:** Which endpoint became the attacker’s path-traversal entry point?

**Finding:** `config_viewer.php`

**Evidence interpretation:** The endpoint appeared in deliberate attacker activity before mass wordlist scanning and later accepted a `file` parameter used for traversal.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s contains "config_viewer.php"
| project EventTime_t, UserAgent_s, HttpMethod_s, RequestUri_s, StatusCode_s, ResponseSize_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/077fc0be-c2eb-4ca9-8087-396f87b0a5ee" />

#### 2.2 What They Pulled

**Investigation question:** Which two files were successfully read through the vulnerable file parameter?

**Finding:** `/etc/passwd` and `database.conf`

**Evidence interpretation:** Two HTTP 200 responses are consistent with successful file retrieval through the traversal parameter. Response codes alone do not reveal the returned file contents.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s contains "file="
| project EventTime_t, RequestUri_s, StatusCode_s, ResponseSize_s, UserAgent_s
| order by EventTime_t asc
```

</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/f2ae8348-9ba2-4a13-b147-218b15dd6648" />

### 3. 🔑 Credential Access

#### 3.1 Borrowed Access

**Investigation question:** Which account was successfully used for SSH access?

**Finding:** `svc_backup`

**Evidence interpretation:** Authentication telemetry recorded an accepted password for `svc_backup` from `10.1.134.57` shortly after `database.conf` was read. This confirms successful password authentication, not the exact credential value or how it was obtained.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
| where EventTime_t between (datetime(2026-02-06 04:08:34) .. datetime(2026-02-06 04:10:00))
| project EventTime_t, ProcessName_s, RawMessage_s, SourceIP, SourcePort_s, TargetUser_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/8da49050-b800-431d-b7bd-1c25550e0df3" />

#### 3.2 The Road Not Taken

**Investigation question:** What two other root-access approaches were attempted, and why did they fail?

**Finding:** Disallowed `sudo` command and failed root SSH password attempts

**Evidence interpretation:** Defender telemetry showed a disallowed `sudo` action and authentication logs showed failed root-password attempts from the attacker IP.

<details>
<summary>View KQL query 1</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "sudo"
| project EventTime_t, EventCategory_s, RawMessage_s, SourceIP
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/10ef7277-7210-434e-9a78-727fa98a2e77" />

<details>
<summary>View KQL query 2</summary>

```kusto
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where SourceIP == "10.1.134.57"
| where TargetUser_s == "root"
| project EventTime_t, RawMessage_s, SourceIP, TargetUser_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/5b4b9df8-cf0e-4e37-94b6-7ac83464e537" />

### 4. ⬆️ Privilege Escalation

#### 4.1 The Planted Root Shell

**Investigation question:** Which binary and flag produced root-level execution?

**Finding:** `/tmp/rootbash -p`

**Evidence interpretation:** Audit telemetry recorded the binary running with effective UID 0 despite originating in a non-root user context.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where Argv_s contains "rootbash"
or exe_s contains "rootbash"
or comm_s contains "rootbash"
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/729376fc-9089-467c-808a-490ae3b78674" />

### 5. 🪝 Persistence

#### 5.1 The Second Foothold

**Investigation question:** Where was the less-obvious secondary foothold located?

**Finding:** `/opt/meridian/scripts/health_check`

**Evidence interpretation:** The process snapshot showed real UID 1001 and effective UID 0, consistent with privileged execution. The snapshot alone does not establish how the binary was launched or made persistent.

<details>
<summary>View KQL query</summary>

```kusto
MeridianSnapshot_CL
| where ProcBeaconName_s == "health_check"
| project EventTime_t, ProcBeaconName_s, ProcBeaconExeLink_s,
ProcBeaconPid_s, ProcBeaconPPid_s, ProcBeaconUid_s,
ProcBeaconGid_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/351def6b-1060-4913-bd65-224d213b5365" />

#### 5.2 Why It Survived

**Investigation question:** Why did the automated sweep detect `health_check` but leave it behind?

**Finding:** Non-baseline binary outside the automated cleanup categories

**Evidence interpretation:** The sweep flagged `health_check` under `/opt`, but its automated cleanup covered other categories such as SSH keys, crontabs, services and temporary directories.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s contains "health_check"
| project EventTime_t, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/091b682e-5ca3-4d04-a513-acb78e11f4b8" />

### 6. 📡 Command and Control

#### 6.1 Calling Home

**Investigation question:** Where was the backdoor trying to connect, and did the network block neutralize it?

**Finding:** Blocked attempts to `10.1.134.57:43212`; the backdoor process remained present

**Evidence interpretation:** Repeated outbound blocks demonstrated network containment while repeated attempts indicated the underlying process remained active.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06 04:40:15)
| where EventCategory_s == "NETWORK"
| project EventTime_t, EventCategory_s, RawMessage_s, SourceIP
| order by EventTime_t asc
```

</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/254364a7-536b-479e-ba3b-e95bb2af954e" />

#### 6.2 What the Block Proves

**Investigation question:** What can repeated network blocks prove, and what can they not prove?

**Finding:** They prove traffic was blocked, not that the backdoor was terminated

**Evidence interpretation:** A firewall block establishes containment of that destination, not endpoint eradication.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s == "NETWORK"
| where RawMessage_s contains "Blocked"
| summarize BlockedAttempts=count() by RawMessage_s
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/de20a29b-97bb-4fb5-bd0f-9e88fa67e1de" />

### 7. 🗃️ Collection

#### 7.1 Patient Data Access

**Investigation question:** What kind of application data was collected?

**Finding:** Queries involving patient records

**Evidence interpretation:** MySQL activity involved the `meridian_patients` database and `patients` table, showing activity involving patient information. These logs alone do not establish external exfiltration.

<details>
<summary>View KQL query</summary>

```kusto
MeridianMySQL_CL
| where isnotempty(EventTime_t)
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/404389a5-aa9f-440f-8443-8f548255e724" />

#### 7.2 The Tampered File

**Investigation question:** Which configuration file was caught and reverted during the final sweep?

**Finding:** `backup.conf`

**Evidence interpretation:** The final sweep explicitly reported that `backup.conf` had been tampered with and was being reverted.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s == "SWEEP"
| order by EventTime_t desc
| project EventTime_t, RawMessage_s
```
</details>

<img width="500" alt="image" src="https://github.com/user-attachments/assets/482b5e9d-a47d-4eb5-a734-4b83c0cfefd8" />

### 8. 🚨 Detection Gaps

#### 8.1 Signal or Setup Noise

**Investigation question:** Were the early SSH-key, crontab and service detections part of the real intrusion?

**Finding:** Earlier setup/baseline activity, not part of the confirmed intrusion

**Evidence interpretation:** The events preceded the confirmed attacker timeline and should not be attributed to the later intrusion.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s == "SWEEP"
| where RawMessage_s contains "SSH"
or RawMessage_s contains "Crontab"
or RawMessage_s contains "service"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```
</details>

<img width="500" alt="image" src="https://github.com/user-attachments/assets/81294f80-f455-4e71-8bf0-d30bf4697ff6" />

#### 8.2 Collateral Damage

**Investigation question:** Which legitimate defensive service was removed, and what visibility was lost?

**Finding:** `sysmon.service`; Sysmon logging visibility

**Evidence interpretation:** An automated sweep removed the service before the confirmed intrusion, leaving gaps in endpoint/security telemetry.

<details>
<summary>View KQL query</summary>

```kusto
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where EventCategory_s == "SWEEP"
| where RawMessage_s contains "service"
| project EventTime_t, RawMessage_s
| order by EventTime_t asc
```
</details>

<img width="500" alt="image" src="https://github.com/user-attachments/assets/3b6f54be-b6c6-4134-b1d9-02ca8417c8c1" />

### 9. 🧯 Incident Response

#### 9.1 Capturing the Evidence

**Investigation question:** Which memory-acquisition tool was used and where was the image written?

**Finding:** AVML; `/tmp/evidence/memory.lime`

**Evidence interpretation:** Audit telemetry showed two AVML executions and the memory-image path. Memory acquisition preserved volatile evidence before final remediation.

<details>
<summary>View KQL query</summary>

```kusto
MeridianAudit_CL
| where isnotempty(EventTime_t)
| where EventTime_t >= datetime(2026-02-06 05:00:00)
| where Argv_s has_any ("avml", "lime", "LiME", "memdump", "memory", ".raw", ".lime", ".mem")
or comm_s has_any ("avml", "insmod", "dd")
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
| order by EventTime_t asc
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/13e49408-82b8-48d1-a9c9-7990f4ee0399" />

#### 9.2 What's Still Live

**Investigation question:** What manual action was still required after the automated response?

**Finding:** Manually terminate and remove the `health_check` backdoor

**Evidence interpretation:** The process snapshot still showed the backdoor after automated response activity. Blocking C2 did not remove the implant.

<details>
<summary>View KQL query</summary>

```kusto
MeridianSnapshot_CL
| project EventTime_t, ProcBeaconName_s, ProcBeaconExeLink_s,
ProcBeaconPid_s, ProcBeaconPPid_s, ProcBeaconUid_s
```
</details>

<img width="700" alt="image" src="https://github.com/user-attachments/assets/0fa4942c-2ead-471a-b737-6e4f81e6b212" />

## ⛓️ Attack Chain and ATT&CK Context

| Stage | Confirmed finding | MITRE ATT&CK mapping from report |
| --- | --- | --- |
| Reconnaissance | Nmap, curl, WhatWeb, Gobuster | T1595 — Active Scanning |
| Initial Access | `config_viewer.php` traversal; `/etc/passwd` and `database.conf` | T1190 — Exploit Public-Facing Application |
| Credential Access | Credentials in files / `svc_backup` access | T1552.001 — Credentials In Files |
| Valid Accounts | SSH as `svc_backup` | T1078 — Valid Accounts |
| Privilege Escalation | `/tmp/rootbash -p` | T1548.001 — Setuid and Setgid |
| Backdoor / possible persistence | `/opt/meridian/scripts/health_check` | Possible T1036.005 — Match Legitimate Name or Location |
| Command and Control | Blocked outbound attempts to `10.1.134.57:43212` | Protocol-specific mapping not established |
| Collection | Patient records | T1213 — Data from Information Repositories |
| Detection gap | `sysmon.service` removed by an automated sweep before intrusion | Not attributed to attacker activity |

*ATT&CK mappings are analytical associations, not proof of every technique. The backdoor naming/location mapping remains tentative. The pre-intrusion removal of `sysmon.service` is a defensive-response issue, not confirmed attacker defense evasion.*

## 💡 Lessons Learned

- **Detection is not remediation.** A tool can identify a suspicious artifact without removing it
- **Containment is not eradication.** Blocking outbound C2 connections did not terminate `health_check`
- **Cross-source correlation matters.** The investigation required pivots between web, authentication, audit, Defender, database, network and process-snapshot telemetry
- **Timeline context prevents false attribution.** Earlier defensive detections occurred before the confirmed intrusion and were assessed as baseline/setup activity
- **UID context matters.** Comparing real and effective UIDs exposed root-level execution from a non-root session
- **Preserve volatile evidence.** Memory acquisition before destructive remediation can retain evidence that would otherwise disappear

## 📎 Supporting Evidence

Each finding above includes its original KQL query and a screenshot of the relevant lab telemetry. The linked PDF provides the full investigation narrative. Screenshots document the lab results; they do not by themselves demonstrate actions outside the simulated environment.

## 🏁 Conclusion

The Meridian threat hunt provided hands-on practice using KQL to follow a multi-stage intrusion across several log sources. The investigation identified reconnaissance, a vulnerable web endpoint, sensitive file access, a compromised service account, privilege escalation, secondary persistence, a C2 destination, patient-data access, defensive gaps and remaining incident-response actions.

The central lesson was to evaluate **what each log proves**. A detection is not automatically a true positive, a blocked connection does not mean the process has terminated and a non-baseline file is not necessarily remediated simply because it was detected.

---


