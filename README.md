# Operation Meridian: Threat Hunt Report

**Single-host web application intrusion, healthcare estate**

|  |  |
|---|---|
| **Analyst** | Amine Mouammine |
| **Incident** | Single-host web application intrusion, healthcare portal (host ip-10-1-15-67 / 10.1.15.67) |
| **Telemetry** | Azure Log Analytics (LAW-HuntPractice), classic custom tables, KQL. All queries filter and order on EventTime_t, never TimeGenerated (ingestion time, 2026-08-30). |
| **Incident window** | 2026-02-06, 02:42:56 to 05:30 UTC (attacker activity 03:47 to 05:05). All times UTC. |
| **Scope** | Full kill chain reconstructed: reconnaissance through incident response (9 stages) |
| **Status** | NOT CONTAINED. Root implant health_check (PID 267155) was still running at 05:30. |

A PDF copy of this report is included: [Meridian_Threat_Hunt_Report.pdf]


---

## 1. Executive summary

An attacker at 10.1.134.57 compromised the Meridian healthcare portal in about 80 minutes. They fingerprinted the web server, abused an unscoped file parameter in config_viewer.php to read database.conf, and reused the credential to log in over SSH as the legitimate service account svc_backup. They escalated to root with a pre-staged SUID shell (/tmp/rootbash -p) and planted a second root implant disguised as a maintenance script (/opt/meridian/scripts/health_check). A patient data export from the attacker's address was also logged early, at 03:56:28, during the directory scan and before the traversal and SSH login.

The automated MeridianCare defence stack only partly worked. It blocked 73 outbound callbacks, killed the loud /tmp shell and reverted a tampered backup.conf. It also logged health_check as non-baseline but has no remediation rule for application directories, so the implant kept running as root. Earlier, the same stack generated false positives from its own installation and removed Sysmon, the host's own monitoring, which left the investigation without process-level telemetry.

**Bottom line:** Patient data (PHI/PII) should be treated as exposed, and the incident cannot be called contained until health_check is preserved, killed and deleted.

| Impact | Evidence |
|---|---|
| Patient records (PHI/PII) exposed | Defence log: "Patient data export from 10.1.134.57" at 03:56:28 (S7 Q1) |
| Root compromise of host | /tmp/rootbash -p at 04:40:15 with euid 0 (S4 Q1); health_check running with effective uid 0 (S5 Q1) |
| Persistence still active | health_check PID 267155, parent PID 1, running at 05:30 (S9 Q2) |
| Credential exposure | database.conf read in full (S2 Q2); svc_backup session established (S3 Q1) |

## 2. Attack path at a glance

| Stage | What happened | Time | Ref |
|---|---|---|---|
| Reconnaissance | Nmap, curl, WhatWeb, then gobuster (18,454 requests) | 03:47 to 03:55 | S1 Q1 |
| Initial access | Pre-scan probe of config_viewer.php; portal login 04:07:47; traversal in file parameter | 03:52 to 04:08 | S2 Q1 |
| Credential access | Read /etc/passwd, then database.conf | 04:07:59, 04:08:34 | S2 Q2 |
| Valid accounts | SSH login as svc_backup, 57 s after database.conf read | 04:09:31 | S3 Q1 |
| Failed escalation | sudo refused; root SSH fails x4 | 04:15, 04:44 to 04:46 | S3 Q2 |
| Privilege escalation | SUID shell /tmp/rootbash -p gives euid 0 | 04:40:15 | S4 Q1 |
| Persistence | health_check planted in app scripts folder, orphaned (PPid 1) | Running by 04:51 | S5 Q1, Q2 |
| Command and control | 73 blocked connections to 10.1.134.57:43212 | 04:48 to 05:02 | S6 Q1, Q2 |
| Collection | Patient data export logged (early, during the scan); backup.conf tampered | 03:56:28; 05:05:02 | S7 Q1, Q2 |
| Defence gaps | Bootstrap false positives (02:53); Sysmon removed (03:08) | 02:53, 03:08 | S8 Q1, Q2 |
| Response | Sweep kills rootbash, logs but ignores health_check; admin captures memory | 05:05 to 05:28 | S9 Q1, Q2 |

## 3. Consolidated timeline (UTC, 2026-02-06)

| Time | Event | Source |
|---|---|---|
| 02:53:31 | Burst of SSH-key, crontab and "new systemd service" detections, auto-reverted (false positive: stack's own install) | Defender DETECTION |
| 03:08:19 to 20 | First sweep removes "service: 60" and sysmon.service | Defender SWEEP |
| 03:47:26 | First attacker activity: Nmap Scripting Engine | Access |
| 03:52:09 / 03:52:29 | curl/8.18.0 starts; direct request to /config_viewer.php (302, no session) | Access |
| 03:54:54 / 03:55:05 | WhatWeb, then gobuster (18,454 requests) | Access |
| 03:56:28 | "Patient data export from 10.1.134.57" logged (WEB category), about a minute into the gobuster scan | Defender WEB |
| 04:07:47 | Portal login (POST /index.php 302, GET /dashboard.php 200) | Access |
| 04:07:59 | file=../../../etc/passwd (200, 3,077 B) | Access |
| 04:08:34 | file=database.conf (200, 1,231 B) | Access |
| 04:09:31 | SSH: Accepted password for svc_backup from 10.1.134.57 (port 39206) | Auth |
| 04:15:07 | sudo refused for svc_backup: "command not allowed" | Defender AUTH |
| 04:40:15 | /tmp/rootbash -p, auid 1001, euid 0 | Audit |
| 04:44 to 04:46 | Four failed root SSH logins (two from 10.1.15.67, two from 10.1.134.57) | Defender SSH |
| 04:48 to 05:02 | 73 blocked connections to 10.1.134.57:43212 | Defender NETWORK |
| 04:51 | health_check (PID 267155, PPid 1, euid 0) in process snapshot | Snapshot |
| 05:05:01 to 06 | Sweep kills rootbash, reverts backup.conf (05:05:02), logs health_check as non-baseline (05:05:06) | Defender SWEEP |
| 05:22:55 / 05:23:01 | Admin "ubuntu" logs in, sudo -i | Auth / Defender |
| 05:27:48 / 05:28:24 | AVML run twice, output /tmp/evidence/memory.lime | Audit |
| 05:30 | health_check still running as root | Snapshot |

## 4. Investigation findings

Each entry shows the finding, the analysis, the KQL and the matching screenshot. "Confirmed" means directly recorded in a log. "Inference" means reasoned from logs but not recorded in them.

### Section 1: The Opening Scan (Reconnaissance)

#### S1 Q1: The Recon Playbook

**Finding:** 4: Nmap Scripting Engine, curl/8.18.0, WhatWeb/0.6.3, gobuster/3.8.2

**MITRE ATT&CK:** T1595 Active Scanning  |  **Pyramid of Pain:** Tools

- Four distinct tools, in order of first appearance: Nmap Scripting Engine (03:47), curl/8.18.0 (03:52), WhatWeb/0.6.3 (03:54), gobuster/3.8.2 (03:55, 18,454 requests).
- Excluded as noise: curl/7.81.0 at 02:55 (one request before any attacker activity, likely the host itself since 7.81.0 ships with Ubuntu 22.04), the Apache internal dummy connection (3), and the blank user agent (4, Nmap probe traffic).
- Why it matters: scan, manual look, technology fingerprint, then exhaustive directory brute force is a methodical operator, not an opportunistic scanner.

**Confidence:** Confirmed (tools). Inference (curl/7.81.0 is the host).

```kql
MeridianAccess_CL
| where isnotempty(EventTime_t)
| where ClientIp_s == "10.1.134.57"
| summarize FirstSeen=min(EventTime_t), Requests=count() by UserAgent_s
| order by FirstSeen asc
```

![Recon tools grouped by user agent]!<img width="1091" height="389" alt="The Opening Scan" src="https://github.com/user-attachments/assets/cf93f303-8485-454e-997d-7f0e89adae7a" />


*Recon tools grouped by user agent*

### Section 2: Initial Access (Initial Access)

#### S2 Q1: The Traversal Point

**Finding:** config_viewer.php

**MITRE ATT&CK:** T1190 Exploit Public-Facing Application  |  **Pyramid of Pain:** Tools

- At 03:52:29, before the gobuster wordlist scan (03:55:05), the attacker requested /config_viewer.php on its own. It returned 302 because no session existed.
- Why it matters: a deliberate hit on one specific endpoint before the mass scan suggests the attacker already knew it existed, from earlier recon or leaked information.

**Confidence:** Confirmed.

```kql
MeridianAccess_CL
| where ClientIp_s == "10.1.134.57"
| where EventTime_t < datetime(2026-02-06 03:55:00)
| where RequestUri_s has "config"
| project EventTime_t, RequestUri_s, StatusCode_s, UserAgent_s
```

![Pre-scan request to config_viewer.php (302, curl/8.18.0)]<img width="1073" height="321" alt="Q1TheTraversal Point" src="https://github.com/user-attachments/assets/d37280dd-928b-475b-bea7-9ed2dab95c41" />


*Pre-scan request to config_viewer.php (302, curl/8.18.0)*

#### S2 Q2: What They Pulled

**Finding:** /etc/passwd, database.conf

**MITRE ATT&CK:** T1552.001 Credentials In Files  |  **Pyramid of Pain:** TTPs

- After authenticating to the portal (04:07:47), the unscoped file parameter returned two files with HTTP 200, in order: /etc/passwd (3,077 B) at 04:07:59, then database.conf (1,231 B) at 04:08:34.
- Why it matters: passwd supplies valid usernames, database.conf supplies credentials. The 35-second gap shows deliberate, sequential exploitation, not automated scanning.

**Confidence:** Confirmed. How the portal credentials were obtained is not recorded.

```kql
MeridianAccess_CL
| where ClientIp_s == "10.1.134.57"
| where RequestUri_s has "config_viewer" and RequestUri_s has "file="
| where StatusCode_s == "200"
| project EventTime_t, RequestUri_s, ResponseSize_s
```

![Two successful file reads via config_viewer.php]<img width="1091" height="327" alt="q2whatTheyPlulled" src="https://github.com/user-attachments/assets/48dd4b4e-2374-453a-896b-d0dd9e2323da" />


*Two successful file reads via config_viewer.php*

### Section 3: Borrowed Access (Credential Access)

#### S3 Q1: Borrowed Access

**Finding:** svc_backup

**MITRE ATT&CK:** T1078 Valid Accounts  |  **Pyramid of Pain:** Network Artifacts

- SSH login accepted for svc_backup from 10.1.134.57 at 04:09:31 (sshd PID 263575, source port 39206), 57 seconds after database.conf was read. No account was created; a provisioned service account was reused.
- Why it matters: the sub-minute gap is consistent with credential reuse, not brute force. The logs do not record which credential was used.

**Confidence:** Confirmed (login). Inference (credential came from database.conf).

```kql
MeridianAuth_CL
| where isnotempty(EventTime_t)
| where EventTime_t between (datetime(2026-02-06 04:08:34) .. datetime(2026-02-06 04:12:00))
| where RawMessage_s has "Accepted password"
| order by EventTime_t asc
```

![Accepted password for svc_backup from 10.1.134.57]<img width="1094" height="292" alt="q3Borrowed Access" src="https://github.com/user-attachments/assets/6e55cea8-e5de-4b6d-adb7-c3ddbd3fc898" />


*Accepted password for svc_backup from 10.1.134.57*

#### S3 Q2: The Road Not Taken

**Finding:** sudo -l: svc_backup has no sudo rights (command not allowed). SSH login as root: authentication failure (wrong password).

**MITRE ATT&CK:** T1078 Valid Accounts  |  **Pyramid of Pain:** TTPs

- sudo at 04:15:07: svc_backup was refused with "command not allowed" (COMMAND=list, i.e. sudo -l). The account has no sudo rights. This happened before the SUID shell.
- Root SSH at 04:44 to 04:46: four failed logins, two from localhost (10.1.15.67) and two from the attacker IP (10.1.134.57). The logs show authentication failure, not the reason.
- Why it matters: these show where defences held. Had sudo or root SSH been open, the SUID shell would not have been needed.

**Confidence:** Confirmed. The two localhost attempts may be the attacker testing from the host or host-side noise; attribution is not recorded.

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t) | where EventCategory_s == "AUTH"
| project EventTime_t, RawMessage_s

MeridianDefender_CL
| where isnotempty(EventTime_t) | where EventCategory_s == "SSH"
| where RawMessage_s has "Failed" | project EventTime_t, RawMessage_s
```

![sudo refusal for svc_backup at 04:15:07 (AUTH category)]<img width="1105" height="348" alt="s3Q2The Road Not Taken" src="https://github.com/user-attachments/assets/43fa0bea-8c45-4fc8-b4d5-b4a00eb11796" />


*sudo refusal for svc_backup at 04:15:07 (AUTH category)*

![Four failed root SSH logins, 04:44 to 04:46]<img width="1094" height="341" alt="s3q2the road not taken2" src="https://github.com/user-attachments/assets/55ff9db8-e350-440e-95a0-1081d2ef692d" />


*Four failed root SSH logins, 04:44 to 04:46*

### Section 4: The Planted Root Shell (Privilege Escalation)

#### S4 Q1: The Planted Root Shell

**Finding:** /tmp/rootbash -p

**MITRE ATT&CK:** T1548.001 Setuid and Setgid  |  **Pyramid of Pain:** TTPs

- /tmp/rootbash -p executed at 04:40:15 by auid 1001 (svc_backup) with euid 0 (mode 0104755, root-owned). The -p flag stops bash from dropping the effective UID.
- Why it matters: this is the privilege-escalation pivot. How the binary reached disk is not captured (Sysmon was removed earlier, see S8 Q2).

**Confidence:** Confirmed (execution). Staging method unknown.

```kql
MeridianAudit_CL
| where Types_s has "EXECVE"
| where Argv_s has "rootbash"
| project EventTime_t, comm_s, exe_s, Argv_s, auid_s, euid_s
```

![rootbash execution: auid 1001, euid 0]<img width="1091" height="242" alt="s4Q1The Planted Root Shel" src="https://github.com/user-attachments/assets/7f46a168-1678-4965-89c9-897bc960ed3d" />


*rootbash execution: auid 1001, euid 0*

### Section 5: Persistence (Persistence)

#### S5 Q1: The Second Foothold

**Finding:** /opt/meridian/scripts/health_check

**MITRE ATT&CK:** T1036.005 Match Legitimate Name or Location  |  **Pyramid of Pain:** TTPs

- health_check ran as PID 267155 with parent PID 1 (orphaned), real UID 1001 (svc_backup) and effective UID 0, inside the application's own scripts folder.
- Why it matters: unlike the obvious /tmp shell, the name and location read as routine maintenance and blend into the legitimate application structure.

**Confidence:** Confirmed.

```kql
MeridianSnapshot_CL
| where isnotempty(ProcBeaconExeLink_s)
| project ProcBeaconName_s, ProcBeaconExeLink_s, ProcBeaconUid_s, ProcBeaconPPid_s
```

![health_check process record: PID 267155, PPid 1, exe link to /opt/meridian/scripts/health_check]<img width="1117" height="239" alt="s5q1" src="https://github.com/user-attachments/assets/aa6db001-f3e5-438a-85e8-591e36bd6e65" />



*health_check process record: PID 267155, PPid 1, exe link to /opt/meridian/scripts/health_check*

#### S5 Q2: Why It Survived

**Finding:** Non-baseline scripts/ check is log-only. health_check is not in a cleanup category (temp dirs, SUID in watched paths, services, cron, SSH keys).

**MITRE ATT&CK:** T1564.001 Hidden Files and Directories  |  **Pyramid of Pain:** TTPs

- The 05:05:06 sweep logged "Non-baseline file in scripts/: health_check" but only auto-remediates five categories: SSH keys, crontabs, temp directories, SUID files in watched paths, and systemd services. A plain script in an application directory matches none, so it is logged and never acted on.
- The same sweep did kill /tmp/rootbash, because it sits in a temp directory.
- Why it matters: a detection-versus-remediation gap. The tool saw the implant and had no rule to remove it. The log line itself is shown in the S9 Q2 screenshot below.

**Confidence:** Confirmed.

```kql
MeridianDefender_CL
| where EventCategory_s == "SWEEP"
| where RawMessage_s has "health_check"
| project EventTime_t, RawMessage_s
```

*Non-baseline scripts/ check is log-only; health_check isn't in a cleanup category (temp dirs, SUID in watched paths, services, cron, SSH keys)*
<img width="1081" height="215" alt="s5q2 1" src="https://github.com/user-attachments/assets/9a24a3bd-045d-4d7b-a9bd-2ff20a09189a" />


### Section 6: Calling Home (Command and Control)

#### S6 Q1: Calling Home

**Finding:** 10.1.134.57:43212. No, the block only stops egress; health_check is still running as root and the file was never removed.

**MITRE ATT&CK:** T1071 Application Layer Protocol  |  **Pyramid of Pain:** Network Artifacts

- 73 blocked connection attempts to 10.1.134.57 on a single port, 43212, between 04:48 and 05:02, a beacon on a schedule.
- The block stopped the callback but never killed the process. Why it matters: blocking traffic is not neutralisation. The process keeps retrying and would succeed if the block were lifted.

**Confidence:** Confirmed (blocks). Inference (source process is health_check; the firewall events name the host, not the process).

```kql
MeridianDefender_CL
| where EventCategory_s == "NETWORK"
| where DestIp_s == "10.1.134.57"
| summarize count() by DestPort_s
```

![73 blocked events to 10.1.134.57, all on port 43212]<img width="1080" height="244" alt="s6q1" src="https://github.com/user-attachments/assets/f9b36407-896a-4f92-a69d-51f2f106d9cc" />


*73 blocked events to 10.1.134.57, all on port 43212*

#### S6 Q2: What the Block Proves

**Finding:** Proves: health_check was live, running as root and repeatedly beaconing or attempting exfil to attacker-controlled 10.1.134.57:43212, and the egress block worked for those attempts. Does not prove: that the threat was neutralised (process still running, file not removed), that no data left before the block or over other channels (SSH/SFTP, HTTP), or what data it tried to send.

**MITRE ATT&CK:** T1071 Application Layer Protocol  |  **Pyramid of Pain:** Network Artifacts

- Proves: outbound TCP connections to 10.1.134.57:43212 were intercepted and dropped 73 times, so the C2 channel is severed at the network layer.
- Does not prove: the process is stopped, the code is removed, or the host is contained. PID 267155 was still running at 05:30 (see S5 Q1 screenshot) and would resume the moment the block is lifted.
- Why it matters: this is the most common analyst over-claim in network defence. A firewall rule is not the same as killing the process that generates the traffic.

**Confidence:** Confirmed.

```kql
MeridianSnapshot_CL
| where isnotempty(EventTime_t)
| project EventTime_t, ProcBeaconExeLink_s, ProcBeaconPid_s
```

![Blocked exfil events from 10.1.15.67 to 10.1.134.57:43212, roughly two minutes apart (exploratory query)]<img width="1081" height="288" alt="s6q2" src="https://github.com/user-attachments/assets/422d5445-d4d6-43d9-97a5-79d1b3bffb7e" />


*Blocked exfil events from 10.1.15.67 to 10.1.134.57:43212, roughly two minutes apart (exploratory query)*


### Section 7: Collection (Collection)

#### S7 Q1: What Left the Database

**Finding:** Patient records (PHI/PII) from the patients table in the meridian_patients database

**MITRE ATT&CK:** T1213 Data from Information Repositories  |  **Pyramid of Pain:** TTPs

- The defence log recorded "Patient data export from 10.1.134.57" (WEB category) at 03:56:28. On a healthcare portal, the patients table is the highest-value target.
- Timing: the export is logged about 1 minute after gobuster started (03:55:05), roughly 11 minutes before the portal login (04:07:47) and the file traversal, and 13 minutes before the SSH login. It is an early event, not the end of the chain. The logs do not show how it was triggered or whether it needed a session, which makes the export function's access control worth checking.
- The second row in the screenshot has an empty EventTime_t. It is a leftover row from the earlier failed ingestion pass described in the hunt brief, so it is excluded (add | where isnotempty(EventTime_t) to drop it).
- A separate "DB: Full patient table query" entry at 02:58 is a red herring, 49 minutes before any attacker activity.
- Why it matters: this is the confirmed impact. The exact export queries and volume are not in the evidence.

**Confidence:** Confirmed (event and time logged). Volume, trigger and method unknown.

```kql
MeridianDefender_CL
| where EventCategory_s == "WEB"
| where RawMessage_s has "export"
| project EventTime_t, RawMessage_s
```

![Patient data export from 10.1.134.57 at 03:56:28; second row has no EventTime_t (excluded)]<img width="1089" height="305" alt="s7q1" src="https://github.com/user-attachments/assets/680a87ef-107d-4065-8098-f5ee23d081c5" />


*Patient data export from 10.1.134.57 at 03:56:28; second row has no EventTime_t (excluded)*

#### S7 Q2: The Tampered File

**Finding:** backup.conf

**MITRE ATT&CK:** T1565.001 Stored Data Manipulation  |  **Pyramid of Pain:** TTPs

- At 05:05:02 the final sweep logged "backup.conf tampered -- reverting" and restored the file.
- Why it matters: backup configuration is a plausible persistence route through the estate's own jobs. Who modified it, and how, is not in the logs.

**Confidence:** Confirmed (tamper and revert). Actor is an inference only.

```kql
MeridianDefender_CL
| where EventCategory_s == "SWEEP"
| where EventTime_t > datetime(2026-02-06 05:04:00)
| where RawMessage_s has "tampered"
| project EventTime_t, RawMessage_s
```

![backup.conf tampered, reverting (05:05:02)]<img width="1097" height="303" alt="s7q2" src="https://github.com/user-attachments/assets/ecc2a75e-7778-4d31-8fdb-f7d1ceb6ea9e" />


*backup.conf tampered, reverting (05:05:02)*

### Section 8: Defence Evasion and Detection Gaps (Defense Evasion)

#### S8 Q1: Signal or Setup Noise

**Finding:** False positive

**MITRE ATT&CK:** T1036 Masquerading  |  **Pyramid of Pain:** TTPs

- At 02:53:31 a burst of SSH-key, crontab and new-systemd-service detections, each auto-reverted within a second, fires about 54 minutes before the first attacker activity (03:47:26). It matches the defence stack's own installation, not the intrusion.
- The sweep also reverts SSH keys, crontabs and temp directories every cycle, whether or not anything changed.
- Why it matters: treating installation artefacts as attack indicators is a common triage error.

**Confidence:** Confirmed (timing). Inference (cause is the install).

```kql
MeridianDefender_CL
| where EventCategory_s == "DETECTION"
| where EventTime_t < datetime(2026-02-06 03:00:00)
| project EventTime_t, RawMessage_s
```

![Bootstrap detection burst at 02:53:31]<img width="806" height="386" alt="s8q1" src="https://github.com/user-attachments/assets/a6371935-3c03-49b8-955d-ff2b532c526d" />


*Bootstrap detection burst at 02:53:31*

#### S8 Q2: Collateral Damage

**Finding:** sysmon.service (Sysmon), removed by the first sweep at 03:08 as a false positive. The host had no Sysmon process, network or file telemetry for the rest of the incident, leaving evidentiary gaps (how the first backdoor was staged, exact credentials, exact export queries) that had to be rebuilt from auditd, auth.log and web logs.

**MITRE ATT&CK:** T1562.001 Impair Defenses: Disable or Modify Tools  |  **Pyramid of Pain:** TTPs

- At 03:08:19 to 20 the first sweep removed "service: 60" and sysmon.service as non-baseline services. Sysmon was the host's own monitoring, not attacker persistence.
- Why it matters: the sweep's over-zealous remediation created the biggest detection gap in the incident, about 40 minutes before the intrusion began. What "service: 60" was is not identified in the logs.

**Confidence:** Confirmed (removal). Inference (telemetry loss; no Sysmon table exists in the workspace).

```kql
MeridianDefender_CL
| where EventCategory_s == "SWEEP"
| where RawMessage_s has "Removed service"
| where EventTime_t < datetime(2026-02-06 03:10:00)
| project EventTime_t, RawMessage_s
```

![Services removed by the first sweep: "60" and sysmon.service]<img width="1065" height="321" alt="s8q2" src="https://github.com/user-attachments/assets/311a4480-d06d-4fef-af7a-eaa4abe05a0b" />


*Services removed by the first sweep: "60" and sysmon.service*

### Section 9: Response (Incident Response)

#### S9 Q1: Capturing the Evidence

**Finding:** AVML (/tmp/avml), run twice, output to /tmp/evidence/memory.lime

**MITRE ATT&CK:** T1005 Data from Local System  |  **Pyramid of Pain:** Tools

- The returning admin (ubuntu, public key from 10.0.2.139, sudo -i at 05:23:01) ran /tmp/avml at 05:27:48 and again at 05:28:24, both writing /tmp/evidence/memory.lime. AVML is Microsoft's open-source Linux memory-acquisition tool.
- Why it matters: capturing volatile state before remediation is the correct order of operations. Both runs used one path, so the second probably overwrote the first (inference), and /tmp is disposable, so the image should be copied off the host and hashed.

**Confidence:** Confirmed. Inference (second run overwrote the first).

```kql
MeridianAudit_CL
| where Types_s has "EXECVE"
| where EventTime_t > datetime(2026-02-06 05:25:00)
| where Argv_s has "avml" or comm_s has "avml"
| project EventTime_t, Argv_s, exe_s
```

![AVML executed at 05:27:48 and 05:28:24]<img width="1088" height="287" alt="s9q1" src="https://github.com/user-attachments/assets/a7aea8ac-35ab-4c5a-9bfb-8d324f8362ca" />


*AVML executed at 05:27:48 and 05:28:24*

#### S9 Q2: What's Still Live

**Finding:** Manually terminate health_check (PID 267155) and delete /opt/meridian/scripts/health_check

**MITRE ATT&CK:** T1036.005 Match Legitimate Name or Location  |  **Pyramid of Pain:** TTPs

- health_check was the one artefact nothing touched: the sweep killed rootbash and reverted backup.conf, the admin captured memory, and the network block stopped its traffic, but health_check was only ever flagged ("Non-baseline file in scripts/: health_check" at 05:05:06), never remediated. It was still running as root at 05:30.
- The screenshot also shows why EventTime_t matters: TimeGenerated is 8/30/2026 (load date) while EventTime_t is the real 2/6/2026 time.
- Why it matters: the incident is not contained until someone manually preserves a copy, kills PID 267155 and deletes the file.

**Confidence:** Confirmed.

```kql
MeridianDefender_CL
| where isnotempty(EventTime_t)
| where RawMessage_s has "health_check"
| project EventTime_t, TimeGenerated, EventCategory_s, RawMessage_s
| order by EventTime_t asc
```

![Sweep logged health_check only. TimeGenerated shows the 2026-08-30 load date; EventTime_t is the real time]<img width="1096" height="295" alt="s9q2" src="https://github.com/user-attachments/assets/dcddc132-5eea-4fb8-96d0-860040495a09" />


*Sweep logged health_check only. TimeGenerated shows the 2026-08-30 load date; EventTime_t is the real time*

## 5. Detection and response assessment

| Area | Worked | Failed or missing |
|---|---|---|
| Network egress | Blocked all 73 callbacks to 10.1.134.57:43212 | Block did not stop the process; would succeed if lifted |
| Automated sweep | Killed /tmp/rootbash; reverted backup.conf | Logged health_check but had no rule to remove it; removed Sysmon as a false positive |
| Authentication controls | sudo denied svc_backup; root SSH failed 4 times | svc_backup password still let the attacker in; no alert on login from a new IP |
| Application | Session required for config_viewer.php (302 without session) | file parameter unscoped; allowed traversal to /etc and config files |
| Forensics | AVML captured memory before remediation | Image left in /tmp; Sysmon gap; no staging evidence |

**Note on the attacker address:** 10.1.134.57 is an RFC 1918 private address. In a real estate this would indicate an attacker already inside the network, or a compromised internal host used as a pivot, which widens scoping beyond this one server.

## 6. Case File

### Indicators of compromise

| Indicator | Ref | Note |
|---|---|---|
| 4 recon tools: Nmap Scripting Engine, curl/8.18.0, WhatWeb/0.6.3, gobuster/3.8.2 | S1 Q1 | User agents from 10.1.134.57 |
| config_viewer.php | S2 Q1 | Traversal endpoint (/config_viewer.php?file=) |
| /etc/passwd, database.conf | S2 Q2 | Files read through the file parameter |
| svc_backup (pivot) | S3 Q1 | Abused service account; sshd PID 263575, source port 39206 |
| sudo -l refused; root SSH failed (pivot) | S3 Q2 | Failed escalation paths |
| /tmp/rootbash -p | S4 Q1 | SUID bash (mode 0104755), killed by sweep |
| /opt/meridian/scripts/health_check | S5 Q1 | Root implant, PID 267155, PPid 1, running at 05:30 |
| Patient records (PHI/PII), patients table, meridian_patients | S7 Q1 | Data at risk; export logged 03:56:28 |
| backup.conf | S7 Q2 | Tampered, reverted by sweep |
| AVML (/tmp/avml) to /tmp/evidence/memory.lime | S9 Q1 | Responder memory capture (evidence to preserve, not an attacker IOC) |
| 10.1.134.57 and 10.1.134.57:43212 | S1 to S6 | Attacker IP; C2 / exfil destination (blocked). Added from logs |

### MITRE ATT&CK techniques (13)

| Technique | Ref | Pyramid of Pain |
|---|---|---|
| T1595 Active Scanning | S1 Q1 | Tools |
| T1190 Exploit Public-Facing Application | S2 Q1 | Tools |
| T1552.001 Credentials In Files | S2 Q2 | TTPs |
| T1078 Valid Accounts | S3 Q1, S3 Q2 | Network Artifacts, TTPs |
| T1548.001 Setuid and Setgid | S4 Q1 | TTPs |
| T1036.005 Match Legitimate Name or Location | S5 Q1, S9 Q2 | TTPs |
| T1564.001 Hidden Files and Directories | S5 Q2 | TTPs |
| T1071 Application Layer Protocol | S6 Q1, S6 Q2 | Network Artifacts |
| T1213 Data from Information Repositories | S7 Q1 | TTPs |
| T1565.001 Stored Data Manipulation | S7 Q2 | TTPs |
| T1036 Masquerading | S8 Q1 | TTPs |
| T1562.001 Impair Defenses: Disable or Modify Tools | S8 Q2 | TTPs |
| T1005 Data from Local System | S9 Q1 | Tools |

## 7. Recommendations

**Immediate (containment)**

- Preserve a copy of health_check and the memory image, then kill PID 267155 and delete /opt/meridian/scripts/health_check.
- Terminate any open svc_backup SSH session; rotate its password and all credentials in database.conf, including the MySQL account.
- Keep the egress block on 10.1.134.57:43212 until host rebuild or verified clean; block 10.1.134.57 entirely.
- Copy /tmp/evidence/memory.lime off the host, hash it, and record chain of custody.
- Treat patient data as exposed; start breach assessment and notification review.

**Short term (1 to 2 weeks)**

- Review the patient export function: it was logged 11 minutes before the portal login, so confirm it requires authentication and logs the requester and query.
- Fix config_viewer.php: allow-list permitted files, reject path separators and "..", or remove it from the public site.
- Hunt for the same patterns elsewhere: other svc_backup, webadmin and dbadmin logins, SUID files outside watched paths, other files in /opt/meridian/scripts.
- Require key-based SSH for service accounts, restrict svc_backup to the backup host, and disable password login.
- Restore Sysmon and exclude it from the sweep baseline.

**Long term**

- Extend the sweep to quarantine, not just log, non-baseline files in application directories; alert on SUID creation anywhere.
- Stop storing reusable credentials in web-readable config files; use a secrets manager.
- Add detections: repeated sequential file= reads, a service-account SSH login within minutes of a config read, processes with PPid 1 and a uid/euid mismatch.
- Whitelist the defence stack's own install so bootstrap noise is not triaged as an incident.

## 8. Evidence gaps and confidence

| Gap | Status |
|---|---|
| Exact credentials used (portal and SSH) | Not recorded. Credential reuse from database.conf is inferred from the 57-second gap. |
| Exact export queries and volume | Not recorded; only the "Patient data export" event exists. |
| How the 03:56:28 export was triggered, and whether it needed a session | Not recorded; it precedes the portal login at 04:07:47. |
| How /tmp/rootbash reached disk | Not captured; Sysmon was removed at 03:08. |
| Who tampered with backup.conf | Not recorded; reverted by the sweep. |
| What "service: 60" was | Unidentified; removed at 03:08:19. |
| Whether data left before 04:48 or via SSH/SFTP/HTTP | Not provable from available logs. |

**Inferences in this report:** curl/7.81.0 is the host; telemetry loss from the Sysmon removal; the svc_backup credential came from database.conf; beacons originate from health_check; AVML run two overwrote run one.
