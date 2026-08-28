```markdown
# Boogeyman 3 — Endpoint Compromise, Lateral Movement & Domain Compromise

## Lab Objective

This investigation focuses on reconstructing a multi-stage enterprise compromise in which an attacker progresses from an initial phishing-based endpoint compromise to persistence, privilege escalation, credential theft, lateral movement, domain compromise, and ransomware deployment.

The objective is to investigate the incident from a defensive SOC perspective using centralized endpoint telemetry stored in an Elastic Stack environment.

Rather than investigating each suspicious event independently, the analysis follows the attacker's activity across multiple systems and correlates process execution, command-line activity, persistence mechanisms, network connections, credential-access activity, remote-share access, lateral movement, and domain-level attacks.

The investigation demonstrates how a SOC analyst can use centralized Windows telemetry to reconstruct an intrusion across multiple hosts and identify the progression from initial access to attempted ransomware deployment.

---

## Scenario Overview

Following previous incidents attributed to the Boogeyman threat group, Quick Logistics LLC outsourced its Security Operations Center to a managed security service provider.

Despite the additional security monitoring, the threat actor maintained access to the environment and eventually attempted to expand the compromise.

An employee's previously compromised account was used as an entry point to target the company's CEO.

The CEO received a suspicious email containing an attachment. Although the message appeared questionable, the attachment was opened.

The document did not immediately display obvious malicious behavior, leading the victim to report the email to the security team.

Initial endpoint investigation revealed the attachment in the victim's Downloads directory and identified an additional file contained within an ISO payload.

The security team then provided centralized endpoint telemetry through an Elastic Stack environment for deeper investigation.

The investigation focused on reconstructing the complete attack chain, including:

- Initial payload execution
- File implantation
- Malicious file execution
- Scheduled-task persistence
- C2 communication
- UAC bypass
- Credential dumping
- Credential reuse
- Remote-share enumeration
- Lateral movement
- Secondary-host compromise
- Additional credential dumping
- Domain Controller compromise
- DCSync activity
- Ransomware staging

---

## Tools & Data Sources

- Elastic Stack
- Kibana
- Windows Event Logs
- Sysmon telemetry
- Process creation events
- Command-line telemetry
- Network connection events
- Scheduled-task telemetry
- Authentication events
- File and share-access events
- PowerShell / command execution telemetry
- GitHub infrastructure investigation

---

## Investigation Walkthrough

### 1. Establishing the Investigation Scope

The investigation began in Kibana using the available centralized Windows telemetry.

The initial investigation window was restricted to the period in which the security team believed the compromise occurred.

Instead of searching immediately for individual indicators, the investigation first reviewed process and endpoint activity associated with the CEO's workstation.

This provided an initial baseline from which suspicious execution could be identified.

The investigation focused heavily on fields such as:

```
host.name
process.name
process.pid
process.parent.pid
process.command_line
user.name
event.code
event.action
```

These fields allowed process execution events to be correlated across the attack chain.

---

## Initial Payload Execution

### 2. Identifying the Stage 1 Process

Process creation telemetry was searched to identify the execution of the initial malicious payload.

The investigation focused on unusual processes associated with the victim's workstation and correlated their:

- Process name
- PID
- Parent PID
- Command line
- Executable path
- User context

A process-creation search was used to narrow the investigation to suspicious execution events.

Conceptually, the investigation followed:

```
Victim Workstation
       ↓
Initial Payload
       ↓
Process Creation Event
       ↓
PID
       ↓
Parent Process
       ↓
Command Line
```

The PID of the process responsible for executing the initial stage was then used as a pivot for subsequent searches.

---

### 3. Stage 1 File Implantation

The stage 1 payload attempted to place another file on the workstation.

The process command-line telemetry was examined for file-copy or file-creation activity originating from the malicious process.

The investigation searched command-line events associated with the identified process and reviewed suspicious file-operation parameters.

Rather than relying on the filename alone, the command line was examined to determine:

- Source file
- Destination path
- Execution context
- Parent process
- Process responsible for the operation

This established that the initial payload was not the final executable used during the compromise.

The attack chain had progressed into a second execution stage:

```
Stage 1 Payload
      ↓
File Implantation
      ↓
New Location
      ↓
Implanted File
```

---

## Implanted File Execution

### 4. Execution of the Implanted File

The implanted file was subsequently executed by the stage 1 payload.

The corresponding process-creation telemetry was searched using the previously identified process and file artifacts.

The command-line value associated with this execution was examined to determine exactly how the implanted file was launched.

This provided an important process relationship between the initial payload and the implanted executable.

The resulting execution chain was reconstructed as:

```
Initial Payload
      │
      └──► Implant File
               │
               └──► Execution
```

This parent-child relationship was then used to investigate the next stages of the compromise.

---

## Persistence

### 5. Scheduled Task Creation

The investigation identified evidence that the attacker established persistence after executing the implanted payload.

Scheduled-task activity was searched within the endpoint telemetry.

Relevant process and command-line events were reviewed for task-creation operations.

The investigation correlated:

```
Malicious Process
      ↓
Scheduled Task Creation
      ↓
Persistence
      ↓
Future Execution
```

The task name and associated creation activity were extracted from the telemetry.

This established that the attacker attempted to maintain access beyond the initial execution event.

---

## Command & Control

### 6. Identifying the C2 Connection

Network telemetry was then correlated with the execution of the implanted file.

The investigation searched for network connection events associated with the suspicious process.

Relevant fields included:

```
process.name
process.pid
destination.ip
destination.port
source.ip
network.transport
```

The suspicious process was found to initiate an outbound connection to external infrastructure.

The destination IP and port were extracted as network-level indicators of compromise.

This established the transition from local execution to remote attacker-controlled communication:

```
Implanted File
      ↓
Execution
      ↓
Network Connection
      ↓
External C2
```

---

## Privilege Escalation

### 7. UAC Bypass Investigation

After establishing access, the attacker determined that the compromised account had local administrator privileges.

The investigation then searched for processes commonly associated with User Account Control bypass techniques.

Process creation and command-line telemetry were correlated around the period immediately following the initial compromise.

The suspicious process was identified through its execution behavior and relationship with the malicious command.

This demonstrated a privilege-escalation stage in which the attacker attempted to obtain elevated execution without relying on a conventional credential prompt.

The attack progression therefore became:

```
Initial Access
      ↓
Payload Execution
      ↓
Persistence
      ↓
C2
      ↓
Privilege Escalation
```

---

## Credential Access

### 8. Credential Dumping Tool Acquisition

With elevated privileges available, the attacker attempted to obtain credentials from the compromised workstation.

The investigation searched process command lines and network activity for evidence of downloading credential-access tooling.

A remote GitHub repository was identified as the source used to retrieve the credential-dumping tool.

The repository URL was treated as an external infrastructure IOC.

This stage demonstrated an important SOC correlation technique:

```
Privilege Escalation
       ↓
Tool Download
       ↓
Credential Dumping
       ↓
Credential Material
```

The tool itself was not treated as the primary finding; the focus was on the attacker behavior of acquiring and executing credential-access tooling after obtaining elevated privileges.

---

### 9. Extracted Credential Reuse

Following the credential-dumping activity, the investigation searched authentication events for evidence that newly obtained credentials were being used against another machine.

Authentication telemetry was correlated with:

- Username
- Source workstation
- Destination workstation
- Authentication type
- Logon events

The investigation identified a credential pair that was subsequently used to access another system.

This was the first clear indication that the attacker had expanded the compromise beyond the original workstation.

---

## Lateral Movement

### 10. Remote Share Enumeration

Using the newly acquired credentials, the attacker attempted to enumerate accessible network shares.

File-share and network-access telemetry was reviewed to identify remote resources accessed by the compromised account.

The investigation focused on remote share activity rather than simply searching for generic file access.

The resulting activity revealed a file accessed from a remote share.

This file became the next pivot because its contents were subsequently used during the attack.

The investigation therefore reconstructed:

```
Compromised Host
      ↓
Stolen Credentials
      ↓
Remote Share Enumeration
      ↓
Remote File Access
      ↓
Credential / Configuration Artifact
```

---

### 11. Credentials Discovered from Remote File

The contents of the accessed remote file revealed another set of credentials.

These credentials were treated as a new pivot rather than assuming that the previously compromised account would be sufficient for further movement.

The newly discovered credentials were then correlated against subsequent authentication events.

This demonstrated a common lateral-movement technique in which attackers search accessible shared resources for credentials that can provide access to additional systems.

---

## Attacker Infrastructure Identification

### 12. Identifying the Attacker's Lab Host

Authentication and network telemetry were reviewed to identify the source system associated with the lateral-movement attempts.

The hostname of the system used by the attacker during the movement phase was extracted from the available telemetry.

This provided additional infrastructure context and allowed activity originating from the attacker's system to be separated from normal enterprise traffic.

The investigation therefore distinguished between:

```
Victim Host
      ↓
Compromised Enterprise Host
      ↓
Lateral Movement
      ↑
Attacker-Controlled Host
```

---

## Secondary Host Compromise

### 13. Identifying Execution on the Second Host

After the attacker used the newly discovered credentials for lateral movement, process telemetry from the second compromised machine was examined.

The malicious command executed during the movement operation was correlated with the resulting process-creation event on the destination system.

The parent process was identified from the process hierarchy.

This was important because the same command can produce different forensic interpretations depending on the process responsible for launching it.

The investigation therefore reconstructed:

```
First Compromised Host
        ↓
Remote Execution
        ↓
Second Host
        ↓
Parent Process
        ↓
Malicious Command
```

---

## Secondary Credential Dumping

### 14. Credential Dumping on the Second Host

After obtaining execution on the second workstation, the attacker repeated credential-access activity.

Process and command-line telemetry was searched for credential-dumping behavior on the newly compromised host.

The resulting credential material was correlated with subsequent activity to determine whether it was used for additional access.

This confirmed that the attack was not limited to the original workstation and that credential harvesting continued as the attacker moved deeper into the environment.

---

## Domain Controller Compromise

### 15. Access to the Domain Controller

The investigation then followed authentication and lateral-movement events associated with the domain environment.

Evidence indicated that the attacker eventually obtained access to the domain controller.

At this point, the investigation shifted from workstation-level compromise to domain-level credential-access activity.

This represented a major escalation in impact:

```
Workstation Compromise
        ↓
Credential Theft
        ↓
Lateral Movement
        ↓
Second Host
        ↓
Additional Credentials
        ↓
Domain Controller
```

---

## DCSync Investigation

### 16. Domain Credential Replication Abuse

After gaining access to the domain controller, the attacker attempted to obtain domain credential hashes using a DCSync technique.

The investigation searched authentication and directory-service telemetry for evidence of replication requests associated with credential extraction.

The objective was to determine which domain account was targeted in addition to the administrator account.

The activity was treated as a high-impact domain compromise indicator because successful DCSync abuse can allow an attacker to obtain password-hash material without directly accessing the domain database in the conventional manner.

The investigation therefore identified:

```
Domain Controller Access
        ↓
Replication Abuse
        ↓
DCSync Activity
        ↓
Domain Credential Hashes
```

---

## Ransomware Staging

### 17. Ransomware Payload Download

After credential dumping and domain-level compromise, the investigation identified another remote file-download operation associated with ransomware deployment.

Network and process telemetry were correlated to determine the remote source used to retrieve the ransomware binary.

The download URL was extracted as an IOC and linked to the final stage of the observed intrusion.

This demonstrated that the attack had progressed from credential compromise into preparation for destructive activity.

The final observed stage was:

```
Credential Theft
      ↓
Domain Compromise
      ↓
DCSync
      ↓
Remote Payload Download
      ↓
Ransomware Execution Preparation
```

---

## Complete Attack Chain

The combined telemetry allowed the incident to be reconstructed as a complete multi-stage intrusion:

```
Phishing Attachment
        │
        ▼
Stage 1 Payload Execution
        │
        ▼
File Implantation
        │
        ▼
Implanted File Execution
        │
        ├──────────────► Scheduled Task Persistence
        │
        ▼
C2 Communication
        │
        ▼
UAC Bypass / Privilege Escalation
        │
        ▼
Credential Dumping Tool Download
        │
        ▼
Credential Theft
        │
        ▼
Credential Reuse
        │
        ▼
Remote Share Enumeration
        │
        ▼
Credential Discovery
        │
        ▼
Lateral Movement
        │
        ▼
Second Host Compromise
        │
        ▼
Additional Credential Dumping
        │
        ▼
Domain Controller Access
        │
        ▼
DCSync
        │
        ▼
Ransomware Payload Download
```

---

## Investigation Methodology

The investigation followed a **pivot-based SOC methodology**.

Each confirmed artifact was used to locate the next stage of attacker activity.

The primary pivots were:

```
Process
  ↓
PID
  ↓
Command Line
  ↓
File Path
  ↓
Parent Process
  ↓
Scheduled Task
  ↓
Network Connection
  ↓
C2
  ↓
Credential Access
  ↓
Username
  ↓
Authentication Event
  ↓
Destination Host
  ↓
Remote Share
  ↓
New Credentials
  ↓
Lateral Movement
  ↓
Domain Controller
  ↓
DCSync
  ↓
Ransomware Download
```

This approach allowed the investigation to move from a single suspicious endpoint event into a broader enterprise-wide compromise.

---

## SOC Investigation Perspective

One of the most important aspects of this investigation was the correlation of events across multiple hosts.

A single suspicious process execution would not have revealed the full impact of the intrusion.

The incident became significantly clearer when the following evidence was correlated:

| Evidence                    | Investigation Value                               |
| --------------------------- | ------------------------------------------------- |
| Process Creation            | Identified malicious execution                    |
| Command Line                | Revealed attacker intent and execution parameters |
| Parent PID                  | Established process relationships                 |
| File Activity               | Revealed payload implantation                     |
| Scheduled Tasks             | Identified persistence                            |
| Network Connections         | Identified C2 communication                       |
| Authentication Events       | Tracked credential reuse                          |
| Remote Share Access         | Revealed lateral-movement activity                |
| Credential-Dumping Activity | Identified credential-access attempts             |
| Domain Activity             | Revealed escalation to domain-level compromise    |
| DCSync Activity             | Indicated high-impact credential extraction       |
| Remote Download             | Identified ransomware staging                     |

The investigation therefore demonstrates why endpoint telemetry must be analyzed as a sequence of related events rather than as isolated alerts.

---

## Impact Assessment

The observed activity indicates a progression from an individual workstation compromise to a potentially enterprise-wide security incident.

The attacker demonstrated the ability to:

- Execute malicious code on an endpoint
- Establish persistence
- Establish command-and-control communication
- Bypass local security controls
- Obtain credentials
- Reuse compromised credentials
- Access remote network resources
- Move laterally between systems
- Dump additional credentials
- Reach the domain controller
- Perform DCSync activity
- Stage a ransomware payload

The combination of credential theft, lateral movement, and DCSync activity represents a significant escalation from endpoint compromise to potential domain compromise.

The ransomware download observed at the end of the attack chain further indicates that the attacker was preparing to transition from reconnaissance and credential access toward destructive or disruptive activity.

---

## Skills Demonstrated

- Elastic Stack / Kibana investigation
- Windows endpoint telemetry analysis
- Sysmon-based process investigation
- Process creation analysis
- PID / PPID correlation
- Command-line investigation
- File implantation analysis
- Scheduled-task persistence detection
- C2 connection identification
- UAC bypass investigation
- Credential-dumping detection
- Threat-tool acquisition tracking
- Authentication-event correlation
- Remote-share investigation
- Credential reuse detection
- Lateral-movement analysis
- Multi-host incident reconstruction
- Domain Controller investigation
- DCSync detection
- Ransomware staging detection
- IOC extraction
- Cross-host event correlation
- Attack-chain reconstruction
- Enterprise-level incident impact assessment
```
