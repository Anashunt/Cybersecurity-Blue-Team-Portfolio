
# Boogeyman 2 — Phishing, Memory Forensics & C2 Investigation

## Lab Objective

This investigation focuses on analysing a multi-stage compromise that begins with a malicious phishing attachment and progresses through payload execution, command-and-control communication, and persistence.

The objective is to reconstruct the attack chain using two primary artefacts:

- A copy of the phishing email
- A memory dump from the compromised workstation

The investigation demonstrates how email analysis can be combined with memory forensics to identify the initial access vector, recover malicious payloads and execution details, trace the process hierarchy, identify C2 infrastructure, and determine how persistence was established after the attacker gained control of the system.

---

## Scenario Overview

An employee working in the Human Resources department received an unsolicited job application containing a resume attachment.

The attachment appeared legitimate at first glance, but the document contained malicious functionality designed to initiate a multi-stage infection.

Following execution of the document, additional payloads were downloaded and executed on the workstation.

The security team detected suspicious process activity, prompting a forensic investigation of the available email and memory artefacts.

The investigation was designed to answer several key questions:

- How was the initial phishing message delivered?
- What malicious document was used as the initial payload?
- What functionality was embedded within the document?
- How was the second-stage payload downloaded?
- Which process executed the second-stage payload?
- How did the second stage retrieve the next malicious binary?
- Which process established the C2 connection?
- What infrastructure was used for C2 communication?
- Where was the malicious attachment stored on the victim system?
- How was persistence established after the C2 connection?

---

## Tools Used

- Email analysis techniques
- `olevba`
- Volatility 3
- Process enumeration
- Process-tree analysis
- Command-line analysis
- Memory-resident network connection analysis
- String and URL investigation
- MD5 hashing
- File-path reconstruction

---

## Analysis Walkthrough

### 1. Phishing Email Investigation

The investigation began with the provided phishing email.

The email headers and message content were reviewed to identify the sender and intended recipient.

Particular attention was given to:

```
From:
To:
Subject:
Attachment:
```

The sender information was extracted from the message headers rather than relying solely on the visible sender name displayed by the email client.

The recipient address was then correlated with the employee associated with the compromised workstation.

This established the initial communication path:

```
Attacker
   ↓
Phishing Email
   ↓
HR Employee
   ↓
Malicious Resume
   ↓
Workstation Compromise
```

---

### 2. Malicious Attachment Identification

The attachment included with the phishing email was identified and isolated for analysis.

The filename was recorded as an initial artifact, but the file was not treated as trustworthy simply because it appeared to be a normal resume document.

The attachment was subsequently examined for embedded malicious functionality.

A cryptographic MD5 hash was also generated to provide a unique identifier for the sample.

For example:

```bash
md5sum <malicious_attachment>
```

The resulting hash was used as an artifact for correlation during the investigation.

---

## Macro Analysis

### 3. Extracting VBA Macros

Because the attachment was a Microsoft Office document, its embedded VBA content was investigated using **Olevba**.

The document was analyzed with:

```bash
olevba <document>
```

The output was reviewed for:

- VBA macro code
- Auto-execution mechanisms
- Suspicious functions
- Encoded strings
- URLs
- PowerShell or command-shell execution
- Download functionality

The purpose of this stage was to determine what the document attempted to execute when opened by the victim.

---

### 4. Identifying the Stage 2 Download

The extracted macro code revealed functionality responsible for retrieving an additional payload from external infrastructure.

The URL embedded within the macro was identified as the download location for the second-stage payload.

Rather than executing the downloaded content, the URL was treated as an IOC and correlated with the subsequent memory investigation.

This established the first payload transition:

```
Malicious Document
       ↓
VBA Macro
       ↓
External URL
       ↓
Stage 2 Payload
```

The macro therefore provided the first direct indication that the document was not simply a malicious attachment, but the initial stage of a larger infection chain.

---

## Memory Forensics

### 5. Memory Dump Analysis

The compromised workstation's memory dump was used to investigate what occurred after the malicious document was executed.

Volatility 3 was used as the primary memory-forensics framework.

The available plugins were first reviewed when necessary:

```bash
vol -f memorydump.raw -h
```

The investigation then focused on process enumeration and process relationships.

---

### 6. Process Enumeration

Running processes were enumerated from the memory image to identify suspicious processes associated with the execution chain.

The investigation focused on identifying:

- Recently executed processes
- Unusual executable names
- Processes associated with downloaded payloads
- Parent-child process relationships
- Processes associated with network activity

A process listing was obtained using the appropriate Volatility process-enumeration plugin.

The resulting process information was then correlated with the execution artifacts recovered from the malicious document.

---

### 7. Stage 2 Process Identification

The process responsible for executing the newly downloaded second-stage payload was identified from the memory image.

The process name was correlated with its executable path and process identifiers.

The following process attributes were specifically examined:

```
Process Name
PID
PPID
Executable Path
Parent Process
```

This allowed the investigation to reconstruct how execution moved from the original document into the next stage of the attack.

The resulting relationship can be represented as:

```
Office Document
      ↓
Macro Execution
      ↓
Downloader
      ↓
Stage 2 Payload
      ↓
Stage 2 Process
```

---

### 8. Parent-Child Process Correlation

The process responsible for executing the stage 2 payload was investigated together with its parent process.

The PID and PPID values were used to establish the parent-child relationship.

This is an important forensic technique because malicious payloads frequently execute through legitimate interpreters or system processes.

Instead of examining a suspicious process in isolation, the investigation therefore reconstructed the surrounding process tree to determine how the execution originated.

---

## C2 Infrastructure Investigation

### 9. Stage 2 Payload Analysis

The stage 2 payload was then investigated to identify additional network activity.

The memory image was searched for URLs and other network-related artifacts associated with the process.

The objective was to determine whether the second-stage payload downloaded another executable.

The investigation identified another external URL associated with the subsequent malicious binary.

This revealed the next stage of the attack chain:

```
Phishing Attachment
        ↓
VBA Macro
        ↓
Stage 2 Downloader
        ↓
Stage 2 Payload
        ↓
Malicious Binary
        ↓
C2 Communication
```

---

### 10. Malicious C2 Process Identification

The memory image was further examined for processes associated with active network communication.

The suspicious process responsible for establishing the command-and-control connection was identified by correlating:

- Process information
- Executable path
- Network connections
- Process identifiers

The PID of the process was extracted and correlated with the corresponding executable.

This allowed the investigation to distinguish the C2 process from earlier stages of the infection.

---

### 11. Malicious Process Path Reconstruction

The executable path associated with the C2 process was recovered from the memory image.

File paths were treated as important forensic artifacts because they can reveal:

- Where the attacker stored the payload
- Which user context was involved
- Whether the file was executed from a temporary directory
- Whether the location was consistent with normal software installation

The process path was therefore correlated with the earlier payload-download activity.

---

### 12. C2 Connection Analysis

The network connections associated with the suspicious process were examined to identify the remote C2 endpoint.

The connection information was correlated with the process responsible for initiating the communication.

The investigation extracted:

```
C2 Process
    ↓
Remote IP
    ↓
Remote Port
```

This provided the network-level IOC required to document the command-and-control stage of the compromise.

The actual infrastructure values were retained as investigation artifacts rather than reproduced in the public portfolio report.

---

## Victim-Side Attachment Path

### 13. Malicious Attachment Path Recovery

The memory dump was also searched for references to the original malicious email attachment.

The objective was to determine the full path under which the attachment existed on the victim workstation.

This provided an important endpoint artifact because it connected the original phishing email to the file present on the compromised machine.

The resulting evidence chain was:

```
Phishing Email
      ↓
Malicious Attachment
      ↓
Victim-Side File Path
      ↓
Macro Execution
      ↓
Payload Download
```

This demonstrated how memory forensics can be used to recover endpoint artifacts even when direct access to the original filesystem is unavailable.

---

## Persistence Investigation

### 14. Scheduled Task Persistence

After establishing the C2 connection, the attacker implemented persistence to maintain access to the compromised workstation.

The investigation therefore examined process and command-line artifacts surrounding the C2 execution for evidence of scheduled-task creation.

Scheduled tasks are a common persistence mechanism because they can cause a malicious command or executable to execute automatically according to a defined trigger.

The suspicious command used to create or configure the scheduled task was reconstructed from the available forensic artifacts.

The investigation specifically focused on identifying:

```
Task Creation
      ↓
Execution Trigger
      ↓
Malicious Command
      ↓
Persistent Access
```

This demonstrated that the compromise did not end when the initial payload established C2; the attacker also attempted to establish a mechanism for continued access.

---

## Complete Attack Chain

The evidence collected during the investigation allowed the incident to be reconstructed as a multi-stage attack:

```
Phishing Email
       │
       ▼
Malicious Resume
       │
       ▼
VBA Macro Execution
       │
       ▼
Stage 2 Download
       │
       ▼
Stage 2 Payload Execution
       │
       ▼
Additional Malicious Binary
       │
       ▼
C2 Connection
       │
       ▼
Scheduled Task Persistence
       │
       ▼
Continued Access
```

Each stage was investigated using a different evidence source.

The phishing email established the initial delivery mechanism, Olevba exposed the malicious macro and its external download functionality, while Volatility was used to reconstruct process execution, payload paths, network activity, and persistence artifacts from the workstation's memory.

---

## Investigation Methodology

The investigation followed a progressive pivoting methodology:

```
Email
  ↓
Attachment
  ↓
Macro
  ↓
URL
  ↓
Stage 2 Payload
  ↓
Process
  ↓
PID / PPID
  ↓
Malicious Binary
  ↓
C2 Process
  ↓
Network Connection
  ↓
Persistence
```

Each newly discovered artifact was used as a pivot for the next stage of investigation.

This approach allowed the attack chain to be reconstructed without requiring execution of the malicious document or payloads.

---

## Summary of Findings

- Identified the sender and victim associated with the phishing email.
- Identified the malicious document delivered through the phishing campaign.
- Generated an MD5 hash for the malicious attachment.
- Extracted and analyzed the document's VBA macros using Olevba.
- Identified the external URL used to retrieve the second-stage payload.
- Used the memory dump to identify the process responsible for executing the second-stage payload.
- Reconstructed the relevant PID and parent PID relationships.
- Identified the URL used to retrieve the subsequent malicious binary.
- Identified the malicious process responsible for establishing C2 communication.
- Recovered the executable path associated with the C2 process.
- Identified the remote C2 endpoint and associated network port.
- Recovered the full victim-side path of the original malicious attachment from memory.
- Identified a scheduled-task persistence mechanism established after C2 communication.
- Reconstructed the complete multi-stage attack chain from initial phishing delivery through persistence.

---

## Skills Demonstrated

- Phishing email investigation
- Email artifact extraction
- Malicious Office document analysis
- VBA macro extraction using Olevba
- IOC extraction from document macros
- Memory forensics using Volatility 3
- Process enumeration and analysis
- Parent-child process correlation
- PID / PPID analysis
- Malicious process identification
- Executable path reconstruction
- URL and network artifact extraction from memory
- C2 connection analysis
- Endpoint artifact recovery
- Scheduled-task persistence investigation
- Multi-stage attack-chain reconstruction
- Cross-artifact forensic correlation
- Safe analysis of malicious files without execution
```
