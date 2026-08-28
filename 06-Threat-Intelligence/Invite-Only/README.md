
# Invites Only — Threat Intelligence Investigation & Indicator Pivoting

## Lab Objective

This lab simulates a SOC threat-intelligence investigation performed during an active incident-response workflow.

The investigation begins with two suspicious indicators escalated by a Tier 1 analyst: an external IP address and a SHA-256 file hash. The objective is to enrich these indicators, identify the malware and files associated with them, trace relationships between dropped files and execution activity, and ultimately connect the technical indicators to a broader threat campaign.

Rather than treating each indicator independently, the investigation demonstrates an **indicator-pivoting methodology**, where every confirmed artifact becomes a starting point for discovering additional related infrastructure, malware samples, and attacker behavior.

The investigation also extends beyond the internal threat-intelligence platform by using external reporting to identify the original campaign, the browser credential-stealing technique, the phishing method, and the infrastructure used to redirect victims toward malicious servers.

---

## Scenario Overview

A Managed Security Service Provider received two suspicious findings that had been identified early during the monitoring process:

- A suspicious external IP address
- A suspicious SHA-256 file hash

The indicators were escalated to a higher-level analyst for further investigation.

The task was to use the organization's newly deployed **TryDetectThis2.0** threat-intelligence platform to determine:

1. What file was associated with the suspicious hash
2. What type of file it represented
3. Which processes executed or spawned the suspicious file
4. What additional files were dropped during execution
5. Which other malicious files were associated with the resulting hash relationships
6. Which malware family linked the suspicious files to the flagged IP
7. Which external threat report originally documented the same indicators
8. How the attackers stole browser cookies
9. Which phishing technique was used
10. Which platform was abused to redirect victims toward malicious infrastructure

This investigation therefore moved from **single-indicator enrichment** to **campaign-level threat intelligence**.

---

## Tools Used

- **TryDetectThis2.0** — Indicator enrichment and relationship analysis
- **Google** — External threat-report identification and campaign research
- Threat-intelligence relationships between hashes, files, IP addresses, and malware families

---

## Analysis Walkthrough

### 1. Initial Indicator Triage

The investigation began with the SHA-256 indicator because a file hash can provide significantly more context than an IP address alone.

The hash was submitted to **TryDetectThis2.0** to determine whether it had previously been observed in the platform's intelligence database.

The initial lookup was used to identify:

- Filename
- File type
- Associated execution information
- Parent/child relationships
- Related hashes
- Dropped files
- Infrastructure relationships

Rather than immediately jumping to external searches, the internal intelligence platform was used first to establish a reliable set of related artifacts.

---

### 2. File Identification

The SHA-256 lookup returned a file associated with the flagged indicator.

The filename and file type were recorded as the initial malware artifact.

The file type was particularly important because it helped establish how the artifact was likely delivered and executed and provided additional context for interpreting the execution-parent relationships returned by the intelligence platform.

The resulting information was treated as the starting point for the investigation rather than as the final finding.

---

### 3. Execution-Parent Analysis

The next step was to examine the execution relationships associated with the flagged hash.

TryDetectThis2.0 provided execution-parent information showing which processes had been responsible for launching or leading to the execution of the suspicious file.

The parent processes were reviewed in chronological order.

This allowed the investigation to reconstruct the execution chain:

```
Initial Process
      ↓
Intermediate Process
      ↓
Flagged Malicious File
```

The hashes associated with the relevant parent processes were also preserved because they could be used as additional pivots within the threat-intelligence platform.

This is an important SOC investigation technique: **a malicious child process can expose otherwise unknown parent artifacts that may themselves be malicious or part of the same infection chain.**

---

### 4. Dropped-File Investigation

The execution relationship was then expanded to examine files created or dropped by the suspicious process.

The platform revealed a file being dropped during execution.

The filename and associated hash were recorded for further investigation.

This created the next pivot:

```
Flagged SHA-256
      ↓
Malicious File
      ↓
Execution Parent
      ↓
Dropped File
      ↓
New SHA-256
```

The newly discovered hash was then submitted independently to TryDetectThis2.0.

---

### 5. Secondary Hash Pivot

The second hash produced a broader set of relationships.

Instead of focusing on a single sample, the investigation examined the complete list of malicious files associated with the hash.

Four malicious dropped files were identified and documented in their observed order.

This provided evidence that the original indicator was part of a larger malware delivery chain rather than an isolated malicious file.

The investigation therefore expanded from:

```
One Hash
```

into:

```
Multiple Files
      ↓
Multiple Payloads
      ↓
Shared Infrastructure
```

This type of relationship analysis is particularly useful during incident response because attackers frequently reuse loaders, payloads, droppers, and supporting components across multiple infections.

---

### 6. IP-to-Malware Correlation

The investigation then returned to the second initial indicator: the suspicious IP address.

The IP was searched within TryDetectThis2.0 and its associated files and relationships were reviewed.

The objective was to determine whether the files discovered through the hash investigation were independently connected to the same infrastructure.

The results showed that multiple files associated with the flagged IP shared a common malware-family relationship.

This established a stronger correlation than simply observing that a file had communicated with a suspicious IP.

The relationship could be represented as:

```
Suspicious IP
      │
      ├── Malicious File A
      ├── Malicious File B
      ├── Malicious File C
      └── Malicious File D
             │
             ▼
      Common Malware Family
```

This provided a malware-family-level classification for the infrastructure.

---

### 7. Indicator Relationship Mapping

At this point, the investigation had accumulated several connected artifacts:

```
Flagged IP
    │
    ├── Related Files
    │       │
    │       └── Malware Family
    │
    └── Infrastructure Relationships

Flagged SHA-256
    │
    └── File
          │
          ├── Execution Parents
          │
          └── Dropped File
                  │
                  └── Related Malicious Files
```

Combining these relationships allowed the investigation to determine that the original indicators were components of a broader malicious campaign.

The important analytical step was not simply collecting indicators, but **connecting the indicators into a coherent relationship graph**.

---

### 8. External Threat-Report Pivot

Once the malware family and associated infrastructure had been identified, the investigation moved outside TryDetectThis2.0.

Google was used to search for the original threat report containing the same combination of indicators.

The search was performed using combinations of:

- Malware family
- File hashes
- IP infrastructure
- Distinctive filenames
- Campaign behavior

Searching multiple indicators together reduced the likelihood of matching an unrelated report.

The original report was identified and used to provide additional context that was not available directly from the internal threat-intelligence platform.

---

### 9. Campaign Attribution

The original report provided broader information about the campaign associated with the observed indicators.

This allowed the investigation to move from technical IOC identification toward understanding the attacker's broader methodology.

The report was reviewed specifically for:

- Initial access technique
- Phishing methodology
- Browser credential theft
- Infrastructure used for redirection
- Malware deployment behavior
- Supporting tools

This stage demonstrated the importance of combining automated threat-intelligence platforms with human-readable threat research.

---

### 10. Browser Cookie Theft

The external report was reviewed for information regarding browser credential and session-data theft.

The attackers were found to have used a specific tool to steal cookies from the **Google Chrome** browser.

This was particularly significant because browser cookies can contain authenticated session information.

From a defensive perspective, cookie theft can allow an attacker to bypass the need for a username and password in situations where an active authenticated session can be reused.

The tool identified in the report was therefore recorded as an additional threat-intelligence artifact.

---

### 11. Phishing Technique Identification

The investigation then focused on how the victims were initially directed toward the malicious infrastructure.

The original report described the phishing technique used by the attackers.

Rather than relying solely on the malware or infrastructure indicators, the investigation used the report's description of the campaign to identify the specific phishing technique.

This added an important behavioral indicator to the investigation:

```
Technical Indicators
        +
Malware
        +
Infrastructure
        +
Initial Access Technique
        =
Campaign Profile
```

---

### 12. Malicious Redirect Infrastructure

The final stage of the investigation focused on the infrastructure used to redirect victims.

The threat report identified a platform that the attackers abused to redirect users toward malicious servers.

This infrastructure was significant because the redirection layer could act as an intermediary between the victim and the actual malicious server.

From a detection perspective, this demonstrates why investigating only the final malicious domain or IP may be insufficient.

A campaign can use:

```
Victim
   ↓
Phishing Infrastructure
   ↓
Redirect Platform
   ↓
Malicious Server
   ↓
Payload
```

Understanding the redirect mechanism provides additional opportunities for threat hunting and infrastructure detection.

---

## Investigation Pivot Chain

The complete investigation can be summarized as an indicator-pivoting workflow:

```
Flagged SHA-256
       │
       ▼
Identify Malicious File
       │
       ▼
Identify File Type
       │
       ▼
Trace Execution Parents
       │
       ▼
Identify Dropped File
       │
       ▼
Pivot to Secondary Hash
       │
       ▼
Identify Additional Malicious Files
       │
       ▼
Correlate With Flagged IP
       │
       ▼
Identify Malware Family
       │
       ▼
Search External Threat Reports
       │
       ▼
Identify Original Campaign Report
       │
       ├── Browser Cookie Theft Tool
       │
       ├── Phishing Technique
       │
       └── Redirect Platform
```

---

## Threat Intelligence Assessment

The investigation demonstrates how a SOC analyst can transform two initially isolated indicators into actionable threat intelligence.

The initial IP and SHA-256 hash were not treated as independent findings. Instead, each confirmed artifact became a pivot point for discovering additional relationships.

The investigation progressed through four levels:

### Level 1 — Indicator

Identify the suspicious IP and file hash.

### Level 2 — Artifact

Determine the filename, file type, execution parents, and dropped files.

### Level 3 — Infrastructure

Correlate the discovered files with the suspicious IP and identify the malware family.

### Level 4 — Campaign

Use external reporting to understand the attacker's phishing methodology, browser-cookie theft activity, and redirect infrastructure.

This approach produces significantly more useful intelligence than simply reporting that an IP address or hash is malicious.

---

## Summary of Findings

The investigation successfully:

- Enriched the initially flagged SHA-256 hash using TryDetectThis2.0
- Identified the associated malicious filename and file type
- Reconstructed the execution-parent relationships
- Identified an additional dropped file and preserved its hash for further pivoting
- Discovered multiple malicious files associated with the secondary hash
- Correlated the malicious files with the initially flagged IP
- Identified the malware family connecting the observed infrastructure
- Located the original external threat report documenting the indicators
- Identified the tool used by the attackers to steal Google Chrome cookies
- Identified the phishing technique used during the campaign
- Identified the platform abused to redirect victims toward malicious servers

The investigation ultimately transformed a pair of raw indicators into a broader **campaign-level intelligence picture**, demonstrating the value of iterative IOC pivoting and external threat-report correlation.

---

## Skills Demonstrated

- Threat-intelligence indicator enrichment
- SHA-256 malware investigation
- IP reputation and infrastructure analysis
- Hash-to-hash pivoting
- Execution-parent relationship analysis
- Malware dropper/payload relationship mapping
- Multi-file malware correlation
- IP-to-malware-family correlation
- Threat-report discovery using search engines
- Campaign-level threat intelligence
- Browser-cookie theft investigation
- Phishing-technique identification
- Redirect infrastructure analysis
- IOC pivoting methodology
- Converting raw indicators into actionable SOC intelligence

---

## SOC Analyst Methodology

This challenge demonstrates a practical threat-intelligence workflow that can be applied during real Incident Response investigations:

```
Collect IOC
    ↓
Enrich IOC
    ↓
Identify Related Artifacts
    ↓
Pivot on New Hashes / IPs
    ↓
Correlate Infrastructure
    ↓
Identify Malware Family
    ↓
Research External Reporting
    ↓
Extract TTPs
    ↓
Build Campaign Context
    ↓
Produce Actionable Threat Intelligence
```

The key lesson is that an IOC should rarely be treated as the end of an investigation.

A suspicious hash can reveal a filename, which can reveal an execution chain, which can reveal additional payloads, which can reveal infrastructure, which can reveal a malware family, and finally lead to the broader campaign and attacker techniques behind the activity.
```
