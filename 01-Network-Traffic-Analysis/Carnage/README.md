# Network Traffic Analysis — Malicious Document to C2 Communication

## Lab Objective
This lab focuses on reconstructing a complete network-based attack chain from a single packet capture (PCAP) — starting from an initial malicious document delivery, through payload retrieval, Cobalt Strike C2 identification, and post-infection behavior — using Wireshark and Brim as the primary analysis tools.

## Scenario Overview
An endpoint agent flagged a workstation for suspicious outbound network connections following the opening of a malicious document. A packet capture was provided for retrospective analysis to reconstruct the full incident timeline and identify all associated indicators of compromise.

## Tools Used
* **Wireshark** (protocol filtering, stream reassembly, header inspection)
* **Brim** (rapid flow triage and timeline overview)
* **VirusTotal** — Community tab (infrastructure attribution)

## Analysis Walkthrough

### 1. Initial Triage
The capture was first loaded into Brim to get a high-level overview of protocol distribution and traffic volume, which helped narrow down the timeframe of interest before switching to Wireshark for deep-dive analysis.

### 2. Payload Delivery Identification
HTTP traffic was filtered in Wireshark to isolate the first suspicious outbound request. By inspecting the GET request and its response headers, the delivered file type, its name, and the hosting domain were identified. The archive's internal contents were also inferred directly from the transfer metadata, without needing to extract or open the file locally — a safer approach when handling potentially malicious payloads.

### 3. Web Server Fingerprinting
The HTTP response headers of the hosting server were reviewed to identify the web server software and version powering the malicious infrastructure, which is a useful step for infrastructure profiling and threat actor attribution.

### 4. Multi-Domain Delivery Chain
Continued HTTP filtering revealed that payloads were staged across multiple distinct domains rather than a single source — a common technique to increase resilience against domain takedowns. The TLS handshake of the first domain in this chain was inspected (via Wireshark's TLS/Follow Stream features) to identify the issuing Certificate Authority of its SSL certificate, which can sometimes reveal patterns in how threat actors provision their infrastructure (e.g., free/automated certificate issuers frequently abused in malicious campaigns).

### 5. Cobalt Strike C2 Identification
Suspicious periodic connection patterns consistent with Cobalt Strike beaconing behavior were identified in the traffic. The associated IP addresses were cross-referenced against VirusTotal's Community tab to confirm their classification as known Cobalt Strike C2 infrastructure. Once confirmed, these IPs were used as pivot points to filter and extract their associated HTTP Host headers and resolve their corresponding domain names — effectively mapping the full C2 infrastructure from a pair of flagged connections.

### 6. Post-Infection Traffic Analysis
A separate domain — distinct from the initial C2 infrastructure — was identified as responsible for post-infection communication. The first outbound packet to this domain was inspected at the byte level to identify a recognizable pattern in the transmitted payload, along with its length and the corresponding server response header, both of which support further malware family attribution.

### 7. Anti-Sandbox / Environment-Awareness Check
A DNS query to a public "IP-lookup" style API service was identified in the traffic. This is a common technique used by malware to fingerprint its execution environment (e.g., detecting sandboxed or virtualized analysis environments) before proceeding with further malicious activity — a detail relevant for both detection engineering and sandbox evasion awareness.

### 8. Malicious Spam (Malspam) Activity
Filtering for SMTP traffic revealed evidence that the compromised host was also being leveraged to send outbound spam/phishing emails, indicating the infected machine had transitioned from an initial foothold to being actively used for further campaign propagation. The relevant SMTP session details (sender address pattern, volume of packets) were extracted to support this finding.

## Summary of Findings
* Full attack chain reconstructed purely from network traffic, without access to the host or the malicious file itself.
* Identified and validated two Cobalt Strike C2 servers using threat intelligence cross-referencing.
* Distinguished between initial C2 infrastructure and separate post-infection communication channels.
* Identified secondary malicious activity (malspam) originating from the compromised host.

## Skills Demonstrated
* End-to-end PCAP-based incident reconstruction.
* Cobalt Strike C2 traffic pattern recognition and validation.
* Certificate and server fingerprinting for infrastructure profiling.
* Cross-protocol correlation (HTTP, TLS, DNS, SMTP) within a single incident.
* Practical application of threat intelligence platforms (VirusTotal) during live analysis.
