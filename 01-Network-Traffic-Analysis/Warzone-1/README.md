# Network Alert Triage — IDS/IPS Alert Validation (Tier 1 SOC)

## Lab Objective

This lab simulates a Tier 1 SOC analyst workflow: taking a raw IDS/IPS alert and independently validating whether it represents a true positive, using only packet capture analysis and open-source threat intelligence.

## Scenario Overview

An IDS/IPS system generated two linked alerts — "Potentially Bad Traffic" and "Malware Command and Control Activity Detected" — on a monitored network segment. The objective was to inspect the associated packet capture, validate the alert, and reconstruct the full scope of the incident, including any additional infected hosts.

## Tools Used

- Brim (fast alert/flow triage)
- Wireshark (deep packet inspection, stream/file reconstruction)
- NetworkMiner (file/object extraction from traffic)
- VirusTotal — Community tab (attribution)

## Analysis Walkthrough

### 1. Alert Triage (Brim)

The PCAP was loaded into Brim and queried using the alert event type (`event_type=alert`) to isolate all IDS-generated alerts within the capture. The specific record matching the "Command and Control" signature was pulled up directly, from which the source and destination IP addresses of the flagged connection were extracted.

### 2. Threat Intelligence Enrichment

The destination IP was submitted to VirusTotal and reviewed under the **Community** tab, which surfaced third-party attribution linking it to a known threat group and a specific malware family — validating the alert beyond just the local signature match.

### 3. Malicious File-Type Profiling

A VirusTotal lookup on the related domain was performed, then the **Communicating Files** tab was reviewed to identify the dominant file type historically served by that infrastructure, reinforcing the malware family identification.

### 4. Traffic Fingerprinting (Wireshark)

Switching to Wireshark, the traffic was filtered using:

```
ip.addr == <flagged_ip> && http
```

This isolated all HTTP requests to/from the flagged host.

Expanding the Hypertext Transfer Protocol section of the request packet revealed the User-Agent header value used by the malicious traffic — a reusable artifact for future detection signatures.

This can also be pulled directly using the display filter:

```
http.user_agent
```

### 5. Scope Expansion (Retracing the Attack)

To determine whether other hosts were part of the same campaign, **Statistics → Conversations** was reviewed alongside a broader filter:

```
http.request
```

This surfaced all outbound HTTP requests in the capture, which were then manually correlated against the known-malicious IP to identify two additional external IP addresses exhibiting the same request pattern — each tied to a distinct downloaded file.

### 6. File Drop Reconstruction

For each of the two newly identified IPs, the relevant TCP session was isolated using:

```
ip.addr == <ip_in_question> && http.request
```

followed by **right-click → Follow → HTTP Stream** on the matching packet to reconstruct the full request/response, including the GET request path and the server's response headers.

In both cases, the response body contained a **Content-Disposition** header (or equivalent path reference) revealing the exact local directory and filenames the payload was written to on the victim host — showing a consistent two-file drop pattern per stage.

File objects were additionally exported for verification via:

```
File → Export Objects → HTTP
```

## Summary of Findings

- Confirmed the alert as a **true positive** with attributed threat group and malware family
- Extracted the malicious User-Agent signature for future detection rules
- Expanded the incident scope beyond the original alert, uncovering two additional compromised hosts and their payloads
- Reconstructed on-disk file drop locations per infection stage directly from network traffic

## Skills Demonstrated

- Independent validation of automated IDS/IPS alerts using Brim's `event_type=alert` querying
- Wireshark display-filter proficiency (`http`, `http.user_agent`, `http.request`, `ip.addr`) for targeted traffic isolation
- HTTP stream reconstruction and object extraction for file-drop analysis
- Threat intelligence pivoting (IP → threat group → malware family → file-type behavior)
```
