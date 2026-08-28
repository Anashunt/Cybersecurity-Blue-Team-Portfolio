```markdown
# Network Alert Triage — Extended Infrastructure Mapping (Tier 1 SOC)

## Lab Objective

This lab is a continuation of a Tier 1 SOC alert-triage exercise, focused on validating multiple simultaneous IDS/IPS alerts from the same incident and — critically — extending the investigation beyond what the IDS itself flagged, to determine whether traffic marked as "not suspicious" was in fact part of the same malicious infrastructure.

## Scenario Overview

Two linked alerts were raised on the same packet capture: "A Network Trojan was Detected" and "Potential Corporate Privacy Violation."

Both needed to be validated against the underlying traffic, the delivered payload needed to be identified and profiled, and the investigation needed to determine whether the incident's true infrastructure footprint extended beyond the IPs the IDS had explicitly flagged.

## Tools Used

- Brim (alert triage, flow overview)
- Wireshark (HTTP stream analysis, object extraction)
- NetworkMiner (file/payload extraction)
- VirusTotal — Community & Relations tabs (domain/IP attribution)

## Analysis Walkthrough

### 1. Alert Triage (Brim)

The capture was queried in Brim using `event_type=alert` to pull both IDS signatures ("A Network Trojan was Detected" and "Potential Corporate Privacy Violation") tied to this incident.

Both alerts were confirmed to share the same triggering IP address, indicating a single host was responsible for both flagged behaviors rather than two separate incidents.

### 2. Payload Delivery Reconstruction

The traffic to the flagged IP was isolated in Wireshark using:

```
ip.addr == <flagged_ip> && http.request
```

The matching `GET` request was followed via **Follow → HTTP Stream** to recover the full request URI of the malicious downloaded file (a `.cab` archive).

The user-agent string associated with this same request was also extracted directly from the HTTP request headers, providing a reusable detection artifact.

### 3. Payload Extraction (NetworkMiner)

Rather than downloading the file manually, the capture was loaded into **NetworkMiner** and the **Files** tab was used to extract the `.cab` object directly from the reconstructed traffic.

Reviewing the archive's contents revealed the name of the payload staged inside it, without needing to execute or manually unpack anything outside the analysis tool.

### 4. Threat Intelligence Cross-Referencing

The domains observed in the surrounding traffic were checked individually against VirusTotal to identify which were independently flagged as malicious, building a confirmed list of malicious infrastructure tied to this delivery chain.

### 5. Extending the Scope — "Not Suspicious" Traffic

Rather than limiting the investigation to the IDS-flagged IP alone, **Statistics → Conversations** in Wireshark was reviewed to list all distinct IP addresses present in the capture.

Each additional IP was checked against VirusTotal, which revealed that a subset of these — despite **not** being flagged by the IDS as suspicious — were in fact associated with known-malicious domains according to VirusTotal's **Relations** tab.

This highlighted a key detection gap: infrastructure that blends in as ordinary traffic can still be part of the same malicious campaign.

### 6. Domain Correlation per Unflagged IP

For each of the "Not Suspicious" IPs identified in the previous step, the domains reported by VirusTotal as associated with that IP were cross-checked against what actually appeared in the packet capture using:

```
ip.addr == <ip> && http
```

and:

```
ip.addr == <ip> && dns
```

This was done to confirm which of those domains were **actively contacted** during this specific incident rather than simply being historically associated with the IP in VirusTotal's records.

## Summary of Findings

- Validated two simultaneous IDS alerts as originating from a single compromised host
- Extracted and profiled the delivered payload without manual file execution, using NetworkMiner's object extraction
- Identified a set of malicious domains beyond the initially flagged indicators
- Uncovered additional malicious infrastructure that had **not** been flagged by the IDS, by manually reviewing the full conversation list and cross-referencing against threat intelligence

## Skills Demonstrated

- Multi-alert correlation to a single root-cause host
- Safe payload extraction and profiling via NetworkMiner (no manual file execution)
- Wireshark filter proficiency (`http.request`, `ip.addr`, `dns`) combined with **Statistics → Conversations** for full-traffic review
- Recognizing the limitation of relying solely on IDS-flagged traffic, and independently verifying "clean" traffic against threat intelligence
```
