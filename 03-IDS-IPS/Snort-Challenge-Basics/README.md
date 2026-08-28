
# Snort Challenge Basics — IDS Rule Development & Traffic Analysis

## Lab Objective

This lab focuses on practical IDS rule development and alert validation using Snort.

The investigation simulates the workflow of a SOC analyst or detection engineer who needs to create network detection rules, test them against packet captures, investigate the resulting alerts, troubleshoot rule errors, and use existing external rules to detect known exploitation activity.

Rather than relying exclusively on pre-built signatures, the investigation demonstrates how network traffic can be translated into custom Snort detection logic for different protocols, file types, authentication behaviors, and malicious payloads.

The lab also covers the validation of detection rules against PCAP data and the investigation of Snort output to extract packet-level evidence.

---

## Scenario Overview

A collection of packet captures representing different types of network activity was provided for investigation.

The objective was to develop and validate Snort rules capable of detecting specific traffic patterns across several protocols and application behaviors.

The investigation progressed from basic protocol-level detection to more targeted content-based signatures, followed by troubleshooting of intentionally broken rules and finally the use of external detection rules against real-world exploitation traffic.

The exercises covered:

- HTTP traffic
- FTP traffic and authentication activity
- PNG and GIF file detection
- Torrent metafile detection
- Snort rule syntax troubleshooting
- Snort rule logic troubleshooting
- MS17-010 exploitation
- Log4j exploitation
- Payload-size based detection
- Encoded command identification

All rules were tested directly against the provided PCAP files to verify that the expected traffic generated alerts.

---

## Tools Used

- **Snort** — IDS rule creation, validation, and alert generation
- **PCAP files** — controlled network traffic for detection testing
- **Snort alert/log files** — investigation of detected packets and rule output
- **Linux command line** — rule management and Snort execution
- **Packet-level analysis** — interpretation of network headers and payloads
- **External Snort rules** — detection of known exploitation activity

---

## Analysis Walkthrough

### 1. HTTP Traffic Detection

The first stage focused on creating a Snort rule capable of detecting TCP traffic associated with HTTP.

Instead of targeting a specific application-layer request, the rule was designed around the transport-layer characteristics of HTTP traffic, allowing all TCP packets communicating with the standard HTTP service port to be detected.

The rule was tested against the supplied HTTP PCAP using Snort's offline PCAP-analysis capability.

The resulting alert count was then reviewed to validate that the rule matched the expected traffic.

This established the basic workflow used throughout the rest of the challenge:

```
PCAP
 ↓
Custom Snort Rule
 ↓
Snort Offline Analysis
 ↓
Alert/Log Generation
 ↓
Packet-Level Investigation
```

---

### 2. Packet-Level Investigation

After generating the HTTP alerts, the Snort output was investigated to identify specific packets associated with the detection.

Individual packet records were correlated with their corresponding network-layer and transport-layer fields.

The investigation examined artifacts such as:

- Source address
- Destination address
- Source port
- Destination port
- TCP sequence number
- TCP acknowledgement number
- TTL

This demonstrated that an IDS alert is not simply an indication that "something happened"; the underlying packet information can provide additional evidence required to reconstruct the network event.

---

## FTP Detection & Authentication Analysis

### 3. Detecting All FTP Traffic

The next stage focused on FTP traffic.

A single Snort rule was created to detect TCP traffic associated with the standard FTP service port.

The rule was tested against the supplied PCAP, and the generated alerts were reviewed to validate the detection.

The resulting Snort logs were then investigated to identify information exposed by the FTP session.

---

### 4. FTP Service Identification

The detected FTP traffic was examined at the application layer to identify the service information contained within the communication.

The investigation used the Snort-generated evidence to determine the FTP service name exposed during the session.

This demonstrated how protocol-level rules can provide an entry point into application-level investigation.

---

### 5. Detecting Failed FTP Authentication

After establishing a working FTP traffic rule, the previous rule was disabled and the alert/log files were cleared to prevent results from earlier tests from affecting the next investigation.

A new Snort rule was created to identify failed FTP login attempts based on the relevant FTP response or authentication content.

The rule was then tested against the same PCAP.

The resulting alerts were reviewed to determine whether the detection correctly isolated unsuccessful authentication attempts.

This represents a more specific IDS detection strategy than simply monitoring FTP traffic:

```
All FTP Traffic
      ↓
Authentication Traffic
      ↓
Failed Login Attempt
```

---

### 6. Detecting Successful FTP Logins

The previous rule was then deactivated and the Snort output was cleared before testing a separate rule for successful FTP authentication.

The rule was designed around the application-layer response associated with a successful login.

Testing the rule against the PCAP allowed the detection logic to be validated independently from the failed-login detection.

This demonstrates how Snort can distinguish between different outcomes within the same protocol.

---

### 7. Detecting Username-Only FTP Login Attempts

The investigation was then narrowed further to identify FTP authentication attempts where a valid username had been submitted but a password had not yet been entered.

A dedicated content-based rule was created to detect the relevant FTP command sequence.

The previous rules were disabled before running the new detection to ensure that the generated alert count represented only the current rule.

This exercise demonstrated the ability to detect a specific stage of an application-layer protocol exchange rather than simply matching an entire protocol.

---

### 8. Detecting a Specific FTP Username

The final FTP detection rule focused on authentication attempts involving a specific administrative username.

The rule was constructed by matching the username within the relevant FTP command sequence while preserving the condition that the authentication process had not yet progressed to password submission.

This demonstrated how Snort content matching can be used to move from broad protocol detection toward highly targeted behavioral signatures.

The progression was:

```
FTP Traffic
   ↓
FTP Authentication
   ↓
Failed Authentication
   ↓
Successful Authentication
   ↓
Username Submission
   ↓
Specific Username
```

---

## File Detection in Network Traffic

### 9. PNG File Detection

The next stage focused on identifying files transferred through network traffic.

A Snort rule was created to detect a PNG file based on recognizable content within the packet payload rather than relying solely on the transport protocol.

The resulting alerts were investigated to identify additional information embedded in the packet.

The packet content revealed software-related information that could be extracted from the detected traffic.

This demonstrated the usefulness of payload-based detection for identifying file types and embedded artifacts.

---

### 10. GIF File Detection

The previous file-detection rule was disabled and the Snort output was cleared before creating a separate rule for GIF traffic.

The GIF rule used the identifying characteristics of the file format to generate alerts when the corresponding content appeared in the PCAP.

The generated alert was then investigated to identify the image format embedded within the packet.

This exercise demonstrated that IDS rules can identify file content even when the analyst is not relying on a filename or a dedicated file-transfer protocol.

---

## Torrent Metafile Detection

### 11. Torrent Metafile Identification

The investigation then moved to torrent-related traffic.

A Snort rule was created to detect the torrent metafile within the supplied PCAP.

The rule was tested against the traffic and the generated alerts were investigated through the Snort log and alarm output.

The investigation extracted application-level metadata from the detected traffic, including:

- Torrent application information
- MIME type
- Hostname associated with the metafile

This demonstrated how content-based Snort rules can be used to identify application artifacts embedded in otherwise ordinary network traffic.

---

## Snort Rule Troubleshooting

### 12. Syntax Error Investigation

The next phase focused on troubleshooting intentionally malformed Snort rules.

Multiple rule files were provided containing syntax errors.

Each ruleset was tested independently using Snort's offline PCAP analysis functionality.

A representative testing workflow was:

```bash
sudo snort -c local-X.rules -r mx-1.pcap -A console
```

The command allowed the ruleset to be loaded against the provided PCAP while displaying alerts directly in the console.

When Snort rejected a ruleset, the error output was used to identify the malformed portion of the rule.

The affected rule was corrected and then retested until Snort successfully loaded the ruleset and generated alerts.

This demonstrated an important detection-engineering workflow:

```
Rule
 ↓
Snort Validation
 ↓
Syntax Error
 ↓
Identify Invalid Component
 ↓
Correct Rule
 ↓
Retest
 ↓
Validate Alerts
```

---

### 13. Logical Error Investigation

Not every broken rule produced a syntax error.

Some rules were syntactically valid but logically incapable of generating the intended detection.

These rules were analyzed by reviewing their direction, protocol, addresses, ports, content conditions, and option logic.

The rules were then modified so that their conditions correctly represented the traffic they were intended to detect.

This distinction is important:

- **Syntax errors** prevent Snort from correctly loading or parsing a rule.
- **Logical errors** may allow Snort to load the rule while preventing it from matching the intended traffic.

The investigation therefore validated both the technical correctness and the detection logic of the rules.

---

### 14. Required Rule Options

One of the troubleshooting exercises required identifying a missing rule option necessary for the intended alert behavior.

The rule was analyzed in the context of Snort's alerting and rule-option structure to determine which option was required.

This reinforced the importance of understanding Snort rule syntax rather than simply copying existing signatures.

---

## External Rules — MS17-010 Detection

### 15. Investigating Known Exploitation Traffic

The next stage moved from custom detection logic to the use of an existing Snort ruleset.

A provided rules file was used to investigate network traffic associated with exploitation of the MS17-010 vulnerability.

The external rules were loaded against the supplied PCAP and Snort alerts were reviewed to determine which signatures matched the observed exploitation traffic.

This demonstrated how SOC teams can combine internally developed rules with maintained external signatures to increase detection coverage against known threats.

---

### 16. SMB Exploitation Payload Detection

After investigating the existing MS17-010 signatures, the previous logs and alert files were cleared and a new custom rule was created.

The objective was to detect payloads containing the distinctive:

```
\\IPC$
```

keyword.

The rule was tested against the supplied traffic and the generated alerts were investigated.

The corresponding packet information was then examined to identify the requested network path associated with the exploitation activity.

This demonstrated a common detection-engineering technique: extracting a recognizable artifact from an attack and turning it into a targeted content-based signature.

---

### 17. Vulnerability Context

The technical detection was also correlated with vulnerability information for MS17-010.

The vulnerability's CVSS v2 severity was reviewed to provide additional context for the significance of the detected exploitation activity.

This step connected network-level detection with vulnerability-management context:

```
Exploit Traffic
      ↓
Snort Detection
      ↓
Attack Artifact
      ↓
Vulnerability Identification
      ↓
Severity Context
```

---

## External Rules — Log4j Exploitation

### 18. Investigating Log4j Exploitation

The final major section focused on network traffic associated with Log4j exploitation.

The supplied external Snort ruleset was loaded against the provided PCAP.

Snort alerts were investigated to determine:

- How many signatures were triggered
- Which rule SIDs generated the alerts
- How the triggered signatures correlated with the observed traffic

The SID information was extracted from the alert output to identify the rules responsible for detecting the exploitation activity.

This demonstrated how analysts can investigate not only whether an alert occurred, but also **which detection logic produced it**.

---

### 19. Payload-Length Based Detection

The existing rules were then cleared and a new custom rule was created to identify packets containing payloads within a specific size range.

The rule used Snort's packet-content and payload-related capabilities to restrict detection to traffic matching the required payload-length boundaries.

The rule was tested against the Log4j PCAP and the resulting alerts were investigated.

This demonstrated that IDS detection does not always have to rely on a specific string.

Network characteristics such as payload size can also become useful detection conditions when they are associated with a known attack pattern.

---

### 20. Encoded Payload Investigation

The packet identified by the payload-length detection was investigated further.

The corresponding alert and packet data were reviewed to identify the encoding mechanism used within the malicious payload.

The encoded command was then decoded to reveal the attacker's command.

This created an additional correlation chain:

```
Log4j Traffic
      ↓
External Detection Rules
      ↓
Custom Payload-Length Rule
      ↓
Matching Packet
      ↓
Encoded Payload
      ↓
Encoding Identification
      ↓
Command Decoding
```

The decoded command provided additional evidence about the attacker's intended activity and demonstrated why payload inspection is important even after an IDS rule has already identified suspicious traffic.

---

### 21. Packet Metadata Correlation

The corresponding packet was also examined for network-layer metadata.

The IP identification field associated with the packet was extracted from the alert investigation.

This demonstrated how IDS investigation can move beyond the rule match itself and into the underlying packet structure to obtain additional forensic artifacts.

---

## Overall Detection Methodology

The challenge demonstrated a progression from broad traffic identification to increasingly precise detection logic:

```
Protocol Detection
       ↓
Application-Layer Detection
       ↓
Content-Based Detection
       ↓
Behavior-Specific Detection
       ↓
Rule Validation
       ↓
Syntax Troubleshooting
       ↓
Logic Troubleshooting
       ↓
External Threat Rules
       ↓
Exploit Detection
       ↓
Payload Analysis
```

The same workflow can be applied in a real SOC environment when developing and validating network detections.

A broad rule can first be used to understand the traffic, after which the analyst can identify stable characteristics and convert them into more specific detection logic.

---

## Detection Engineering Principles Demonstrated

### Broad → Specific

Rules were progressively refined from detecting entire protocols to detecting specific application behaviors and payload characteristics.

### Validate Against PCAP

Every detection was tested against controlled packet captures rather than being assumed to work based solely on syntactic correctness.

### Investigate Alerts

The alert count was treated as an initial validation point, while packet and application-layer information was examined to understand what actually triggered the rule.

### Separate Syntax from Logic

A rule can fail because Snort cannot parse it, or because it parses successfully but does not describe the intended traffic correctly.

### Combine Custom and External Rules

Custom signatures were used alongside existing detection rules to demonstrate how broader threat coverage can be achieved.

### Pivot From Alerts to Packets

Once a rule identified suspicious traffic, the investigation moved back to packet-level evidence to extract additional indicators and contextual information.

---

## Summary of Findings

- Developed custom Snort rules for HTTP and FTP traffic.
- Progressively refined FTP detection from general traffic to authentication-specific behaviors.
- Created content-based rules for identifying PNG, GIF, and torrent-related artifacts.
- Investigated Snort-generated logs to extract packet-level network information.
- Troubleshot multiple Snort rules containing syntax and logical errors.
- Validated corrected rules by executing them against supplied PCAP files.
- Used external Snort rules to investigate MS17-010 exploitation traffic.
- Created a custom detection for the `\\IPC$` artifact associated with SMB exploitation activity.
- Investigated Log4j exploitation using both external signatures and custom detection logic.
- Demonstrated payload-length based detection and subsequent encoded-command analysis.
- Practiced correlating IDS alerts with packet metadata and application-layer evidence.

---

## Skills Demonstrated

- Snort IDS rule development
- Snort rule syntax and option structure
- TCP/HTTP/FTP traffic detection
- Application-layer content matching
- FTP authentication monitoring
- File-signature based detection
- Payload-based IDS detection
- Torrent traffic identification
- PCAP-based IDS validation
- Snort alert and log analysis
- Rule syntax troubleshooting
- Rule logic troubleshooting
- Custom signature development
- External rule integration
- MS17-010 exploitation detection
- Log4j exploitation detection
- SMB traffic analysis
- Payload inspection and decoding
- Packet-level forensic analysis
- Detection engineering methodology
```
