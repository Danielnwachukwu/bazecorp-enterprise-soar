# BAZECORP Enterprise SOAR

### Enterprise-Style Security Orchestration, Automation and Response

**Automated Security Monitoring | Threat Detection | Incident Correlation | MITRE ATT&CK | Telegram Incident Reporting**

[![Platform](https://img.shields.io/badge/Platform-Windows%2011-blue)](https://www.microsoft.com/windows)
[![Monitoring](https://img.shields.io/badge/Telemetry-Sysmon-informational)](https://learn.microsoft.com/sysinternals/downloads/sysmon)
[![SIEM](https://img.shields.io/badge/Security%20Monitoring-Wazuh-00A5A8)](https://wazuh.com/)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)](https://attack.mitre.org/)
[![Notifications](https://img.shields.io/badge/Notifications-Telegram-26A5E4)](https://telegram.org/)

---

## 1. Project Overview

BAZECORP Enterprise SOAR is an independently developed, enterprise-style Security Orchestration, Automation and Response project designed to demonstrate how a Security Operations Centre (SOC) can monitor endpoint activity, identify suspicious behaviour, correlate security events, enrich detections with MITRE ATT&CK intelligence and automatically generate incident notifications.

The project uses a controlled virtual lab environment to simulate enterprise security monitoring and attack scenarios.

Its central monitoring workflow uses a Python-based live monitor to process Windows endpoint telemetry and generate structured security alerts. Telegram provides automated incident notifications, while Wazuh supplies additional endpoint telemetry collection, security event analysis and validation.

The system is designed to support security analysts by reducing manual monitoring effort and improving the speed and consistency of incident reporting.

**Core principle: FINAL DECISION LEFT FOR THE ANALYST.**

The platform supports detection and reporting. Investigation, validation and authorization of response actions remain with the analyst.

## 2. Project Objectives

- Develop a continuously running endpoint monitoring workflow.
- Monitor Windows Sysmon and Windows Security events.
- Identify suspicious process execution and authentication activity.
- Detect repeated failed authentication attempts.
- Identify selected suspicious PowerShell execution patterns.
- Correlate related security events within configured time windows.
- Enrich supported detections with MITRE ATT&CK techniques.
- Generate structured security incident reports.
- Deliver automated Telegram notifications.
- Demonstrate analyst-led incident investigation and response decisions.

## 3. Enterprise Lab Architecture

### Logical architecture

The project uses a distributed lab architecture consisting of an attacker machine, a monitored Windows endpoint, a central Wazuh server and a Telegram notification channel.

```text
                 CONTROLLED SECURITY LAB
                         |
                         |
              +----------------------+
              |     KALI LINUX       |
              |   Attacker Machine   |
              |   192.168.56.111     |
              +----------+-----------+
                         |
                         | Controlled attack simulations
                         | Nmap / SMB / PowerShell tests
                         |
                         v
              +----------------------+
              |   WINDOWS 11         |
              |   SOC ENDPOINT       |
              |   192.168.56.1       |
              |                      |
              |   Sysmon             |
              |   Windows Security   |
              |   Wazuh Agent        |
              |   Python Live Monitor|
              +----------+-----------+
                         |
               +---------+----------+
               |                    |
               |                    |
               v                    v
      +------------------+   +----------------------+
      | PYTHON SOAR      |   | WAZUH SERVER         |
      | DETECTION ENGINE |   | 192.168.56.122       |
      |                  |   |                      |
      | Event Monitoring |   | Wazuh Manager        |
      | Event Correlation|   | Wazuh Indexer        |
      | MITRE Mapping    |   | Wazuh Dashboard      |
      | Severity Rating  |   | Central Event Review |
      +--------+---------+   +----------------------+
               |
               | Structured incident notification
               v
      +----------------------+
      | TELEGRAM             |
      | SOC NOTIFICATIONS    |
      |                      |
      | Incident Reports     |
      | Severity Levels      |
      | MITRE ATT&CK Details |
      | Analyst Assessment   |
      +----------------------+
```

### Lab components

| Component | Purpose |
|---|---|
| Kali Linux | Controlled attack simulation and security testing |
| Windows 11 | Monitored endpoint and SOC workstation |
| Sysmon | Process and endpoint telemetry collection |
| Windows Security Logs | Authentication and network connection events |
| Python live monitor | Event monitoring, detection and correlation |
| MITRE ATT&CK | Threat technique enrichment |
| Wazuh Agent | Endpoint telemetry forwarding |
| Wazuh Server | Centralised event analysis and dashboard |
| Telegram Bot | Automated incident notification |

### Lab network addressing

| System | Lab IP address |
|---|---|
| Kali Linux | 192.168.56.111 |
| Windows 11 endpoint | 192.168.56.1 |
| Wazuh server | 192.168.56.122 |

These addresses belong exclusively to the controlled lab environment.

## 4. Detection and Monitoring Capabilities

### A. Network reconnaissance

Controlled Nmap scans are performed from Kali Linux against the Windows endpoint.

Activities include:

- TCP port discovery.
- Identification of open and filtered ports.
- Service and version enumeration.
- Identification of exposed services such as SSH, SMB, NetBIOS and RPC.

The project collects Windows network telemetry to support investigation of inbound connections.

### B. Failed authentication and password guessing

Windows Security Event ID 4625 is monitored for failed authentication attempts.

The Python detection workflow correlates repeated failures by source IP within a configured time window.

Demonstrated detection:

- Five failed authentication attempts.
- One source IP.
- One targeted account.
- Five-minute correlation window.
- HIGH severity notification.
- MITRE ATT&CK T1110.001 — Password Guessing.

### C. Suspicious PowerShell execution

Sysmon Event ID 1 is monitored for selected suspicious process execution patterns.

The demonstrated test uses a harmless encoded PowerShell command to validate detection and reporting.

Demonstrated mapping:

- Sysmon Event ID 1.
- Encoded PowerShell command execution.
- HIGH severity notification.
- MITRE ATT&CK T1059.001 — PowerShell.
- Execution tactic.

### D. Network connection monitoring

Windows Security Event ID 5156 is monitored for permitted inbound connections from the designated Kali lab host.

The report includes:

- Source and destination IP addresses.
- Source and destination ports.
- Application and process information where available.
- Protocol.
- Windows Security record identifier.

A permitted connection is not, by itself, proof of malicious activity or successful exploitation. The current evidence shows these individual connection alerts classified as LOW.

## 5. Severity Classification

The project uses four severity levels to communicate the assessed significance of detected activity.

| Severity | Meaning |
|---|---|
| CRITICAL | A configured detection indicates activity requiring immediate analyst attention |
| HIGH | Significant suspicious activity or correlated security events |
| MEDIUM | Suspicious or unusual activity requiring investigation |
| LOW | Informational activity or a connection event without sufficient evidence of an attack |

Severity is determined by configured detection logic and lab policy. It should not be interpreted as proof of compromise.

## 6. MITRE ATT&CK Integration

The project uses the MITRE ATT&CK Enterprise framework to enrich supported detections with adversary behaviour classifications.

| Technique | Name | Demonstrated scenario |
|---|---|---|
| T1110.001 | Password Guessing | Repeated failed authentication |
| T1059.001 | PowerShell | Encoded PowerShell execution simulation |

Network discovery and other techniques may be mapped where sufficient telemetry and correlation evidence are available.

A technique mapping is an analytical classification, not proof that an attacker successfully completed the associated behaviour.

## 7. Automated Telegram Incident Reporting

Detected events are converted into structured SOC incident notifications.

The notification format includes:

1. Incident identification and timestamp.
2. Endpoint intelligence.
3. Detection details.
4. MITRE ATT&CK intelligence, where established.
5. SOC analyst assessment.
6. Final decision and response authorization reminder.

The reporting workflow is designed to provide useful context rather than simply forwarding raw event messages.

**FINAL DECISION LEFT FOR THE ANALYST**

Investigate, validate and authorize any response action.

## 8. Project Evidence

The following evidence is organised according to the project naming convention:

- **K** — Kali attack and testing evidence.
- **W** — Wazuh event and detection evidence.
- **T** — Telegram incident reports.
- Numbered files represent the main sequence.
- Decimal suffixes represent continuation screenshots.

### 8.1 Kali attack evidence

Controlled testing and reconnaissance performed from Kali Linux.

**K1 — Initial TCP port reconnaissance**

![K1 Nmap Initial TCP Port Reconnaissance](KALI%20ATTACKS/K1-Nmap-Initial-TCP-Port-Reconnaissance.png)

**K2 — Service and version enumeration**

![K2 Nmap Service Version Enumeration](KALI%20ATTACKS/K2-Nmap-Service-Version-Enumeration.png)

**K3 — Controlled SMB password guessing test**

![K3 Controlled SMB Password Guessing Test](KALI%20ATTACKS/K3-Controlled-SMB-Password-Guessing-Test.png)

**K4 — Encoded PowerShell execution simulation**

![K4 Encoded PowerShell Execution Simulation](KALI%20ATTACKS/K4-Encoded-PowerShell-Execution-Simulation.png)

### 8.2 Wazuh evidence

Centralised security event evidence from the monitored Windows endpoint.

**W3 — Kali-originated failed authentication event**

![W3 Kali Originated Failed Authentication Event 4625](WAZUH/W3-Kali-Originated-Failed-Authentication-Event-4625.png)

### 8.3 Telegram incident reporting evidence

Automated incident notifications generated by the Python monitoring workflow.

**T1 — Inbound SSH connection**

![T1 Telegram Inbound SSH Connection Alert](TELEGRAM%20REPORTS/T1-Telegram-Inbound-SSH-Connection-Alert.png)

**T1.1 — SSH connection assessment continuation**

![T1.1 Telegram SSH Connection Assessment](TELEGRAM%20REPORTS/T1.1-Telegram-SSH-Connection-Alert-Assessment-Continuation.png)

**T2 — Inbound NetBIOS connection, port 139**

![T2 Telegram NetBIOS Connection](TELEGRAM%20REPORTS/T2-Telegram-Inbound-NetBIOS-Port-139-Connection.png)

**T2.1 — Inbound SMB connection, port 445**

![T2.1 Telegram SMB Connection](TELEGRAM%20REPORTS/T2.1-Telegram-Inbound-SMB-Port-445-Connection-Details.png)

**T2.2 — Inbound MSRPC connection, port 135**

![T2.2 Telegram MSRPC Connection](TELEGRAM%20REPORTS/T2.2-Telegram-Inbound-MSRPC-Port-135-Connection.png)

**T3 — HIGH severity password guessing detection**

![T3 Telegram High Severity Password Guessing Detection](TELEGRAM%20REPORTS/T3-Telegram-High-Severity-Password-Guessing-Detection.png)

**T3.1 — MITRE T1110.001 assessment**

![T3.1 Telegram Password Guessing MITRE Assessment](TELEGRAM%20REPORTS/T3.1-Telegram-Password-Guessing-MITRE-T1110.001-Assessment.png)

**T4 — HIGH severity encoded PowerShell detection**

![T4 Telegram High Severity Encoded PowerShell Detection](TELEGRAM%20REPORTS/T4-Telegram-High-Severity-Encoded-PowerShell-Detection.png)

**T4.1 — MITRE T1059.001 assessment**

![T4.1 Telegram PowerShell MITRE Assessment](TELEGRAM%20REPORTS/T4.1-Telegram-MITRE-T1059.001-PowerShell-Execution-Assessment.png)

## 9. Repository Structure

The repository is organised around the monitoring engine, detection modules, MITRE enrichment, notifications, datasets and supporting evidence.

```text
bazecorp-enterprise-soar/
│
├── automation/
│   ├── config/
│   │   ├── live_sysmon_monitor.py
│   │   └── telegram_config.py
│   │
│   ├── detection/
│   │   └── alert_engine.py
│   │
│   ├── mitre/
│   │   ├── mapping.py
│   │   └── enterprise-attack.json
│   │
│   ├── notifications/
│   │   └── telegram_notifier.py
│   │
│   ├── datasets/
│   │   └── recon_events.json
│   │
│   └── watcher.py
│
├── KALI ATTACKS/
│   ├── K1-Nmap-Initial-TCP-Port-Reconnaissance.png
│   ├── K2-Nmap-Service-Version-Enumeration.png
│   ├── K3-Controlled-SMB-Password-Guessing-Test.png
│   └── K4-Encoded-PowerShell-Execution-Simulation.png
│
├── WAZUH/
│   └── W3-Kali-Originated-Failed-Authentication-Event-4625.png
│
├── TELEGRAM REPORTS/
│   ├── T1-Telegram-Inbound-SSH-Connection-Alert.png
│   ├── T1.1-Telegram-SSH-Connection-Alert-Assessment-Continuation.png
│   ├── T2-Telegram-Inbound-NetBIOS-Port-139-Connection.png
│   ├── T2.1-Telegram-Inbound-SMB-Port-445-Connection-Details.png
│   ├── T2.2-Telegram-Inbound-MSRPC-Port-135-Connection.png
│   ├── T3-Telegram-High-Severity-Password-Guessing-Detection.png
│   ├── T3.1-Telegram-Password-Guessing-MITRE-T1110.001-Assessment.png
│   ├── T4-Telegram-High-Severity-Encoded-PowerShell-Detection.png
│   └── T4.1-Telegram-MITRE-T1059.001-PowerShell-Execution-Assessment.png
│
├── README.md
└── requirements.txt
```

*Note: This is the documented logical structure of the project and its evidence. Keep the actual source tree and filenames consistent with the files uploaded to the repository. Do not create empty or placeholder modules simply to match this illustration.*

## 10. Security and Operational Considerations

- Telegram bot credentials must never be committed to a public repository.
- Use environment variables or a locally excluded configuration file for secrets.
- Exclude Python virtual environments, caches and local log files.
- Do not publish real credentials, tokens or private organisational information.
- Perform testing only against systems for which authorization has been granted.
- Preserve analyst approval for response actions.
- Validate detection rules against genuine event evidence before treating an alert as confirmed malicious activity.

## 11. Current Demonstrated Capabilities and Limitations

The available lab evidence demonstrates:

- Kali-based TCP reconnaissance and service enumeration.
- Controlled SMB authentication testing.
- Windows Security Event ID 4625 monitoring.
- Correlation of repeated failed authentication attempts.
- Sysmon Event ID 1 process monitoring.
- Encoded PowerShell execution detection.
- MITRE ATT&CK mapping for T1110.001 and T1059.001.
- Automated Telegram incident reporting.
- Wazuh collection and review of endpoint security events.
- Analyst-led incident assessment and response decisions.

The available evidence does not establish successful exploitation, account compromise, a successful malware infection, or complete coverage of all network scanning activity. Aggregated high-severity Nmap detection remains a separate validation requirement.

## 12. Disclaimer — Simulated Enterprise Environment

**BAZECORP Enterprise SOAR is an independently developed cybersecurity project designed to demonstrate how an enterprise SOC and SOAR solution can operate.**

The name BAZECORP is used as a fictional enterprise environment for demonstration and educational purposes. This project does not represent, belong to, or claim deployment within any actual organisation or employer, including any organisation with a similar name.

All displayed IP addresses, hostnames, usernames, network configurations, security events, incident reports and other organisational details are simulated lab information or controlled test data. They must not be interpreted as actual infrastructure, confidential information, or security incidents belonging to a real organisation.

This project is independently developed and tested in a controlled virtual lab environment. Its purpose is to demonstrate enterprise-style security monitoring, threat detection, event correlation, MITRE ATT&CK enrichment, automated incident reporting and analyst-led response workflows.

## 13. Project Philosophy

The objective is not simply to generate alerts. It is to demonstrate how security telemetry can be transformed into structured, contextualised and actionable information for SOC analysts.

**Detect. Correlate. Enrich. Report. Investigate.**

**FINAL DECISION LEFT FOR THE ANALYST.**

---

**BAZECORP Enterprise SOAR**  
*Automated Security Monitoring & Incident Reporting*
