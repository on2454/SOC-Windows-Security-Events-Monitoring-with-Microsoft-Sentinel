SOC – Windows Security Events Monitoring with Microsoft Sentinel
📌 Project Overview

This project demonstrates an end-to-end Security Operations Center (SOC) monitoring solution using Microsoft Sentinel to collect, analyze, and visualize Windows Security Events from a non-Azure Windows machine.

The objective was to simulate a real-world SOC workflow by onboarding a Windows host via Azure Arc, ingesting logs with Azure Monitor Agent (AMA), performing threat hunting using KQL, and building a SOC dashboard (Sentinel Workbook) for continuous monitoring and detection.

🎯 Project Objectives

Ingest Windows Security Events into Microsoft Sentinel

Monitor authentication, privilege use, and process execution

Build a SOC-focused dashboard for visibility

Perform threat hunting using KQL

Implement a basic detection rule (analytics rule)

Document the project professionally for portfolio use

🏗️ Architecture
Windows 11 VM (VirtualBox / On-Prem)
        |
        v
Azure Arc (Hybrid Compute)
        |
        v
Azure Monitor Agent (AMA)
        |
        v
Log Analytics Workspace
        |
        v
Microsoft Sentinel (SIEM)
        |
        v
SOC Dashboard (Workbook)

🧰 Tools & Technologies

Microsoft Sentinel (SIEM)

Azure Arc

Azure Monitor Agent (AMA)

Log Analytics Workspace

Windows Security Event Logs

KQL (Kusto Query Language)

Azure Portal

🔄 Data Ingestion

Windows 11 VM onboarded to Azure using Azure Arc

Azure Monitor Agent (AMA) installed via Azure Arc

Data Collection Rule (DCR) configured to collect:

Windows Security Events

Logs routed to a Log Analytics Workspace

Microsoft Sentinel enabled on the workspace

🔐 Windows Audit Configuration

Audit policies were configured to ensure meaningful security telemetry was generated.

Enabled categories include:

Logon / Logoff

Account Lockout

Special Logon

Privilege Use

Process Creation

Audit configuration was validated using auditpol commands.

🔍 Threat Hunting (KQL Examples)
Failed Logons (Brute Force Indicator)
SecurityEvent
| where EventID == 4625
| summarize FailedLogons = count() by Account, bin(TimeGenerated, 10m)
| order by TimeGenerated desc

Account Lockouts
SecurityEvent
| where EventID == 4740
| summarize Lockouts = count() by TargetAccount = Account
| order by Lockouts desc

Privileged Logons
SecurityEvent
| where EventID == 4672
| project TimeGenerated, Account, Computer
| order by TimeGenerated desc

Process Creation Monitoring
SecurityEvent
| where EventID == 4688
| summarize Count = count() by NewProcessName
| top 10 by Count

📊 SOC Dashboard (Microsoft Sentinel Workbook)

A custom Sentinel Workbook was created to provide SOC-level visibility into:

Log ingestion & agent health

Successful and failed logons

Account lockouts

Privileged activity

Process execution trends

The dashboard supports:

Real-time monitoring

Threat hunting

Rapid investigation

📸 Screenshots of the dashboard are included in this repository.

🚨 Detection & Alerting

A scheduled Analytics Rule was created to detect potential brute-force activity:

Use case: Multiple failed logons within a short time window
Severity: Medium
Mapped to MITRE ATT&CK: Credential Access (T1110)

🎯 Use Cases Covered

SOC authentication monitoring

Privileged account oversight

Hybrid (non-Azure) security monitoring

Threat hunting with KQL

SIEM dashboard design

Detection engineering fundamentals

🧠 Key Learnings

Azure Arc enables hybrid machines to be monitored like native Azure resources

AMA provides flexible and scalable log collection

Workbooks are ideal for SOC visibility and dashboards

Threat hunting queries should be validated before converting to alerts

Not all security events occur frequently (low data ≠ misconfiguration)

📄 Project Documentation (PDF)

Full technical documentation is available here:

👉 Download Project PDF

🚀 Future Improvements

Add more analytics rules (RDP abuse, privilege escalation)

Map detections to MITRE ATT&CK

Simulate advanced attack scenarios

Integrate SOAR automation using Logic Apps

Add incident response walkthroughs

👤 Author

Oni Victor
Aspiring SOC Analyst / Security Engineer

Hands-on experience with:

SIEM operations

Microsoft Sentinel

Threat hunting

Hybrid security monitoring
