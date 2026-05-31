# Azure Sentinel Cloud SIEM Lab: Attack Simulation & Detection Engineering

## Objective
The goal of this project was to construct a fully functioning cloud-based Security Information and Event Management (SIEM) system using Microsoft Sentinel, configure custom log ingestion pipelines, and engineer KQL (Kusto Query Language) detections to identify simulated cyber attacks mapped to the MITRE ATT&CK framework.

## Technologies & Tools Used
* **Cloud Provider:** Microsoft Azure (Log Analytics Workspace, Microsoft Sentinel, Virtual Machines)
* **Endpoint Security:** Sysmon (System Monitor)
* **Log Ingestion:** Azure Monitor Agent (AMA), Data Collection Rules (DCR)
* **Attack Framework:** Atomic Red Team
* **Query Language:** KQL (Kusto Query Language)

## Architecture & Configuration
1. Deployed a Windows Server virtual machine in Azure to act as the target endpoint.
2. Installed Sysmon on the endpoint with a custom SwiftOnSecurity configuration file to capture granular process and network telemetry.
3. Configured Azure Data Collection Rules (DCRs) to route native Windows Security Events and custom Sysmon `Operational` logs via the Azure Monitor Agent into Sentinel.
4. Temporarily disabled Windows Defender to allow malware execution, then utilized Atomic Red Team to simulate adversary techniques.

---

## Detection Engineering & Threat Hunting

### 1. PowerShell Obfuscation & Execution (T1059.001)
**Scenario:** Attackers often use Base64 encoding or execution bypass flags to hide malicious PowerShell commands from defenders.
**KQL Query:**
` ` `WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 1
| extend CommandLine = tostring(EventData.CommandLine), 
         Image = tostring(EventData.Image),
         User = tostring(EventData.User)
| where Image has "powershell.exe"
| where CommandLine contains "-enc" or CommandLine contains "-nop" or CommandLine contains "mimikatz"
| project TimeGenerated, Computer, User, Image, CommandLine
` ` `

### 2. Local Account Creation for Persistence (T1136.001)
**Scenario:** Attackers create local backdoor accounts to maintain access to a compromised host. Because native Event ID 4720 logging was disabled, the detection pivots to Sysmon process creation.
**KQL Query:**
` ` `
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 1 
| extend CommandLine = tostring(EventData.CommandLine),
         User = tostring(EventData.User),
         Image = tostring(EventData.Image)
| where (Image has "net.exe" or Image has "net1.exe") and CommandLine contains "user" and CommandLine contains "/add"
| project TimeGenerated, Computer, User, Image, CommandLine
| sort by TimeGenerated desc
` ` `

### 3. WMI Reconnaissance & Lateral Movement (T1047)
**Scenario:** Windows Management Instrumentation (WMI) is abused to gather system data or execute payloads remotely. 
**KQL Query:**
` ` `
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 1 
| where EventData has "wmic.exe"
| where EventData has "useraccount" 
| project TimeGenerated, Computer, EventData
| sort by TimeGenerated desc
` ` `

### 4. Data Exfiltration via C2 Channel (T1041)
**Scenario:** Malware utilizing native script interpreters like PowerShell to open outbound network connections to external Command and Control (C2) servers.
**KQL Query:**
` ` `
WindowsEvent
| where Provider == "Microsoft-Windows-Sysmon" and EventID == 3 
| where EventData has "powershell.exe" 
| project TimeGenerated, Computer, EventData
| sort by TimeGenerated desc
` ` `

### 5. RDP Brute Force Attacks (T1110)
**Scenario:** Live threat actors utilizing automated botnets to brute-force credential access on an internet-facing RDP port.
**KQL Query:**
` ` `
SecurityEvent
| where EventID == 4625 
| where LogonType == 2 or LogonType == 3  
| project TimeGenerated, TargetAccount, IpAddress, Computer
| summarize FailureCount=count() by TargetAccount, IpAddress, bin(TimeGenerated, 5m)
| where FailureCount >= 5
| sort by TimeGenerated desc
` ` `
*(Insert `Detection-6.jpg` here)*
