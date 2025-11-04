![VmAttackMap](/images/Windows%20VM%20Attack%20Map.png)

# Azure-Sentinel-Honeypot
I built a honeypot in Azure and it was compromised 1,750 times in 72 hours. Here's what I found.

# SOC Analyst Exercise: Building an Azure Honeypot (Part 1: Detection & Analysis)

### Project Overview

As a cybersecurity analyst, one of the best ways to understand attacker techniques, tactics, and procedures (TTPs) is to observe them in a controlled environment. For this project, I designed and deployed a live, intentionally vulnerable Windows 11 VM in the Microsoft Azure cloud.

The goal was twofold:

1. **Build** a realistic "honeypot" asset to attract malicious traffic.
    
2. **Integrate** the asset with a modern SIEM (Microsoft Sentinel) to ingest, analyze, and visualize the resulting security events, following the **Detection and Analysis** phases of the NIST Incident Response framework.
    

Within 72 hours, the machine was discovered and compromised by attackers thousands of times. This write-up details the project's architecture, the detection of the initial breach, and the triage of post-compromise activity.



## Phase 1: Building the "Victim" - Cloud Infrastructure

The entire project was built using an Infrastructure as a Service (IaaS) model in Microsoft Azure, ensuring complete isolation from any production or personal networks.

The architecture was organized logically:

- **Resource Group:** `HomeLab-Soc-Project`
    
- **Virtual Network (VNet):** `Vnet-HomeLab-Soc-Project`
    
- **Virtual Machine (VM):** `CORP-WEST-2` (A Windows 11 Pro instance)
    
- **Log Analytics Workspace:** `LOW-Soc-Lab` (To collect logs)
    
- **SIEM:** Microsoft Sentinel (To analyze logs)
    

Here is a visualization of the resource group and its components:

![Azure Resource Map](/images/Honeypot%20Diagram.png)

To make the honeypot an attractive target, I implemented two key misconfigurations:

1. **Network Security Group (NSG):** I created an inbound rule named `DANGER_AllowAnyCustomInbound` that allows all traffic, from any source IP and any port, to the VM. 

![NSG "Allow Any" Rule](/images/Danger%20NSG.png)
    
2. **Host-Based Firewall:** I RDP'd into the new VM and manually disabled the Windows Defender Firewall for all profiles (Domain, Private, and Public), ensuring the machine was fully exposed. 

![Windows Firewall Disabled](/images/Firewalls%20Off.png)
    

With the defenses down, the honeypot was live and ready.



## Phase 2: Connecting the Watchtower (SIEM)

A vulnerable VM is useless without a way to record what happens to it. I connected the `CORP-WEST-2` VM to the `LOW-Soc-Lab` Log Analytics Workspace and enabled Microsoft Sentinel. This piped all Windows Security Events from the VM directly into the SIEM in real-time.

It didn't take long for attackers to find the machine. Within 72 hours, an initial query for **EventID 4625 (An account failed to log on)** showed a staggering **28,584** failed login attempts.



## Phase 3: Triage and Analysis

The 28,584 failed logins were just the "noise" of automated, internet-wide scanners. The real investigation began by enriching this data.

**1. Visualizing the Global Threat** To map the source of the attacks, I ingested a third-party Geo-IP database into Sentinel as a Watchlist.

I then used a KQL query to join the `SecurityEvent` logs with this watchlist, correlating attacker IPs to their geographic coordinates. This data was used to build a "Windows VM Attack Map" workbook.

The map revealed a coordinated, global campaign, with the highest volume of attacks originating from:

- **Pingzhen District, Taiwan:** 6.43K
    
- **Amstelveen, Netherlands:** 5.58K
    
- **Swellendam, South Africa:** 4.4K
    
- **Minodacho, Japan:** 3.38K
    

![Windows VM Attack Map](/images/Windows%20VM%20Attack%20Map.png)

**2. Finding the "Signal" - Successful Compromise** While the _failed_ logins were high-volume, the most critical finding was in the _successful_ logins.

I filtered for **EventID 4624 (An account successfully logged on)** and was alarmed to find **1,750** successful, unauthorized logins. This means that while 28k+ attempts failed, attackers _did_ find valid credentials—or the RDP service was vulnerable.

A query to summarize the successful logins by IP and Account revealed the "smoking gun":

- **Attacker IP `**.**.***.137`**
    
- **Successful Logins: 26**


This immediately pivoted the investigation from "detection" to "incident response." The machine was not just being scanned; it was actively compromised. The next question was: _What did they do?_

**3. Triage of Post-Compromise Activity** With a confirmed breach, I ran a broad triage query to hunt for common post-compromise TTPs, searching for events related to privilege escalation, process creation, and discovery.

The results showed a 1,229 suspicious activities, confirming the attacker had moved laterally _after_ logging in. 

![Post-Compromise Triage Query](/images/Post%20Compromise%20Triage%20Query.png)

Key findings from this query include:

- **EventID 4672 (Privilege Escalation):** "Special privileges assigned to new logon."
    
- **EventID 4688 (Execution):** "A new process has been created."
    
- **EventID 4798 (Discovery):** "A user's local group membership was enumerated."
    
- **EventID 4799 (Discovery):** "A security-enabled local group membership was enumerated."
    
- **EventID 5058 & 5061 (Credential Access/Defense Evasion):** Cryptographic and key file operations.

   

## Conclusion & Next Steps (Part 1)

This project successfully demonstrated the ability to rapidly deploy cloud infrastructure, configure data ingestion into a SIEM, and perform the initial stages of incident analysis.

We've established that our asset is not only under attack but is _actively compromised_. We have identified the source of the attacks, visualized the global threat, and—most importantly—isolated the activity of a specific, persistent attacker.

This concludes Part 1: Detection and Analysis. **Part 2 of this analysis** will move deeper into the Incident Response (IR) cycle, focusing on a deep-dive investigation of the 1,229 suspicious activities to trace the exact actions taken by the `abuser` account and map their TTPs to the MITRE ATT&CK framework.
