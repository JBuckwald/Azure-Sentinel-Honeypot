![VmAttackMap](/images/Windows%20VM%20Attack%20Map.png)

# Anatomy of a Honeypot: A 28,000-Attack Investigation Guided by NIST SP 800-61r3

In cybersecurity, theory is one thing—practice is another. To bridge this gap, I built a live, intentionally vulnerable Windows 11 VM in Microsoft Azure. My goal was to observe real-world attacker techniques, tactics, and procedures (TTPs) in a controlled environment.

Within 72 hours, the honeypot was discovered and targeted by over 28,000 attacks.

This write-up is a formal case study of that incident, following the **NIST SP 800-61r3 incident response framework**. It's a story that begins with a mountain of "noise" and ends with the discovery of a single, subtle "signal," demonstrating the full investigative lifecycle from preparation to recovery.

![NIST SP 800-61r3 Incident Response Framework diagram](/images/NIST%20SP%20800-61r3.png)

---

## Part 1: Preparation (Govern, Identify, Protect)

Before an incident ever occurs, the `Preparation` phase is critical. For this project, this involved building the "victim" and the "watchtower."

- **Govern & Identify:** The project was governed by a single goal: create an isolated IaaS (Infrastructure as a Service) environment to attract and analyze threats. The assets were identified and organized within a single Azure Resource Group (`HomeLab-Soc-Project`) for easy management and teardown.
    
    The key components were:
    
    - **Virtual Network (VNet):** `Vnet-HomeLab-Soc-Project`
        
    - **Virtual Machine (VM):** `CORP-WEST-2` (a Windows 11 Pro instance)
        
    - **Log Analytics Workspace:** `LOW-Soc-Lab` (to collect logs)
        
    - **SIEM:** Microsoft Sentinel (to analyze logs)
        

![Diagram of the cloud-based honeypot architecture](/images/Honeypot%20Diagram.png)

- **Protect (The Misconfiguration):** The goal of a honeypot is to fail at the `Protect` phase _intentionally_. I implemented two key misconfigurations to make the VM an irresistible target:
    
    1. **Network Security Group (NSG):** I created an inbound rule, `DANGER_AllowAnyCustomInbound`, allowing all traffic from any source IP and any port.
        
    2. **Host-Based Firewall:** I RDP'd into the VM and manually disabled the Windows Defender Firewall for all profiles (Domain, Private, and Public).
        

!['Danger NSG' rule and the 'Firewalls Off' configuration](/images/Insecure%20Settings.png)

Finally, I connected the `CORP-WEST-2` VM to the `LOW-Soc-Lab` Log Analytics Workspace and enabled Microsoft Sentinel. This crucial step ensured all Windows Security Events were piped directly into the SIEM, arming the "watchtower" and making `Detection` possible.

---

## Part 2: Incident Response (Detect, Respond, Recover)

This phase represents the core of the incident, following the `Detect -> Respond -> Recover` loop.

#### Detection: The Alarms Go Off

It didn't take long for attackers to find the exposed machine. The initial `Detection` came from a simple KQL query for **EventID 4625 (An account failed to log on)**.

Within 72 hours, this query returned a staggering **28,584** failed login attempts.

![KQL query for EventID 4625](/images/kql-query-1.png)

This was the "noise"—a massive, automated, global brute-force campaign. To visualize this global threat, I ingested a Geo-IP database into Sentinel as a Watchlist. By joining the `SecurityEvent` logs with this watchlist, I created a "Windows VM Attack Map" that showed the geographic origins of the attacks.

![VmAttackMap](/images/Windows%20VM%20Attack%20Map.png)

While the failed logins were voluminous, the _real_ alarm was in the successful logins. A query for **EventID 4624 (An account successfully logged on)** returned over **1,750** successful, unauthorized logins.

This discovery immediately pivoted the investigation from passive `Detection` to active `Response`.

#### Response: The Hunt for the "Signal"

The `Response` phase is all about analysis: separating the signal from the noise. I had 1,750+ successful logins. My task was to find the _who, what,_ and _when_.

A query to summarize successful remote logons (`LogonType == 3`) gave me my first two leads.

![The "Pivot" query screenshot](/images/kql-query-3.png) 

**Lead #1: The False Positive ( IP `76.32.x[.]x`)** My first hypothesis was that `IP 76.32.x[.]x` was the primary threat. It had a high login count, and a quick triage query against its activity revealed a terrifying list of "suspicious" TTPs, including `EventID 4672 (Privilege Escalation)`, `EventID 4688 (Execution)`, and `EventID 4798 (Discovery)`.

![Post-Compromise TTP query, showing EventIDs 4672, 4688, etc.](/images/kql-query-4.png)

This looked like a potentially serious compromise. However, after checking the IP address `76.32.x[.]x`, I realized it was **my own administrative IP**. The "alarming" events were the benign, noisy processes of my own RDP session and normal Windows operations. This is the most crucial step of any real-world investigation: **baselining**. I had successfully triaged my primary lead as a **False Positive**.

**Lead #2: The Real Attacker (`NT AUTHORITY\ANONYMOUS LOGON` from IP `218.205.64[.]41`)** I pivoted my investigation. After filtering out my own admin activity, the _true_ signal became clear. The vast majority of the 1,750+ successful logins were from the `ANONYMOUS LOGON` account, with the top offender being IP `218.205.64[.]41`.

My analysis of this attacker followed two stages:

1. **Identify Confirmed TTPs:** The attacker's behavior perfectly mapped to two MITRE ATT&CK techniques:
    
    - **T1078 (Valid Accounts):** The attacker gained `Initial Access` by leveraging a valid, built-in, low-privilege account: `NT AUTHORITY\ANONYMOUS LOGON`.
        
    - **T1592 (Gather Victim Host Information):** The _purpose_ of a "Null Session" is to perform `Reconnaissance` to gather host information.
        
2. **Hunt for Subsequent TTPs (Scoping the Incident):** The attacker was in. Now I had to determine: _how far did they get?_ I formed a hypothesis that they would attempt Execution or further Discovery, and I hunted for those TTPs.
    
    - **Hunt for Execution (MITRE T1059):** I hunted for `EventID 4688 (Process Creation)` from this new IP to see if they ran any commands.
        
    - **Hunt for Discovery (MITRE T1087):** I hunted for `EventID 4798/4799 (Group Enumeration)` from this IP to see if they tried to list users or groups.
        

!['Execution' hunt and 'Discovery' hunt, both showing "0 results"](/images/kql-queries-5-6.png)

**Result: 0.** The attacker _never_ executed a single command and _never_ enumerated any groups.

This was the "Aha!" moment. The VM wasn't compromised by a brute-force RDP attack. It was being _scanned_ by a global botnet exploiting a classic **"Null Session" vulnerability**. The attacker's TTPs were limited to `Reconnaissance` and `Initial Access`. My proactive hunt for `Execution` and `Discovery` TTPs _proved_ the incident was contained and the attacker's automated script was not programmed for further post-compromise activity.

#### Recover: Containing and Eradicating the Threat

The `Recover` phase is about fixing the problem and returning to a normal state.

1. **Containment:** The immediate threat was the exposed NSG. I replaced the `DANGER_AllowAnyCustomInbound` rule with a new rule that **only allows RDP (port 3389)** from a **single, trusted administrative IP**. This immediately contained the threat and stopped all scanners.
    
2. **Eradication:** The _root cause_ was the Null Session vulnerability. To eradicate it, I enabled the Local Security Policy on the VM: `"Network access: Do not allow anonymous enumeration of SAM accounts and shares"`. This breaks the scanner's ability to authenticate as `ANONYMOUS LOGON`.
    
3. **Validation (Recovery):** I monitored the VM for 24 hours post-fix. KQL queries confirmed that `EventID 4624` (Successful Logon) for `ANONYMOUS LOGON` dropped to **zero**, and `EventID 4625` (Failed Logon) for the same account began to appear. The fix was validated; the scanners were now being correctly rejected.
    

---

## Part 3: Lessons Learned (Identify Improvement)

This project feeds directly back into the `Preparation` phase for any future deployment.

- **Key Takeaway 1: The Importance of Baselining.** The noisiest and most "obvious" threat (`labuser`) was a false positive. An analyst who panics and chases ghosts will miss the real, more subtle threat. Always baseline your own administrative activity.
    
- **Key Takeaway 2: The Value of Proactive Hunting.** The investigation wasn't complete once I found the _real_ attacker. The most critical step was _scoping_ the incident by hunting for the TTPs I _expected_ to see next (Execution, Discovery). Proving a negative (that they _didn't_ run commands) was the key to closing the case.
    
- **Key Takeaway 3: Scanned vs. Compromised.** The data showed 1,750+ "successful logins," but context is everything. These were not 1,750 distinct breaches. They were low-level, automated `Initial Access` events that never progressed further. Understanding the _type_ of logon is more important than the _volume_.

- **Conclusion: The Framework Works.** By following the NIST framework, I was able to move methodically from the `Preparation` of the environment, to the `Detection` of 28,000+ events, to the `Response` of triaging a false positive and finding the real vulnerability, and finally to the `Recovery` and validation of the fix.