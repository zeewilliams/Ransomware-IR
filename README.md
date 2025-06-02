# 🔐 Ransomware Attack Incident Response

![Ransomware Incident](images/event-logs-cover.png) <!-- Replace with a relevant ransomware or forensic investigation image -->

---

## 📘 Introduction

This lab focuses on investigating a simulated ransomware incident from the TryHackMe “Retracted” room. The scenario involves a user named Sophie who unintentionally downloads and executes a malicious file disguised as antivirus software (`antivirus.exe`). This triggers file encryption across the user’s system and leaves a ransom note (`SOPHIE.txt`) on the desktop demanding payment.

The investigation leverages Windows Event Logs and Sysmon logs to uncover the timeline of attacker activity, identify suspicious processes, track file creation and modification events, and detect signs of log tampering or evasion. The lab aims to simulate a realistic incident response workflow for ransomware detection and recovery.

---

## 🎯 Objectives

- Gain practical experience analyzing Windows Event Logs and Sysmon data during a ransomware incident  
- Identify process creation events related to the malicious executable and ransom note  
- Correlate event timestamps to reconstruct the attack timeline  
- Detect suspicious user activity such as file encryption and ransom note deployment  
- Understand how ransomware may manipulate logs or evade detection  
- Develop incident response strategies based on log analysis and forensic evidence

---

## 🧰 Tools & Technologies

| Tool/Service     | Purpose                                                |
|------------------|--------------------------------------------------------|
| Event Viewer     | Visualize and filter Windows event logs                |
| Sysmon           | Monitor detailed process creation, file, and network activity |
| PowerShell       | Query, filter, and export Windows Event Logs           |
| Windows 10 VM    | Simulated victim environment for ransomware infection   |

---

## 🧪 Lab Setup & Investigation Steps

### ✅ Step 1: Locate and Examine Ransom Note

- Accessed the victim’s desktop and found `SOPHIE.txt` ransom note at:  
  `C:\Users\Sophie\Desktop\SOPHIE.txt`  
- Opened the note to analyze the attacker’s message and demands  
- Verified creation metadata by filtering for file creation events in Sysmon logs

### ✅ Step 2: Trace Malicious Executable Execution

- Used Sysmon Event ID 1 (Process Creation) to identify when and how `antivirus.exe` was executed  
- Mapped parent process and user context to confirm it was launched by Sophie  
- Cross-referenced timestamps with ransom note creation and file encryption start times

### ✅ Step 3: Correlate Process and File Events

- Investigated additional Sysmon events related to file write and delete operations to observe encryption activity  
- Reviewed PowerShell and command line activity logs for potential attacker commands or lateral movement  
- Searched for any evidence of log tampering such as Security log clearing (Event ID 1102)

### ✅ Step 4: Timeline Reconstruction and Analysis

- Developed a detailed timeline of events starting from the download of the malicious executable to the ransom note deployment  
- Identified periods of attacker persistence and any attempts at removing traces  
- Documented sequence of encryption and subsequent file decryption if applicable  

### ✅ Step 5: Incident Response and Recommendations

- Summarized findings highlighting indicators of compromise (IOCs) and attacker TTPs  
- Recommended containment steps including isolating the affected machine and preserving forensic logs  
- Suggested preventive measures like enhancing log monitoring, application whitelisting, and user training  
- Advised on restoring files from backups and patching exploited vulnerabilities

---

## 📸 Screenshots

| Description                   | Screenshot                                      |
|------------------------------|------------------------------------------------|
| Sysmon Event Viewer Analysis  | ![Event Viewer Screenshot](images/event-viewer.png) |
| Ransom Note Found             | ![Ransom Note Screenshot](images/ransom-note.png) |
| Process Creation Logs         | ![Sysmon Process Creation](images/sysmon-process.png) |

---

## ✅ Key Takeaways

- Windows Event Logs and Sysmon provide critical forensic data for ransomware investigations  
- Process creation events (Sysmon Event ID 1) help identify the exact execution of malicious files  
- Correlating multiple log sources allows reconstruction of the attacker’s timeline and methods  
- Monitoring for ransom note creation and suspicious file modifications can be early detection signs  
- Log tampering attempts (e.g., clearing security logs) indicate attacker efforts to cover tracks  
- Regular log collection, analysis, and alerting are essential to timely ransomware detection and response  
- Incident response workflows must include containment, eradication, recovery, and lessons learned

---

## 📎 References

- [TryHackMe Retracted Write-Up](https://medium.com/@fritzadriano63/retracted-tryhackme-writeup-86539ece169c)  
- [TryHackMe Room – Retracted](https://tryhackme.com/room/retracted)  
- Microsoft Docs: [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)  
- Microsoft Docs: [Event Viewer](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-event-ids)  
- SANS: [Ransomware Incident Response](https://www.sans.org/white-papers/38945/)

---

## 📬 About Me

👋 I'm **Zee**, a cybersecurity analyst focused on digital forensics, incident response, and proactive defense. Through hands-on labs, I strive to simulate and defend against real-world threats in enterprise environments.

🔗 [Connect with me on LinkedIn](https://www.linkedin.com/in/zee-williams)  
🔍 [Explore my cybersecurity projects on GitHub](https://github.com/zeewilliams)
```
