## Summary 

This medium-difficulty capstone project is typically completed at the end of the L1 SOC Analyst path on THM. Although I did not finish that path, I find it gratifying to see how the insights I’ve gained from various courses converge allowing me to draw logical connections between events more quickly while investigating cyber security incidents. The entire lab is based on investigation in ELK. <a href="https://tryhackme.com/room/boogeyman3" target="_blank" rel="noopener noreferrer">Link to this challenge on TryHackMe.</a>

## Scenario

Without tripping any security defences of Quick Logistics LLC, the Boogeyman was able to compromise one of the employees and stayed in the dark, waiting for the right moment to continue the attack. Using this initial email access, the threat actors attempted to expand the impact by targeting the CEO, Evan Hutchinson. 
![image](https://github.com/user-attachments/assets/631193b7-4b0f-435d-80e0-d63dd02f9a30)

The email appeared questionable, but Evan still opened the attachment despite the scepticism. After opening the attached document and seeing that nothing happened, Evan reported the phishing email to the security team.

Initial Investigation

Upon receiving the phishing email report, the security team investigated the workstation of the CEO. During this activity, the team discovered the email attachment in the downloads folder of the victim.

![image](https://github.com/user-attachments/assets/3794c48f-1ae5-48a6-b54a-e8c475ab9df7)
In addition, the security team also observed a file inside the ISO payload, as shown in the image below.
![image](https://github.com/user-attachments/assets/f3be4152-5bf0-4225-906a-fc01371a0b36)

Lastly, it was presumed by the security team that the incident occurred between August 29 and August 30, 2023.

## Given the initial findings, you are tasked to analyse and assess the impact of the compromise.

---

#### 1. What is the PID of the process that executed the initial stage 1 payload?

We know the that the incident occured between 29th and 30th of August, and we know that malicious file name is `ProjectFinancialSummary_Q3.pdf`. 
![image](https://github.com/user-attachments/assets/86690089-b95e-44a3-8c87-cb6618be09aa)

Answer: 6392

#### 2. The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

Using the same query we can find that one of the events has particularly interesting command line.

![image](https://github.com/user-attachments/assets/cb8da41a-25d2-46db-9689-0d8ac42f924c)

Answer: "C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

#### 3. The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

Following the timeline wwe can see that previously implanted file was used.

Answer: "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

#### 4. The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

Using the first query we can find the answer in `process.command_line` field![image](https://github.com/user-attachments/assets/4643df1f-d0f5-4302-8d38-f06d98aabfb8)

Answer: Review

#### 5. The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

We can use `event ID 3` to look for network connection events and correlate the events with the time, when `review.dat` was executed.

![image](https://github.com/user-attachments/assets/e0eb6ac9-4387-46bf-ae09-f27560d73620)

Answer: 165.232.170.151:80

![image](https://github.com/user-attachments/assets/70f428c3-252f-4370-8ad4-cb25c8ff67b7)

#### 6. The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

If we look for review.dat, we can find 39 events. We know that one of the way to bypass UAC is via fodhelper.exe, and we can clearly see that because of the parent process.
![image](https://github.com/user-attachments/assets/307c9322-00fb-4acd-ab1d-c7e4aa55c5b6)

Answer: fodhelper.exe

#### 7. Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

The question hints us that it is a github download link on the infected machine. Using `*GitHub*` we can find 149 events. While investigating `process.command_line field` we can see that top 5 downloads from the github are PowerSploit module for reconnasaince, and mimikatz, which is used for credential dumping.
   
![image](https://github.com/user-attachments/assets/a72ccb8b-25ac-40c5-806f-0dcd8ee50594)

Answer: https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

#### 8. After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

Previously we discovered that Mimikatz is downloaded and used for credentials dumping. Let's search for `*Mimikatz*` with `Event Code 1` filter to narrow down the searc from 70+ events to just 20. While investigating these events, we can see pash-the-hash attack for itadmin first and then for administrator accounts.

![image](https://github.com/user-attachments/assets/6ae0c113-ca68-40ba-a9bb-53806d726b39)

Answer: itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

#### 9. Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

From the previous questions we know that the Threat Actor utilises power shell process with ID 6190, so we can filter for this value to see all the command run by this PID.![image](https://github.com/user-attachments/assets/1a7edf78-49dc-48bc-9f6c-fa8a1c5331b1)

Answer: IT_automation.ps1

The following events after accessing file show that the TA forcefully converted a plain text password into a secure string and then run a power shell command using credentials.
![image](https://github.com/user-attachments/assets/7ab645e4-4e76-49da-bd35-fe5db52aad75)

Answer: QUICKLOGISTICS\allan.smith:Tr!ckyP@ssw0rd987

#### 10. What is the hostname of the attacker's target machine for its lateral movement attempt?
The answer can be found in `host.name` field or while analysing events.
![image](https://github.com/user-attachments/assets/9ec0cfee-b36c-4609-a74d-e0cb68c33a59)

Answer: WKSTN-1327
I filtered for user `"QUICKLOGISTICS\allan.smith"` and created a visualizaion to look through parent processes names and their executed commands. `wsmprovhost.exe` got my attention, and I found out that it also ran a malicious base64.
![image](https://github.com/user-attachments/assets/c452dcad-c316-4ddb-a019-cd981da8b34d)

Answer: wsmprovhost.exe 

#### 11. The attacker then dumped the hashes in this second machine. What is the username and hash of the newly dumped credentials? (format: username:hash)

The answer could be found during investigation of question 8. I specified user Allan Smith and we know that Mimikatz was for credential dumping.
![image](https://github.com/user-attachments/assets/6f8a2294-60da-4b5c-b28b-276570bd0b15)

#### 12. After gaining access to the domain controller, the attacker attempted to dump the hashes via a DCSync attack. Aside from the administrator account, what account did the attacker dump?
We know mimikatz command for DCsync attack, so it is enough to type in `*dcsync*` to find another targeted account backupda, likely a reserve account. Also, the answer can be found earlier while investigating all events that related to `mimikatz`.
![image](https://github.com/user-attachments/assets/b0069be0-bc7b-49f8-ab44-f8581b889d6c)

#### 13. After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

While analysing commands executed by compromised account itadmin I was able to find the link without any problems as it has a hint in the name.

Answer: http://ff.sillytechninja.io/ransomboogey.exe


