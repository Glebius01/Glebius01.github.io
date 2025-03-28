## Summary
## Scenario

---

#### What is the PID of the process that executed the initial stage 1 payload?

We know the that the incident occured between 29th and 30th of August, and we know that malicious file name is `ProjectFinancialSummary_Q3.pdf`. 
![image](https://github.com/user-attachments/assets/86690089-b95e-44a3-8c87-cb6618be09aa)

Answer: 6392

#### The stage 1 payload attempted to implant a file to another location. What is the full command-line value of this execution?

Using the same query we can find that one of the events has particularly interesting command line.

![image](https://github.com/user-attachments/assets/cb8da41a-25d2-46db-9689-0d8ac42f924c)

Answer: "C:\Windows\System32\xcopy.exe" /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat

#### The implanted file was eventually used and executed by the stage 1 payload. What is the full command-line value of this execution?

Following the timeline wwe can see that previously implanted file was used

Answer: "C:\Windows\System32\rundll32.exe" D:\review.dat,DllRegisterServer

#### The stage 1 payload established a persistence mechanism. What is the name of the scheduled task created by the malicious script?

Using the first query we can find the answer in `process.command_line` field![image](https://github.com/user-attachments/assets/4643df1f-d0f5-4302-8d38-f06d98aabfb8)

Answer: Review

#### The execution of the implanted file inside the machine has initiated a potential C2 connection. What is the IP and port used by this connection? (format: IP:port)

We can use `event ID 3` to look for network connection events and correlate the events with the time, when `review.dat` was executed.

![image](https://github.com/user-attachments/assets/e0eb6ac9-4387-46bf-ae09-f27560d73620)

Answer: 165.232.170.151:80

![image](https://github.com/user-attachments/assets/70f428c3-252f-4370-8ad4-cb25c8ff67b7)

#### The attacker has discovered that the current access is a local administrator. What is the name of the process used by the attacker to execute a UAC bypass?

If we look for review.dat, we can find 39 events. We know that one of the way to bypass UAC is via fodhelper.exe, and we can clearly see that because of the parent process.
![image](https://github.com/user-attachments/assets/307c9322-00fb-4acd-ab1d-c7e4aa55c5b6)

Answer: fodhelper.exe

#### Having a high privilege machine access, the attacker attempted to dump the credentials inside the machine. What is the GitHub link used by the attacker to download a tool for credential dumping?

The question hints us that it is a github download link on the infected machine. Using `*GitHub*` we can find 149 events. While investigating `process.command_line field` we can see that top 5 downloads from the github are PowerSploit module for reconnasaince, and mimikatz, which is used for credential dumping.
   
![image](https://github.com/user-attachments/assets/a72ccb8b-25ac-40c5-806f-0dcd8ee50594)

Answer: https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip

#### After successfully dumping the credentials inside the machine, the attacker used the credentials to gain access to another machine. What is the username and hash of the new credential pair? (format: username:hash)

Previously we discovered that Mimikatz is downloaded and used for credentials dumping. Let's search for `*Mimikatz*` with `Event Code 1` filter to narrow down the searc from 70+ events to just 20. While investigating these events, we can see credential dump for itadmin account.

![image](https://github.com/user-attachments/assets/6ae0c113-ca68-40ba-a9bb-53806d726b39)

Answer: itadmin:F84769D250EB95EB2D7D8B4A1C5613F2

#### Using the new credentials, the attacker attempted to enumerate accessible file shares. What is the name of the file accessed by the attacker from a remote share?

#### After dumping the hashes, the attacker attempted to download another remote file to execute ransomware. What is the link used by the attacker to download the ransomware binary?

While analysing commands executed by compromised account itadmin I was able to find the link without any problems as it has a hint in the name.

Answer: http://ff.sillytechninja.io/ransomboogey.exe


