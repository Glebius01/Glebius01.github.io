## Scenario: 

SOC Analyst **Johny** has observed some anomalous behaviours in the logs of a few windows machines. It looks like the adversary has access to some of these machines and successfully created some backdoor. His manager has asked him to pull those logs from suspected hosts and ingest them into Splunk for quick investigation. Our task as SOC Analyst is to examine the logs and identify the anomalies.

---
#### How many events were collected and Ingested in the index **main**?  

	| eventcount index=main summarize=false

Answer: 12256
#### On one of the infected hosts, the adversary was successful in creating a backdoor user. What is the new username?  

	 index="main" EventCode="4720"

The query returns only one event. ![[Pasted image 20250328142908.png]]

Answer: A1berto
#### On the same host, a registry key was also updated regarding the new backdoor user. What is the full path of that registry key?

	index="main" Hostname="Micheal.Beaven" A1berto

![[Pasted image 20250328144540.png]]

Answer: HKLM\SAM\SAM\Domains\Account\Users\Names\A1berto
#### Examine the logs and identify the user that the adversary was trying to impersonate.

The target does not have a lot logs, so I used a simple query to see statistics. In an enterprise environment this query could be too costly.

	 index="main" User=*

![[Pasted image 20250328145142.png]]

Answer: Alberto
#### What is the command used to add a backdoor user from a remote computer?  

	index="main" A1berto | table CommandLine
	
![[Pasted image 20250328145940.png]]

Answer: "C:\windows\System32\Wbem\WMIC.exe" /node:WORKSTATION6 process call create "net user /add A1berto paw0rd1"
#### How many times was the login attempt from the backdoor user observed during the investigation?

None of the event IDs with this username signifies about authentication attempts.

	index="main" A1berto 

![[Pasted image 20250328150355.png]]

Answer: 0
#### What is the name of the infected host on which suspicious Powershell commands were executed?

	index="main" A1berto EventID=4103

![[Pasted image 20250328151047.png]]

Answer: James.browne
#### PowerShell logging is enabled on this device. How many events were logged for the malicious PowerShell execution?

	index="main" SourceName="Microsoft-Windows-PowerShell"

Answer: 79
#### An encoded Powershell script from the infected host initiated a web request. What is the full URL?

	index="main" EventID="4104" OR EventID="4103" 
	| rex field=ContextInfo "Host Application = (?<Command>[^\r\n]+)"
	| table Command
	| dedup Command

![[Pasted image 20250328153505.png]]
![[Pasted image 20250328153528.png]]

Answer: hxxp[://]10[.]10[.]10[.]5/news[.]php