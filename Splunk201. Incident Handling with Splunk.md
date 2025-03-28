### Summary:

This hands-on learning module focuses on using Splunk for security incident detection and response. Based on the _Boss of the SOC_ challenge (_Investigating APT_), it allowed me to enhance my SIEM skills, cyber kill chain investigation, and OSINT techniques through repetition and the gradual learning of new concepts. [Link to this room on TryHackMe]([TryHackMe | Incident handling with Splunk](https://tryhackme.com/room/splunk201))
### Scenario:

A Big corporate organization **Wayne Enterprises** has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website **http://www.imreallynotbatman.com** . Their website is now showing the trademark of the attackers with the message **YOUR SITE HAS BEEN DEFACED** as shown below.
---
### Reconnaissance Phase

#### One Suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?

The query returns 38 possible results, but 36 of them have CVE-2014-6271. 

	index=botsv1 sourcetype="suricata" src=40.80.148.42 
	dest="imreallynotbatman.com" CVE | stats count by signature

Answer: CVE-2014-6271![Pasted image 20250327144807](https://github.com/user-attachments/assets/a9017b7b-afb7-4e0a-a371-80e431d67eac)

#### What is the CMS our web server is using?

We know DNS name and IP address of our web server, when look at incoming connections we can see used CMS in URL.

	index=botsv1 sourcetype="suricata" src=40.80.148.42   
	dest="imreallynotbatman.com" OR dest="192.168.250.70"

Answer: Joomla![Pasted image 20250327144215](https://github.com/user-attachments/assets/6843721a-1c8b-462a-98ce-771954fa1321)

#### What is the web scanner, the attacker used to perform the scanning attempts?

Using the same broad query as above we can see `http.http_user_agent` statistics and see that web application scanner Acunetix has been used several times.

Answer: Acunetix ![Pasted image 20250327145558](https://github.com/user-attachments/assets/2e168cfe-b416-4f28-b217-10e2c5751ea8)

#### What is the IP address of the server imreallynotbatman.com?

The answer can be easily found by looking after DNS `imreallynobatman.com` and checking `dest.ip` field.

Answer: 192.168.250.70
---
### Exploitation Phase

#### What was the URI which got multiple brute force attempts?

Utilising the provided query we can see multiple attempts to authenticate via this URI.

	index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST 
	form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" 
	|table 
	_time src_ip uri http_user_agent creds

Answer: /joomla/administrator/index.php![Pasted image 20250327153053](https://github.com/user-attachments/assets/aa64fa11-c39e-49dd-8939-fadb2b35520a)

#### Against which username was the brute force attempt made?

The answer can be easily found by viewing events with the same query.

Answer: admin

#### What was the correct password for admin access to the content management system running **imreallynotbatman.com**?

Successful authentication keeps the connection alive. Also, status 200 maybe another sign.

	index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" 
	http_method=POST form_data=*username*passwd* dest_headers!="*Connection: 
	close*"

Answer: batman![Pasted image 20250327190436](https://github.com/user-attachments/assets/681beffa-8636-4de8-bd2d-fcdc93365821)

#### How many unique passwords were attempted in the brute force attempt?

Adding `dedup` command to the query removes duplicates and leaves only unique values.

Answer: 412

#### What IP address is likely attempting a brute force password attack against **imreallynotbatman.com**?

Answer: 23.22.63.114

#### After finding the correct password, which IP did the attacker use to log in to the admin panel?

Answer: 40.80.148.42
---
### Installation Phase

#### Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?

	`index=botsv1 "3791.exe" EventCode=1 | table CommandLine, Hashes` 

Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

#### Looking at the logs, which user executed the program 3791.exe on the server?

Answer: NT AUTHORITY\IUSR

#### Search hash on the virustotal. What other name is associated with this file 3791.exe?

Answer: ab.exe
---
### Action on Objective

#### What is the name of the file that defaced the imreallynotbatman.com website?

Investigate `URL` field to get the answer.

	index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114

Answer: poisonivy-is-coming-for-you-batman.jpeg

#### Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

Investigate `attack` field to find the answer.

	index=botsv1 src_ip="40.80.148.42" sourcetype="fortigate_utm"

Answer: HTTP.URI.SQL.Injection
---
### Command and Control

#### This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

Investigate `HTTP` field to find the answer.

	index=botsv1 dest_ip="192.168.250.70" "poisonivy-is-coming-for-you-batman.jpeg"

Answer: prankglassinebracket.jumpingcrab.com
---
### Weaponization Phase

#### What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

Using source IP from the previous queries we can conduct additional research using Robtex, VirusTotal or Whois.domaintools to get more information on this IP.

Answer: 23.22.63.114

#### Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

First of all, I looked up domain name po1sonivy on VirusTotal ![Pasted image 20250328093239](https://github.com/user-attachments/assets/06c579a2-da6d-4c50-b9d5-5c8e18d5bd70)


Then I used a hint and checked suspicious sibling web pages on `otx.alienvault.com` ![Pasted image 20250328093322](https://github.com/user-attachments/assets/fae54ac5-afa2-4cab-bde5-cfbe8ca89a86)

Answer: lillian.rose@po1s0n1vy.com
---
### Delivery Phase

#### What is the HASH of the Malware associated with the APT group?

Look up IP address `23.22.63.114` on ThreatMiner to analyse related to it files. One of them marked as a malicious one, investigate it using VirusTotal for confirmation.

Answer: c99131e0169171935c5ac32615ed6261

#### What is the name of the Malware associated with the Poison Ivy Infrastructure?

Answer: MirandaTateScreensaver.scr.exe













