### Summary:

This hands-on learning module focuses on using Splunk for security incident detection and response. Based on the _Boss of the SOC_ challenge (_Investigating APT_), it allowed me to enhance my SIEM skills, cyber kill chain investigation, and OSINT techniques through repetition and the gradual learning of new concepts. [Link to this room on TryHackMe]([TryHackMe | Incident handling with Splunk](https://tryhackme.com/room/splunk201))
### Scenario:

A Big corporate organization **Wayne Enterprises** has recently faced a cyber-attack where the attackers broke into their network, found their way to their web server, and have successfully defaced their website **http://www.imreallynotbatman.com** . Their website is now showing the trademark of the attackers with the message **YOUR SITE HAS BEEN DEFACED** as shown below.

---
### Reconnaissance Phase
#### 1. One Suricata alert highlighted the CVE value associated with the attack attempt. What is the CVE value?

The query returns 38 possible results, but 36 of them have CVE-2014-6271. 

	index=botsv1 sourcetype="suricata" src=40.80.148.42 
	dest="imreallynotbatman.com" CVE | stats count by signature

Answer: CVE-2014-6271 ![[Pasted image 20250327144807.png]]

#### 2. What is the CMS our web server is using?

We know DNS name and IP address of our web server, when look at incoming connections we can see used CMS in URL.

	index=botsv1 sourcetype="suricata" src=40.80.148.42   
	dest="imreallynotbatman.com" OR dest="192.168.250.70"

Answer: Joomla ![[Pasted image 20250327144215.png]]

#### 3. What is the web scanner, the attacker used to perform the scanning attempts?

Using the same broad query as above we can see `http.http_user_agent` statistics and see that web application scanner Acunetix has been used several times.

Answer: Acunetix ![[Pasted image 20250327145558.png]]

#### 4. What is the IP address of the server imreallynotbatman.com?

The answer can be easily found by looking after DNS `imreallynobatman.com` and checking `dest.ip` field.

Answer: 192.168.250.70

---
### Exploitation Phase

#### 1. What was the URI which got multiple brute force attempts?

Utilising the provided query we can see multiple attempts to authenticate via this URI.

	index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST 
	form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" 
	|table 
	_time src_ip uri http_user_agent creds

Answer: /joomla/administrator/index.php ![[Pasted image 20250327153053.png]]

#### 2. Against which username was the brute force attempt made?

The answer can be easily found by viewing events with the same query.

Answer: admin
#### 3. What was the correct password for admin access to the content management system running **imreallynotbatman.com**?

Successful authentication keeps the connection alive. Also, status 200 maybe another sign.

	index=botsv1 sourcetype="stream:http" dest_ip="192.168.250.70" 
	http_method=POST form_data=*username*passwd* dest_headers!="*Connection: 
	close*"

Answer: batman ![[Pasted image 20250327190436.png]]

#### 4. How many unique passwords were attempted in the brute force attempt?

Adding `dedup` command to the query removes duplicates and leaves only unique values.

Answer: 412

#### 5. What IP address is likely attempting a brute force password attack against **imreallynotbatman.com**?

Answer: 23.22.63.114

#### 6. After finding the correct password, which IP did the attacker use to log in to the admin panel?

Answer: 40.80.148.42

---
### Installation Phase

#### 1. Sysmon also collects the Hash value of the processes being created. What is the MD5 HASH of the program 3791.exe?

	index=botsv1 "3791.exe" EventCode=1 | table CommandLine, Hashes 

Answer: AAE3F5A29935E6ABCC2C2754D12A9AF0

#### 2. Looking at the logs, which user executed the program 3791.exe on the server?

Answer: NT AUTHORITY\IUSR

#### 3. Search hash on the virustotal. What other name is associated with this file 3791.exe?

Answer: ab.exe

---
### Action on Objective

#### 1. What is the name of the file that defaced the imreallynotbatman.com website?

Investigate `URL` field to get the answer.

	index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114

Answer: poisonivy-is-coming-for-you-batman.jpeg

#### 2. Fortigate Firewall 'fortigate_utm' detected SQL attempt from the attacker's IP 40.80.148.42. What is the name of the rule that was triggered during the SQL Injection attempt?

Investigate `attack` field to find the answer.

	index=botsv1 src_ip="40.80.148.42" sourcetype="fortigate_utm"

Answer: HTTP.URI.SQL.Injection

---
### Command and Control

#### 1. This attack used dynamic DNS to resolve to the malicious IP. What fully qualified domain name (FQDN) is associated with this attack?

Investigate `HTTP` field to find the answer.

	index=botsv1 dest_ip="192.168.250.70" "poisonivy-is-coming-for-you-batman.jpeg"

Answer: prankglassinebracket.jumpingcrab.com

---
### Weaponization Phase

#### 1. What IP address has P01s0n1vy tied to domains that are pre-staged to attack Wayne Enterprises?

Using source IP from the previous queries we can conduct additional research using Robtex, VirusTotal or Whois.domaintools to get more information on this IP.

Answer: 23.22.63.114

#### 2. Based on the data gathered from this attack and common open-source intelligence sources for domain names, what is the email address that is most likely associated with the P01s0n1vy APT group?

First of all, I looked up domain name po1sonivy on VirusTotal ![[Pasted image 20250328093239.png]]
Then I used a hint and checked suspicious sibling web pages on `otx.alienvault.com` 
![[Pasted image 20250328093322.png]]

Answer: lillian.rose@po1s0n1vy.com

---
### Delivery Phase

#### 1. What is the HASH of the Malware associated with the APT group?

Look up IP address `23.22.63.114` on ThreatMiner to analyse related to it files. One of them marked as a malicious one, investigate it using VirusTotal for confirmation.

Answer: c99131e0169171935c5ac32615ed6261

#### 2. What is the name of the Malware associated with the Poison Ivy Infrastructure?

Answer: MirandaTateScreensaver.scr.exe













