### Investigation:

* On Apr, 20, 2023, 09:42 AM L1 analyst escalated the case because of its malicious hash and reports of it being WSHRAT-type malware.

* We can observe execution of "C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs" (8FAF36EDFAE1EC0E8ECCD3C562C03903) on the endpoint "David" by wscript.exe. The VBScript attempted to access sensitive system resources or files, such as the Windows Registry or system files, that are not related to its expected functionality.

* Beside the unusual process interaction and the file's location, we confirmed the malicious nature of the file by looking the hash up on Virus Total, which revealed the following insights: 

  - Malware type: trojan.zbot/heur2
  - The code is a VBScript designed to establish and maintain remote control over a compromised system. It employs an initial layer of obfuscation to hide its primary script content, which is deobfuscated during execution.

* The logs indicate that the user opened Chrome and downloaded ZIP archive from https:[]//files-ld.s3.us-east-2.amazonaws.com/Purchase_Order.zip (drive-by-download). Correlating this with email security logs (MX server), we can confirm that user david@letsdefend.io received a phishing email from support@gododdy.com (spoofing “GoDaddy”) containing a URL which downloads the malware.

  <img width="619" height="681" alt="Pasted image 20260117214813" src="https://github.com/user-attachments/assets/acba8087-db10-4754-80b7-e35e036de69e" />


* At 2023-04-20 09:42:06.918 we can see that C:\Windows\System32\wscript.exe executed the malware. Searching for SYSmon event 13, we are able to observe registry changes (set value, T1060) to HKU\S-1-5-21-3163960855-2866672989-1813526453-1008\Software\Microsoft\Windows\CurrentVersion\Run\Purchase_Order establishing persistence.

  <img width="846" height="539" alt="Pasted image 20260117220915" src="https://github.com/user-attachments/assets/4941c519-9b30-48c3-9bd2-feeaae3dcdde" />

* There are no indicators of other malicious activity such as credential access or privilege escalation.

### Eradication:

* The malicious email was removed from the inbox and sender blocked;
* The ZIP archive and .VBS executable removed from the host;
* The persistence entry removed from registry and startup items;
* Full EDR scan performed;
* The system was rebooted and checked for other persistence points - no other indicators of it (scheduled tasks, services, user accounts checked)

### Lessons learned:

Since the malicious ZIP file was delivered through a phishing email from the spoofed domain, we recommend the following:
* Improve URL rewriting, attachment sandboxing, and link reputation checks in the email gateway.
* Implement stronger filtering for typo‑squatted domains, especially those imitating well‑known service providers
* Improve on cyber security awareness training for the users via regular phishing simulations
* .vbs, .js, .hta, .ps1, and other script formats should not be allowed to run from user download folders.

### Key Entities and IOCs:

* Hostname: "David"
* Malicious file: C:\Users\LetsDefend\Downloads\Purchase_Order\Purchase_Order.xls.vbs 
* SHA256:(1C546A6548BEDA639640EBFBB52ABD5F6013C33500172CFCCF0E8716C96BB196)
* Source URL: https://files-ld.s3.us-east-2.amazonaws.com/Purchase_Order.zip
* Source IP: 172.16.17.31
