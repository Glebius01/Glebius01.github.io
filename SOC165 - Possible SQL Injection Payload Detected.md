  
Key Entities:

Hostname: WebServer1001
Destination IP Address: 172.16.17.18
Source IP Address: 167.99.169.17
HTTP Request Method: GET
Requested URL: https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
User-Agent : Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
Alert Trigger Reason: Requested URL Contains OR 1 = 1
Device Action: Allowed
**Primary user:** webadmin  
**Last login:** February 10, 2022, 11:12 PM

The alert was triggered on **February 25, 2022, at 11:34** upon detecting possible SQL injection. We start the investigation by verifying the alert and decoding the URL to confirm the type of attack.

**Decoded URL:**  
`https://172.16.17.18/search/?q=" OR 1 = 1 -- -`

We can observe that this is a classic Boolean‑based SQL injection, using an always‑true statement such as `1 = 1`. This type of query is commonly used to test for SQL injection vulnerabilities, as it forces the system to return more information than intended or bypass filters or authentication mechanisms.

The traffic originated from the external IP address **167.99.169.17** with malicious reputation and association with DigitalOcean LLC, Data Center based in the US. The target is the web server on the local network **172.16.17.18**. From the network logs, we can see **six GET requests** within **four minutes**, sent from source ports **48675** and **48577** to port **443** on the target server. The low frequency of the requests suggests they were sent manually.

The requests were permitted, but no data was returned to the malicious IP address according to the logs. Generally, to determine whether the attack was successful, we would need to analyze the size of the response packets.

**In summary**, we can confirm that this was an unsuccessful SQL injection attempt. Closing as such.

![[Pasted image 20260222114717.png]]