# AWS Bucketware — Writeup

An attacker used compromised AWS credentials to establish persistence within a cloud environment and propagate large-scale phishing campaigns. In this challenge, as an Incident Responder, you’ll analyze the various steps taken by the attacker to achieve persistence and set up the staging for phishing campaigns from the compromised environment.

*Inspired by a real-world scenario of actual cloud malware.*

Having followed the lab instructions on how to unzip and inflate the archive, the first problem I encountered was readability. There are 24 JSON files in the folder; opening them one by one to look for artifacts is a nightmare. Thankfully, using the command ```jq . *.json > analysis.json```, I could format and save all of these logs into one single file.

<img width="1906" height="1006" alt="download" src="https://github.com/user-attachments/assets/84aa9d7b-53a9-42e4-98f7-d1bec9203151" />

---

### Q1 – Compromised Identity: What is the compromised identity?

Scrolling through the log, we can see that the user `s3user` attempted to perform an unauthorized action: `ListServiceQuotas`. This triggered my suspicion, and by looking up the user using Ctrl+F in the file, I could see attempts to run `ListServiceUsers`, `CreateUser` (for `adm1n` and `dev0ps_user`), and other calls.

Answer: **`s3user`**

<img width="1904" height="519" alt="download (5)" src="https://github.com/user-attachments/assets/c6fd848a-ad07-4ebe-86aa-e3ef0a0028be" />



---

### Q2 – Reconnaissance: In order of occurrence, what were the last three reconnaissance API calls the attacker performed using the compromised credentials?

Since we know the compromised user, we can filter by "s3user" and look for calls typically used for reconnaissance. I asked AI to kindly assist with the right query:

```
jq -r '.Records[] | select(.userIdentity.userName == "s3user") | "\(.eventTime) — \(.eventName)"' analysis.json | sort
```

<img width="1910" height="344" alt="download (2)" src="https://github.com/user-attachments/assets/db6acfc8-57dc-4d9d-9489-87725874deac" />

In chronological order, these three match the question criteria:

* **`GetBucketVersioning`**: The attacker was checking if object versioning was turned on (reconnaissance to see if their modifications could be easily reversed).
* **`ListObjects`**: The attacker enumerated the contents of the bucket to find files of interest.
* **`GetObject`**: The attacker read/downloaded the file (the platform classifies this as part of their data-gathering visibility).

---

### Q3 – Reconnaissance: What was the first successful reconnaissance API call?

Modifying the query to see only successful calls where there is no error:

```
jq -r '.Records[] | select(.userIdentity.userName == "s3user" and .errorCode == null) | "\(.eventTime) — \(.eventName)"' analysis.json | sort
```
<img width="1910" height="421" alt="download (3)" src="https://github.com/user-attachments/assets/e3ed5c05-368e-4770-a6e0-99352883ed53" />

Getting the answer: **`ListBuckets`**

---

### Q4 – Persistence: How did the attacker attempt to maintain persistence within the environment?

Previously, when we were only searching for the compromised user, we were able to see attempts to create other accounts. Thus, we can conclude that this was an attempt to establish persistence.

---

### Q5 – Persistence: In order of occurrence, which IAM users were involved in this persistence attempt?

It was enough to search for the `CreateUser` attempts in the log and correlate the timestamps to get the answer.

Answer: **`adm1n`**, **`rooter`**, and **`dev0ps_user`**

---

### Q6 – Persistence: Were the persistence attempts successful?

None of the `CreateUser` calls were completed successfully.

---

### Q7 – Targeted Resource: Which S3 bucket was affected in this attack?

Scrolling down to the failed `CreateUser` calls, we can see a successful `GetBucketVersioning` call and the target bucket among the key entities in the logs:

```json
"eventTime": "2023-04-25T16:03:02Z",
"eventSource": "s3.amazonaws.com",
"eventName": "GetBucketVersioning",
"awsRegion": "us-east-1",
"sourceIPAddress": "159.48.53.157",
"userAgent": "[aws-cli/2.2.27 Python/3.8.8 Darwin/22.2.0 exe/x86_64 prompt/off command/s3api.get-bucket-versioning]",
"requestParameters": {
  "bucketName": "webrew-dev-backup",
  "Host": "webrew-dev-backup.s3.us-east-1.amazonaws.com"
}

```
<img width="1839" height="721" alt="download (4)" src="https://github.com/user-attachments/assets/34911b89-b035-4e95-82a9-8a76b1b95c73" />

Answer: **`webrew-dev-backup`**

---

### Q8 – Defense Evasion / Reconnaissance: How did the attacker check for protection on this resource?

In AWS S3, Bucket Versioning is a safety feature that keeps multiple variants of an object in the same bucket. If you overwrite or delete a file, versioning allows you to retrieve the older versions.

Thus, we may infer that `GetBucketVersioning` was run as a reconnaissance step. They wanted to see if their malicious actions (like altering files or deploying ransomware) could be easily undone by an administrator restoring an older version.

---

### Q9 – Defense Evasion: How did the attacker remove the protection on this resource?

And consequently, they used **`PutBucketVersioning`** to suspend that safety feature. Once suspended, they could delete or encrypt files without AWS creating safety backups.

---

### Q10 – Data Exfiltration: What file did the attacker exfiltrate?

Knowing the source IP of the threat actor, we can utilize another advanced query to see calls that involve file movement, such as `GetObject`:

```
jq -r '.Records[] | select(.sourceIPAddress == "159.48.53.157") | "\(.eventTime) — \(.eventName) — File: \(.requestParameters.key // "N/A")"' analysis.json | sort
```

Indeed, having executed the command, we can see the list of calls, among which was a `GetObject` action.

Answer: **`highprofilecoffeeorders.csv`**

---

### Q11 – Impact: What was the name of the ransom note?

The threat actor apparently wanted us to find the note, so they called it simply **`ransomenote.txt`**.

---

### Key Takeaways:

* **Initial Compromise:** Threat actor gained access via a compromised IAM user (`s3user`).
* **Log Aggregation:** Streamlined the parsing of 24 disjointed CloudTrail logs into one analysis file using `jq`.
* **Failed Persistence:** Identified a backdooring campaign where the attacker attempted (and failed) to provision three new IAM accounts (`adm1n`, `rooter`, `dev0ps_user`).
* **Defensive Evasion:** Tracked the attacker's active suspension of S3 Bucket Versioning (`PutBucketVersioning`) on the target backup asset to ensure data destruction would be permanent.
* **Exfiltration & Impact:** Map-constructed data movement tied to the attacker's primary external IP (`159.48.53.157`), identifying data theft of a CSV database asset followed by a ransomware notification placement.
