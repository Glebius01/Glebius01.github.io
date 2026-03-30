* toc
{:toc}

### Executive Summary

A targeted phishing campaign was identified within the organization, affecting three systems. A forensic triage image from one compromised host was analyzed to identify attacker tactics, techniques, and procedures (TTPs). The investigation revealed the use of a malicious document for initial access, execution of a staged payload, persistence via registry manipulation, lateral movement through RDP, and post-exploitation activity consistent with a Metasploit framework. The triage image was collected from one of the infected systems and provided for us for identification of TTPs being used by attackers.

### Q1 – Initial Access. Initial access was made through a malicious document delivered via email. What was the full path where the document was downloaded?

Accessing the partition using FTK Imager: FTK Imager >> File >> Add Evidence Item >> Image >> Filepath.ad1 (encountered an error in the LetsDefend environment—the files could not be exported, so I had to mount the image instead).

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/d3550e4f-71a0-4976-be5c-ad2c467b52bb" />

ShellBagsExplorer allows us to trace ShellBags, which are Windows registry artifacts that record user navigation preferences. They effectively remember how a user last viewed a particular folder, even after the folder is closed and reopened, ensuring that the same view settings are applied. This includes local drives, network shares and removable devices. 

We need to load an offline hive using it. Hive location: C:\users\cyberjunkie\appdata\local\microsoft\windows\usclass.dat

The hive is dirty, so we have to hold Shift when opening it. Afterwards, we can see that one of the visited directories is:
C:\Users\CyberJunkie\Downloads\MailDownloads

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/44008afe-965f-4b2e-9c7f-163d7e964ee0" />

### Q2 – Delivery. What's the document name? (The document which was delivered via phishing)

After we determine where the file was downloaded, we return to the mounted image to search for it. The aforementioned directory is not present in the image; however, there are .doc files in $Recycle.Bin that can't be opened, which prompts us to use the dedicated tool RBCmd.

File Security Awareness.docx was deleted on 2022-08-21 13:03:33. The other file has an unknown header 0x50 and remains known as $RWKWHDC.docx.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/122f4c4f-b26f-4e89-8ebb-a9578f7c93e0" />


### Q3 – Command and Control. What's the stager name which connected to the attacker C2 server (Fullpath\name)?

The hint says that SECURITY AWARENESS.docx was opened when a stager was downloaded and then the document was securely deleted, making it unrecoverable. This means that to answer this question, we have to use a tool that will show us process launch/execution.

To find the stager, we process all the prefetch files from the image and store the output in a convenient format such as .txt.

<img width="1000" height="124" alt="image" src="https://github.com/user-attachments/assets/0ea75edd-ab26-416f-82ef-21bcabd19391" />

Searching by date leads us straight to the executable SECURITYPATCH.EXE, created at the same time when SECURITY AWARENESS.docx was deleted. Searching by the filename, we can find its location on the Desktop, confirming the suspicion.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/4da07d7e-5680-45ef-ac42-e328ae556331" />

### Q4 – Defense Evasion. The attacker manipulated MACB timestamps of the stager executable to confuse analysts. Analyze the timestamps of the stager and verify the original and tampered timestamps. (ORIGINAL TIMESTAMP : TAMPERED TIMESTAMP)

We know the name of the stager file and its creation time—the information we need must be in the MFT record.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/dc6ed51e-1d49-4951-b385-ba22c063db74" />

$STANDARD_INFORMATION – information at user level: 2021-12-25 15:34:32
$FILE_NAME – information at kernel level: 2022-08-21 13:02:23.66

Thus, the answer (in the required format) is:
2022-08-21 13:02:23.66 : 2021-12-25 15:34:32

### Q5 – Persistence. The attacker set up persistence by manipulating registry keys. All we know is that the GlobalFlags Image File technique was used to establish persistence. When exiting a certain process, the attacker's persistence executable is executed. What's the name of that process?

From the question, we know the technique used and that registry keys were modified. This sounds like a job for RegistryExplorer.

Looking up about the technique we can get more details on its detection using MITR&ATTCK framework.

T1546.012
Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. 

IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\ 

We load the hive and search for "Microsoft\Windows NT\SilentProcessExit". I made a rookie mistake here - I used the search bar for SilentProcessExit, and because of this I was not able to see the subkey explorer.exe under it. A bit of research helped me realise the problem.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/9601d6c9-20a0-4b04-9428-e574f8f33838" />

### Q6. Persistence. What's the full path alongside the name of the executable which is set up for persistence? (FULLPATH\Filename)

We found it in the previous question: every time explorer.exe is closed, GetPatch.exe is executed.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/e2765cdb-10cb-4c32-bf2a-166057834196" />

### Q7 – Lateral Movement. The attacker logged in via RDP and then performed lateral movement. The attacker accessed an internal network-connected device via RDP. What command was run in cmd after successful RDP into the other Windows machine?

The Terminal Server Client cache stores bitmap images locally to improve Remote Desktop performance and reduce network bandwidth usage. Using bmc-tools.py, we can extract the cache and review those images as if they were a puzzle.

This way, we can find net localgroup execution.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/23fa5c33-6f96-468e-9eb4-664c9e004659" />

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/1b055625-5c1e-45cb-92bd-418228eaab93" />

### Q8 - Lateral Movemnet. The attacker tried to download a tool from the user's browser on that second machine. What's the tool name? (name.ext)

Same as in the previous question, we can see that the actor uploaded PowerView.ps1 on the target host.

### Q9 – Privilege Escalation. What command was executed which resulted in privilege escalation?

We can relatively quickly find the answer by utilizing another saved tool for us—DeepBlueCLI.

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/d734962f-2b05-4bdd-94f8-6530e8fc58fe" />

Answer: Blcmd.exe /c echo kyvckn > \\.\pipe\kyvckn

### Q10 – Command and Control / Actions on Objectives. What framework was used by the attacker?

DeepBlue recognises the command above as Metasploit-type.

### Key Takeaways:
- Initial compromise occurred via phishing with a malicious document
- Execution of a staged payload enabled C2 communication
- Persistence was established through registry-based IFEO abuse
- Lateral movement was performed using RDP
- Post-exploitation included PowerView usage and privilege escalation
- Indicators strongly align with Metasploit framework activity
