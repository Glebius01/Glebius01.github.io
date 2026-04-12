* TOC
{:toc}

### Part I. Preparation

First of all, we need to ensure that the environment for analysis is safe. I have created a Linux machine (Parrot Security 7.1 - Debian) using Oracle VirtualBox.

Then, it is neccessary to harden the VM box to prevent potential escape to the host:

1. Disabling shared clipboard and drag-and-drop features
2. Setting the network adapter to "Not attached" to isolate the machine
3. Ensuring there are no shared folders
4. Creating a snapshot of the VM to be able to roll back changes should there be a need

<img width="1280" height="800" alt="Pasted image 20260411182621" src="https://github.com/user-attachments/assets/ac9af986-7afe-4a86-913b-7afcf45f0a76" />

I'm going to start with a simple but top-quality crackme: [Kanax01's Fixed Easy Crackme](https://crackmes.one/crackme/698d2206e2ba6023bfacaa4f)

To move the crakme to the isolated machine, I'm going to create an ISO image of it, and mount it to the VM using ImgBurn. That allows us to safely analyse the crackme and is an absolute necessity for analysing real-world malware. After mounting, we should be able to find our executable image among "removable devices".

<img width="1280" height="800" alt="Pasted image 20260411183220" src="https://github.com/user-attachments/assets/10c847d5-6a6d-4226-9d86-e20131766d71" />

<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/1e2531bf-ed58-4d29-8ce9-9ef438ac1b90" />

### Part II. Reverse engineering.

1. We need to know what we're dealing with before touching it. Identifying the file type: `file "CrackMeEasy.exe"`

<img width="1280" height="800" alt="Screenshot_20260411_194747" src="https://github.com/user-attachments/assets/05973705-255e-4041-82de-7e220be43e72" />

2. Getting fingerprints to search for it on VirusTotal, ensure file integrity, and track the IOC in the environment: `sha256sum "CrackMeEasy.exe"`

<img width="1280" height="800" alt="image" src="https://github.com/user-attachments/assets/1dfa0a93-ec69-4b40-8d72-d110365d8b2c" />

3. It is common for malware to be compressed or obfuscated to make it more challenging to reverse engineer, avoid detection, or reduce size. The target file does not appear to be packed/obfuscated, so we may skip the use of the UPX tool to read the output.
4. String analysis allows us to see human-readable data such as passwords, messages, or function names that may expose key logic: `strings "EasyCrackMe.exe" > cracked.txt`

<img width="1280" height="800" alt="Screenshot_20260411_195114-1" src="https://github.com/user-attachments/assets/f31e13b8-8bc1-4c38-b029-232704134361" />

5. Should we want to create a YARA rule, we could utilise the YARA Gen tool to ingest the file's strings and obtain a detection rule searching for IOCs such as SHA256, MD5, IMPHASH, exports, etc., from the file. After creating the rule, we can review and modify it as necessary, adding more strings and conditions to enhance detection fidelity. This is out of scope of the challenge, but would likely be used when dealing with real malware.

6. Launching the disassembler Ghidra, creating a new project, loading the file, and running analysis on it. My current level of understanding of Assembly language isn't great, so we need to use the decompiled side of the screen.

<img width="1280" height="800" alt="Screenshot_20260411_195928" src="https://github.com/user-attachments/assets/a61517d8-1b3d-4782-80b3-3d3a4b7972fa" />

   We should search for the following functions: "Main", "Entry", "WinMain", "start". The search returns void entry; it is the usual "ignition switch" for 64-bit Windows applications to call some initialisation function to set up the C runtime before calling the real logic.
   
<img width="1280" height="800" alt="Screenshot_20260411_204748" src="https://github.com/user-attachments/assets/6dbf4350-0e43-4ef6-ab58-553a80163bdd" />

   Since the attempt above failed, we will search for strings in Ghidra instead. They are mapped to the function addresses, which will let us quickly find the "true" main page. `Search > For Strings`.
   
<img width="1280" height="800" alt="Screenshot_20260411_205919" src="https://github.com/user-attachments/assets/7796ca39-dbea-4c84-8fb2-830b38a5bde6" />
<img width="1280" height="800" alt="Screenshot_20260411_210752" src="https://github.com/user-attachments/assets/896cf85f-60c1-4cca-84db-f1316ac78350" />

   
   We can see the real logic, having analysing the code we can deduce that he application does the following:

* Prints a welcome message and asks for a password (input stored in buffer `local_38`)
* Reads user input using `cin`
* Compares the input to the stored password: `memcmp(puVar6, pcVar7, local_28)` where `pcVar7 = s_EasyPassword_1400050b8` is the hardcoded password in memory
* Also checks that the input length matches the expected length `local_28 == DAT_1400050c8`
* If correct, it prints: `"Congrats!! You cracked the code"`
* If wrong, it prints: `"Wrong Password, Please Try Again"`
* Waits for user input before exiting

<img width="1280" height="800" alt="Screenshot_20260411_211213" src="https://github.com/user-attachments/assets/92c0b8fb-7e0d-40b7-abbc-8831638ba7bc" />


The very first crackme done. More upcoming.
<p align="center">
  <img src="https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExdG01OXU2cjIxdHo2ZnN4a21weXcxbG91YnRlMXYydnZvOTgxbmVkeSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/DA8op0omzFuwe14iyj/giphy.gif"
       width="250"
       alt="funny cat gif">
</p>
