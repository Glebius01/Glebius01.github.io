What username does the attacker go by?

Used this tool https://exif.tools/ to read picture's metadata, found the username in directory path: 

Answer:
SakuraSnowAngelAiko
<img width="1447" height="263" alt="image" src="https://github.com/user-attachments/assets/d751b680-6096-4f7e-a953-d5cf868e3195" />


Searching the nickname on Google I found Github account (https://github.com/sakurasnowangelaiko), Twitter account (https://x.com/sakuraloveraiko?lang=en), and Lead Contact page (https://leadcontact.ai/en/contact/sakurasnowangelaiko).

On his Github among cryptominers there is left PGP public key. The key usually has metadata related to the registrar. It can be decrypted using John the Ripper (offline) or if private key is known via Cyber Chef functions. I managed to find this tool https://cirw.in/gpg-decoder/ which easily decrypt User ID Packet (0xd)
for me.
<img width="1114" height="200" alt="image" src="https://github.com/user-attachments/assets/1c64b18d-183a-48d4-930a-a02137bd7390" />

To validate whether the email is valid, we can send a test email. If it's delivered - it's working.

What is the full email address used by the attacker?
Correct Answer
What is the attacker's full real name?
Aiko Abe

What cryptocurrency does the attacker own a cryptocurrency wallet for?

Found a hint that the wallet is in Ethereum in one his Github repositories.
"stratum://ethwallet.workerid:password@miningpool:port".
<img width="1914" height="470" alt="image" src="https://github.com/user-attachments/assets/246a90b1-c7d2-4bbc-a8b0-fce27a091b7b" />


What is the attacker's cryptocurrency wallet address?

I checked all comits on the repository and the initial commit contained sensitive data such as password and the wallet address.

Answer: 0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef
<img width="1917" height="823" alt="image" src="https://github.com/user-attachments/assets/813724d9-5e33-46e9-bf1b-e454d924ca1f" />

A mining pool address is the server URL (commonly using the Stratum protocol) that your ASIC miner or mining software connects to in order to submit hashing work and shares. In the 2nd commit we can see a structure, that pool name is after @ and before port. Thus, we can conclude that the pool is ethermine.

Answer: ethermine

What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet?

Using tools such as https://etherscan.io/txs?a=0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef, we can see transaction history for the wallet. Having scrolled thourgh them I could see few transactions into Tether Stablecoin.

Answer: Tether
<img width="1704" height="564" alt="image" src="https://github.com/user-attachments/assets/f9a8e752-8979-4208-8e6e-124f05467097" />



