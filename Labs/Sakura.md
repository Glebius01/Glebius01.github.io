## TIP-OFF

The OSINT Dojo recently found themselves the victim of a cyber attack. It seems that there is no major damage, and there does not appear to be any other significant indicators of compromise on any of our systems. However during forensic analysis our admins found an image left behind by the cybercriminals. Perhaps it contains some clues that could allow us to determine who the attackers were?

We've copied the image left by the attacker, you can view it in your browser here.

#### What username does the attacker go by?

Used this tool https://exif.tools/ to read picture's metadata, found the username in directory path: 

Answer: SakuraSnowAngelAiko

<img width="1447" height="263" alt="image" src="https://github.com/user-attachments/assets/d751b680-6096-4f7e-a953-d5cf868e3195" />

Searching the nickname on Google I found Github account (https://github.com/sakurasnowangelaiko), Twitter account (https://x.com/sakuraloveraiko?lang=en), and Lead Contact page (https://leadcontact.ai/en/contact/sakurasnowangelaiko).

On his Github among cryptominers there is left a PGP public key. The key usually has metadata related to the registrar. It can be decrypted using John the Ripper (offline) or if private key is known via Cyber Chef functions. I managed to find this tool https://cirw.in/gpg-decoder/ which easily decrypt User ID Packet (0xd) for me.

<img width="1114" height="200" alt="image" src="https://github.com/user-attachments/assets/1c64b18d-183a-48d4-930a-a02137bd7390" />

To validate whether the email is valid, we can send a test email. If it's delivered - it's working.

#### What is the full email address used by the attacker?

Answer: SakuraSnowAngel83@protonmail.com

#### What is the attacker's full real name?

Answer: Aiko Abe

## UNVEIL

It seems the cybercriminal is aware that we are on to them. As we were investigating into their Github account we observed indicators that the account owner had already begun editing and deleting information in order to throw us off their trail. It is likely that they were removing this information because it contained some sort of data that would add to our investigation. Perhaps there is a way to retrieve the original information that they provided?

#### What cryptocurrency does the attacker own a cryptocurrency wallet for?

Found a hint that the wallet is in Ethereum in one his Github repositories: "stratum://ethwallet.workerid:password@miningpool:port".

Answer: Ethereum
<img width="1914" height="470" alt="image" src="https://github.com/user-attachments/assets/246a90b1-c7d2-4bbc-a8b0-fce27a091b7b" />

#### What is the attacker's cryptocurrency wallet address?

I checked all comits on the repository and the initial commit contained sensitive data such as password and the wallet address.

Answer: 0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef
<img width="1917" height="823" alt="image" src="https://github.com/user-attachments/assets/813724d9-5e33-46e9-bf1b-e454d924ca1f" />

#### What mining pool did the attacker receive payments from on January 23, 2021 UTC?

A mining pool address is the server URL (commonly using the Stratum protocol) that your ASIC miner or mining software connects to in order to submit hashing work and shares. In the 2nd commit we can see a structure, that pool name is after @ and before port. Thus, we can conclude that the pool is ethermine.

Answer: ethermine

#### What other cryptocurrency did the attacker exchange with using their cryptocurrency wallet?

Using tools such as https://etherscan.io/txs?a=0xa102397dbeeBeFD8cD2F73A89122fCdB53abB6ef, we can see transaction history for the wallet. Having scrolled thourgh them I could see few transactions into Tether Stablecoin.

Answer: Tether
<img width="1704" height="564" alt="image" src="https://github.com/user-attachments/assets/f9a8e752-8979-4208-8e6e-124f05467097" />

## TAUNT

Just as we thought, the cybercriminal is fully aware that we are gathering information about them after their attack. They were even so brazen as to message the OSINT Dojo on Twitter and taunt us for our efforts. The Twitter account which they used appears to use a different username than what we were previously tracking, maybe there is some additional information we can locate to get an idea of where they are heading to next?

We've taken a screenshot of the message sent to us by the attacker, you can view it in your browser here (https://raw.githubusercontent.com/OsintDojo/public/main/taunt.png).

#### What is the attacker's current Twitter handle?

Answer: @SakuraLoverAiko

#### What is the BSSID for the attacker's Home WiFi?

Scrolling down his Twitter (X) page we can find this comment talking about a paste site (online text-sharing platforms). The words DEEP and PASTE are capitalised and from the screenshot we can see MD5 and some sort of a site being used.

<img width="765" height="407" alt="image" src="https://github.com/user-attachments/assets/b84a8fc8-29d4-486b-8ac4-bba1db78b3a6" />

Having browsed around in the internet, I discover that this site was accessible only from .onion and is now outdated/removed from the internet. Regardless, I can find the network name from other people 

<img width="1196" height="1015" alt="image" src="https://github.com/user-attachments/assets/011a33d8-a248-4b4b-b1b3-f6caf63e6203" />

Now I search for his home network name on website https://wigle.net/ and it helps me to geolocate his BSSID.

Anwer: 84:AF:EC:34:FC:F8

## Homebound

Based on their tweets, it appears our cybercriminal is indeed heading home as they claimed. Their Twitter account seems to have plenty of photos which should allow us to piece together their route back home. If we follow the trail of breadcrumbs they left behind, we should be able to track their movements from one location to the next back all the way to their final destination. Once we can identify their final stops, we can identify which law enforcement organization we should forward our findings to.

#### What airport is closest to the location the attacker shared a photo from prior to getting on their flight?

Searching this beautiful picture using Google lens we can discover that it was taken in Arlington, Virginia. The closest airport there is Ronald Reagan Washington National Airport (DCA)

Answer: DCA

<img width="1907" height="1083" alt="image" src="https://github.com/user-attachments/assets/0d4eefcb-23fe-49a8-8d4e-8960270e5e77" />

#### What airport did the attacker have their last layover in?

Likewise we search for the next picture, we can see that this lounge room in Tokyo Haneda airport.

Answer: HND

<img width="1900" height="1082" alt="image" src="https://github.com/user-attachments/assets/3c316bcf-4871-41ab-95ad-f7047789ab23" />

#### What lake can be seen in the map shared by the attacker as they were on their final flight home?

Answer: Lake Inawashiro

<img width="1893" height="1007" alt="image" src="https://github.com/user-attachments/assets/a16f8028-7fc8-4326-b6ef-18a3d8264d67" />

#### What city does the attacker likely consider "home"?

Previously on the paste site we could see that Aiko saved Hirosaki free ciy WiFi there, and given that Aiko was flying Northbound from Tokyo, we can deduce that the destination is Hirosaki. 

Answer: Hirosaki
