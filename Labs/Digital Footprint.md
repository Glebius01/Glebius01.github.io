---
layout: default
title: Digital Footprint
platform: TryHackMe
difficulty: Easy
skills:
- OSINT
description: "Beginner-friendly OSINT challenge investigating the digital footprint of a fictional company, ACME Jet Solutions. It involves critical thinking, metadata analysis, picture location searches, and general internet browsing."
---

## Summary: 

Beginner-friendly OSINT challenge investigating the digital footprint of a fictional company, ACME Jet Solutions. It involves critical thinking, metadata analysis, picture location searches, and general internet browsing.

## Walkthrough:

#### An ACME Jet Solutions employee uploaded a photo of a residential property believed to be linked to ACME Jet's early operations. Can you figure out where the picture was taken to confirm or debunk the rumour? 

In the picture, we see a street or building name and a yellow ADT sign with a phone number. Searching for ADT, we can find the business in South Africa. I tried to magnify the phone number to locate the branch, but I wasn't successful. Then, I thought it would be simpler to read the file's metadata instead, where I found the coordinates: 

Answer: Johannesburg

<img width="1451" height="670" alt="image" src="https://github.com/user-attachments/assets/6c43ff9f-b90c-479f-a875-9f55e50c7076" />

---
#### ACME Jet Solutions (warc-acme.com/jef/) is all over social media claiming they were founded in 2025 and that they are the fastest-growing data company in Africa. But something doesn't add up; one of their ex-employees assures you that the company existed long before that. Your job as an OSINT investigator is to verify their founding date using only public information.

We have the site name, and the easiest way to view its history is using [Archive.org](https://archive.org/details/warc-acme.com-jef).

Answer: 20160210224602 

<img width="1047" height="662" alt="image" src="https://github.com/user-attachments/assets/e93bba86-cccf-469f-a193-2b9f3d865f24" />

---
#### Further investigation uncovers another image believed to be connected to the company's international expansion. Research reveals that to the right of the iconic landmark is a building that played a big role in the fight for independence of a particular country. Signs on the external wall provide the name of the building. 

One of the banners in the picture says "Dublin" and "at the city ❤️". I searched for Dublin city center and found this [touristic article about the city center](https://theoldshelter.com/walk-oconnell-street-history-heart-dublin/).

<img width="1197" height="662" alt="image" src="https://github.com/user-attachments/assets/4bdef704-5b2e-4b99-9797-11683d858805" />

---

#### After uncovering ACME Jet Solutions' origins and tracing their online presence through archived websites and international landmarks, investigators believe that an internal document was accidentally leaked by one of the company's developers. The document may contain crucial information about the individual responsible for maintaining their systems.

For the next file to analyze, I started by reading the content to determine who sent what to whom. Next, by analyzing the file's metadata, we can find the sender's nickname. Searching for this nickname returned a YouTube channel where the same sender is expected to publish a video with more details on the updates. This is where I found the last flag for this challenge.

Answer: THM{Y0u_f0und_7h3_fin4l_fl4g!}

<img width="1910" height="1035" alt="image" src="https://github.com/user-attachments/assets/39ae71c1-c6dd-4dc6-a612-544c3cfb61d3" />

<img width="1095" height="848" alt="image" src="https://github.com/user-attachments/assets/f3d5af10-c170-4d87-a4fb-ef413a7a0b77" />

---
