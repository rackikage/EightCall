# Botnets

A **botnet** (short for "robot network") is a vast collection of internet-connected devices that have been infected with malware and are controlled centrally by an attacker, often called a "bot herder." The owners of these devices usually have no idea their hardware has been compromised.

Botnets rely heavily on the "weak vectors" common to opportunistic intrusion—particularly unpatched vulnerabilities and default passwords on internet-exposed infrastructure.

## How Botnets are Built and Controlled

The lifecycle of a botnet closely follows the Cyber Kill Chain, heavily emphasizing automation.

* **Mass Infection:** The attacker writes a script that constantly scans the public internet for vulnerable devices. In modern botnets, this often targets Internet of Things (IoT) devices like home routers, security cameras, and smart appliances because they are rarely patched and often use factory-default passwords.
* **Command and Control (C2):** Once infected, the malware silently reaches out to the attacker's C2 server. The device is now a "zombie" or "bot," awaiting instructions.
* **Peer-to-Peer (P2P) Architecture:** While older botnets used a single, centralized C2 server (which defenders could easily take down), modern botnets often use decentralized P2P networks. Each infected device passes instructions to its neighbors, making the botnet incredibly resilient to takedowns.

## What Attackers Use Botnets For

Once an attacker controls tens of thousands (or even millions) of devices, they harness that collective computing power and internet bandwidth for large-scale operations.

* **Distributed Denial of Service (DDoS):** The bot herder commands every infected device to send garbage data to a single target website or server simultaneously. The target's infrastructure is overwhelmed by the massive influx of traffic and goes offline.
* **Credential Stuffing:** Attackers take lists of usernames and passwords from previous data breaches and use the botnet to test those logins across banking, retail, and enterprise websites. Distributing the login attempts across thousands of different IP addresses prevents security systems from blocking a single IP for trying too many passwords.
* **Spam and Phishing Distribution:** Botnets are used to send massive volumes of spam and phishing emails. Because the emails originate from legitimate, albeit compromised, residential IP addresses, they often bypass traditional spam filters.
* **Cryptojacking:** The attacker secretly runs cryptocurrency mining software on the infected devices, stealing the victims' electricity and computing power to generate profit.

## A Real-World Example: Mirai

One of the most famous botnets, **Mirai** (discovered in 2016), didn't use complex zero-day exploits. Instead, it aggressively scanned the internet for IoT devices (primarily security cameras and routers) and attempted to log in using a hardcoded list of just 61 common factory-default usernames and passwords (like `admin`/`admin` or `root`/`password`).

Mirai successfully infected hundreds of thousands of devices and launched some of the largest DDoS attacks in history, temporarily crippling major portions of the internet's DNS infrastructure.
