---
layout: post
title:  Unpacking an Emotet trojan
categories: [Unpacking,Malware,RE,Emotet]
---

![Alt text](/images/unpacking-emotet-header.jpg "a title")

Emotet, in general, is a banking trojan. Identified in-the-wild for the first time in 2014 as a stealth info stealer (mainly targeting banking informations), emotet has evolved to a sofisticated trojan over the years; Now having funcionalities that goes from simply keylogging to self-spreading (as worms do).

The main campaign of the malware is through malspam. Using the "urgency" pretext, emotet make his victims by malicous documents with a macro embedded, malicious scripts or malicious links. Then, the pretext comes with subjects like: "Your Invoice", "Payment Details" or an upcoming shipment from well-known companies.

Emotet uses some tricks to evade and prevent his detection and analysis. The malware will check for common malware analysis tools (like IDA or Wireshark), check if it is running on a virtual environment and remain sleep, and every sample comes packed or encrypted.

Today we will be covering the unpacking of a sample from emotet family.

### Reconnaissance

```
sha256: 3a9494f66babc7deb43f65f9f28c44bd9bd4b3237031d80314ae7eb3526a4d8f
md5: ca06acd3e1cab1691a7670a5f23baef4
```

First, we need to know if the sample is definitely packed. Lets open it on DiE.