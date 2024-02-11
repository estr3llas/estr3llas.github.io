---
layout: post
title:  Unpacking an Emotet trojan
categories: [Unpacking,Malware,RE,Emotet]
excerpt: Emotet, in general, is a banking trojan. Identified in-the-wild for the first time in 2014 as a stealth info stealer (mainly targeting banking informations), emotet has evolved to a sofisticated trojan over the years; Now having funcionalities that goes from simply keylogging to self-spreading (as worms do).
---

![header image](/images/unpacking-emotet/unpacking-emotet-header.jpg "just a header")

Emotet, in general, is a banking trojan. Identified in-the-wild for the first time in 2014 as a stealth info stealer (mainly targeting banking informations), emotet has evolved to a sofisticated trojan over the years; Now having funcionalities that goes from simply keylogging to self-spreading (as worms do).

The main campaign of the malware is through malspam. Using the "urgency" pretext, emotet make his victims by malicous documents with a macro embedded, malicious scripts or malicious links. Then, the pretext comes with subjects like: "Your Invoice", "Payment Details" or an upcoming shipment from well-known companies.

Emotet uses some tricks to evade and prevent his detection and analysis. The malware will check for common malware analysis tools (like IDA or Wireshark), check if it is running on a virtual environment and remain sleep, and every sample comes packed or encrypted.

Today we will be covering the unpacking of a sample from emotet family.

# Reconnaissance

```
sha256: 3a9494f66babc7deb43f65f9f28c44bd9bd4b3237031d80314ae7eb3526a4d8f
md5: ca06acd3e1cab1691a7670a5f23baef4
```

First, we need to know if the sample is definitely packed. Lets open it on DiE.

![](./images/unpacking-emotet/unpacking-emotet-die.png)

We can see that it is a 32-bit binary, made in C/C++ and having a certificate stored in the overlay section (WinAuth(2.0))

Looking at the entropy, we see that the binary has 89% chance of being packed.

![](/images/unpacking-emotet/unpacking-emotet-entropy.png)

We can confirm it by looking at the sample on IDA.

![](/images/unpacking-emotet/unpacking-emotet-idaconfirm.png)

IDA shows some indicators of packing, like:

- Lack of subroutines on a malware this sofisticated.
- Lack of internet-related APIs
- Main (start) function seems small and doesn't have any WindowsAPI or indirect calls.

But, we can have the proof of it by looking into common packing APIs:

- CreateProcessInternalW()
- VirtualAlloc()
- VirtualAllocEx()
- VirtualProtect() / ZwProtectVirtualMemory()
- WriteProcessMemory() / NtWriteProcessMemory()
- ResumeThread() / NtResumeThread()
- CryptDecrypt() / RtlDecompressBuffer()
- NtCreateSection() + MapViewOfSection() / ZwMapViewOfSection()
- UnmapViewOfSection() / ZwUnmapViewOfSection()
- NtWriteVirtualMemory()
- NtReadVirtualMemor

Searching for VirtualAlloc(), we will soon find the subroutine that probably is the responsible for unpacking the malware.

![](/images/unpacking-emotet/unpacking-emotet-valloc.png)

Now it gets a little bit more complicated. The red box marks an "abnormal epilogue". An "abnormal epilogue" occurs when we have some pushes into the stack and not a single pop before it returns.

> You can notice that ds:VirtualAlloc is being moved into ecx, then ecx is pushed onto the stack and the return is called, meaning the call of VirtualAlloc().

After calling ecx (VirtualAlloc), the return will execute the second push from the stack (osffset loc_417d9a), executing whatever is present on the second block, and then the real return will come.

![](/images/unpacking-emotet/unpacking-emotet-sub_41d50.png)

Normally, after the code finishes the unpack, we will have a indirect call to it.

![](/images/unpacking-emotet/unpacking-emotet-jmpecx.png)

We can confirm it by looking at the end of the main function, which has an "jmp ecx".

Again, take notes of the address. 0x00417F1F.

# Unpacking

So we got two addresses to set breakpoints in:

```
0x00417E3F
0x00417F1F
```

We can open it on x64dbg, search for those addresses (Ctrl+G), and then set the breakpoints.

![jmpex](/images/unpacking-emotet/unpacking-emotet-breakpoints.png)