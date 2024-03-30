---
layout: post
title:  "Glupteba's .NET dropper deep dive."
categories: [.NET,Malware,RE,Glupteba]
excerpt: In this article, we will be analyzing Glupteba's first stage, where a executable is dropped and executed at disk from a decrypted .NET resource.
---

## Overview

Glubteba is a modular malware, meaning that it can deploy and executes a variety of independent code which implements different capabilities.

Its main category is a backdoor trojan, usually driven by a botnet operator. Known to steal user credentials and cookies, mine cryptocurrency on victims and deploying proxy components targeting Windows systems and IoT devices.

Its distribution is mainly through pay per install (PPI) networks and traffic distribution systems (TDS).

In this article, we will be analyzing its first stage, where a executable is dropped and executed at disk.
## Initial Analysis

```
sha256:e70dcf3f915087251224a7db3850669c000a6da68ef2b55e3e2eda196cb01fc3
```

The file is a 32-bit executable, written in .NET (v4.0.30319). There are only 3 sections: .text, .rsrc and .reloc and only one DLL import: mscoree.dll, which is common for .NET application (as well as the `_CorExeMain` API import). 

Checking for strings, the reader can soon see that there are plenty of meaningful strings.

```
antiSandbox
antiEmulator
DetectVirtualMachine
DetectSandboxie
CheckRemoteDebuggerPresent
DetectDebugger
CheckEmulator
isDebuggerPresent
enablePersistence
enableFakeError
encryptType
compressed
Decompress
EncryptOrDecryptXOR
EncryptInitializer
EncryptOutput
GetResource
RunOnStartup
WriteAllBytes
```

Those strings can give us some insights related to the malware's capabilities. The malware likely can detect sandboxes/debuggers/emulators, persist in the victim's machine, encrypt and decrypt with XOR, retrieve something from the resources and manipulate memory.

Also, They are great indicators of not the final payload, but a dropper instead.

To confirm it, the reader may have noticed a big chunk of apparently the same encrypted string. If we correlate that information with the capabilities listed before, we can assume that this file is actually a dropper, not the final payload. Furthermore, we can even figure out the general dropping procedure. It is possibly done by XORing this string, writing into some place in memory, then following with it's execution.

![](/images/glupteba/bigchunk.png)

> Notice the pattern being repeated in this chunk, it is likely caused by XOR encryption.

## Packer Analysis

As said before, the file is a 32-bit .NET executable.  Open it on dnSpy 32-bit and you'll soon see that the file is not obfuscated, making our analysis easier to accomplish. Before continuing to main, the reader needs to pay attention on a extremely important thing when analyzing .NET binaries, the class constructors.

Whenever a class or a struct is instantiated, it's constructor is invoked. The point here is that these constructors runs before the execution of the main method, class initializers and even the executable's entrypoint. Aware of that, there reader should always examine the `ctor()` / `cctor()` before the main method. 

And that's what happens in our binary, following the `Main` entrypoint of the program, we get to the `Program` class, which the reader will see it contains almost all the dropper's procedure, but if looked closer, there is a `cctor()`, which initializer a bunch of lists, paths and variables.

![](/images/glupteba/cctor.png)

Analyzing this constructor, we can see that it sets various flags to false, the field `encryptType` to "XORIAIZCNIWw", `cvers` to "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" (when decoded from base 64) and four lists: the first being for the `fileNames`, the second fot `fileTypes`, third for `fileRunTypes` and the last one for `fileDropPaths` (ledaing us to believe that the dropped payload will be at the %TEMP% directory).

![](/images/glupteba/cctor_init.png)

Now the reader can proceed to the `Main` function at `Program` class, or in other words, the binary's entrypoint. 

It firsts perform a kind o environmental keying, in which there are four functions which tries to detect if the binary is currently being executed inside a controlled or sandboxed environment.

The first subroutine, `Anti.DetectVirtualMachine`, executes a WMI query `Select * from Win32_ComputerSystem`, which is a [WMI class](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-computersystem) that represents the computer system running Windows. Then, based on the `Manufacturer` field, it checks whether the machine's manufacturer is equal to "microsoft corporation" AND the machine's model contains "VIRTUAL" OR the machine's manufacturer is equal to "vmware" OR the machine's model is equal to "VirtualBox". If so, the subroutine returns `true`.

![](/images/glupteba/detect_vm.png)

Next, at `Anti.Sandboxie`, the dropper simply tries to retrieve a handle to `SbielDll.dll`, which is a common [DLL](https://sandboxie-plus.github.io/sandboxie-docs/Content/SBIEDLLAPI.html) present on the "Sandboxie" project, "a sandbox-based isolation software for Windows that lets you try and run untrusted applications" - [Sandboxie's website](https://sandboxie-plus.github.io/sandboxie-docs/). If it is not equal to 0, the return value will be `true`.

![](/images/glupteba/sandboxie.png)

Following, the next check is at `Anti.DetectDebugger`, which employs the use of the API `CheckRemoteDebuggerPresent`.

Intrinsically, `CheckRemoteDebuggerPresent` calls `NtQueryInformationProcess` with the parameter `0x7`, which translates to `ProcessDebugPort`. Then, if the process is being debugged, a DWORD with the value equals to 0xFFFFFFFF (-1) will be returned.

![](/images/glupteba/detect_dbg.png)

The last check is made by `Anti.CheckEmulator`.  This subroutine makes a comparison in how much time the binary took to accomplish the call to `Sleep(10)`, which, in case of emulation, it will be slightly more than 10L.

![](/images/glupteba/detect_emulator.png)

In case of checks being satisfied, the dropper will delay it's execution by the value set earlier in the `cctor()` for `delayTime` times(\*) 1000. But in our case, it was set to 0 (as well as every other flag that enable the previous anti-analysis checks). 

![](/images/glupteba/sleep.png)

Next, if `enablePersistence` flag is set, `RunOnStartup` is called. This routine is pretty simple, it gets the application domain's friendly name, or in other words, the executable's name and appends an ".exe" to it. Then it checks if the executables exists in the specified `AppPath` (arg2), if not, it copy's itself to that location. If `Hide` (arg3) is `true`, it sets the "Hidden" attribute for that specific file, which permits the file to not be included in an ordinary directory listing.

Next, it tries to open previous set `cvers` constant, but as a subkey at "LocalMachine" registry path. After opened, it sets a key of `regName` (arg1) with the value of the combined `AppPath`. 

Finally, it tries the same procedure above, but for "CurrentUser" registry path.

![](/images/glupteba/regkey.png)

Subsequently to it, the dropping phase starts. For each one of the file names listed at `fileNames` list (initialized in the `cctor()`), the dropper sets `text` to the current iteration's `fileNames`, `text2` to the current iteration's `fileTypes`, `text3` to `fileRunTypes` and `text4` to `fileDropPaths`.

Next, it calls `GetResource` to get the resource inside the current iteration's `fileNames` and stores it into an array.

`GetResource` subroutine retrieves the named resource "e3cgcd4b2oq" in `Assembly.GetExecutiongAssembly()`, which references the assembly that contains the code that is currently executing. Returning an object for it.

![](/images/glupteba/getrsrc.png)

After retrieving the resource, it checks if the `compressed` flag is enabled. If so, calls `Decompress`.

This subroutine opens two memory streams of type `MemoryStream()`, deflate the former (which contains our compressed resource) and copy it to the latter. Then, returns the copied memory stream in the form of an array.

![](/images/glupteba/memstream.png)

Following, the dropper checks which one of the encryption types was set. If `encryptType` is equal to "AwkCZdaodw", `Decrypt` routine is called. If it's equal to "XORIAIZCNIWw", `EncryptOrDecryptXOR` is called.

> Both of them uses "mjsqrfk0ee4" as key.

The `Decrypt` routine returns the result of `EncryptOutput` in the form of an array.

Moving on, `EncryptOutput` is basically RC4. It firsts calls `EncryptInitialize`, which performs a identity permutation on the array `array`, then it executes the RC4's KSA, returning the scrambled array `array`.

Returning to `EncryptOutput`, The RC4's PRGA phase is executed, XORing our keystream with each byte from `data` (arg2).

![](/images/glupteba/rc4.png)

The `EncryptOrDecryptXOR` routine is much more simpler. It will XOR each byte of the resource with each byte of the key, rotating around the key bytes.

![](/images/glupteba/xor.png)

After the resource gets decrypted, the dropper will combine the %TEMP% (`fileDropPaths`) with `text` + `text2` (`fileNames` + `fileTypes`). Then, `Execute` is called for this binary.

If `runType` is "Run Always", this function starts the decrypted binary and returns, if it is "Run Once" it do not returns.

Returning means that, at the end of execution, the `flag` variable will be assigned to `enableFakeError`. This assignment employs the following screen, which tries to confuses both the victim and the analyst.

![](/images/glupteba/fakeerror.png)

## Extracting the payload

To extract the final payload, the reader should put a breakpoint on line 67, at `WriteAllBytes` call. Then, in the "Locals" tab, save the content of `array`. This can be done by the following:

![](/images/glupteba/extraction.png)

Giving us as result:

![](/images/glupteba/extracted.png)

We can further analyze the dropped executable, but it will be a subject for another article (As I'm focusing on .NET for this one).

And that's it for today, hope you enjoyed and learnt something from this article. Thank you!

![](/images/glupteba/pink.gif)