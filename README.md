# Mockingjay-POC

Here's my PoC for the Mockingjay injection technique (https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

> I'm learning C++ so my code is far from perfect but I tried to do the best I could.

Right now it supports only the self-injection technique but remote injection technique is planned.
It works in 2 steps :
1. Using the [`RWXfinder`](https://github.com/Darktortue/Mockingjay-POC/tree/master/RWXfinder) tool you can find vulnerable DLLs with a RWX section present and waiting for you :)
2. Once this is done, fire up the `Mockingjay-POC.exe` program by specifying your XOR key and the path to the DLL you choose based on the choice given by the *RWXfinder* tool.

This code will :
- Get the XOR key and the DLL path as cmdline arguments
- Give info about the RWX section
- Compare the size of the shellcode and the RWX section. If shellcode is bigger, program will exit
- If size is ok, inject XOR'd shellcode in RWX section
- Decrypt the XOR shellcode
- Execute shellcode

### Usage
```ps1
PS C:\Users\admin\source\repos\Mockingjay-POC\x64\Release> .\Mockingjay-POC.exe

MOCKINGJAY SUPER ASCII ART

[!] Error: Please provide the XOR key and the path to the DLL as a positional argument.

Usage: C:\Users\admin\source\repos\Mockingjay-POC\x64\Release\Mockingjay-POC.exe MY_XOR_KEY PATH_TO_DLL
```

*RWXfinder* output example :
![screen1](https://github.com/Darktortue/Mockingjay-POC/assets/11302315/94b8bcfc-2d1a-44c0-9646-39f98cdaad92)

*Mockingjay-POC* output example :
![screen2](https://github.com/Darktortue/Mockingjay-POC/assets/11302315/baca8a97-7fb6-4519-869c-f7a150a649ba)



#### TODO
- Fix THREAD mess. Right now, i'm waiting 3 seconds before closing the main thread / program because I don't know how to do it properly for shellcodes such as reverse shells/beacons. For simples shellcodes such as `windows/x64/exec CMD="calc.exe"` you can replace `WaitForSingleObject(hThread, 3000)` by some clean stuff such as `Infinite`.
