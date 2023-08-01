# Mockingjay-POC

Ugly PoC for the Mockingjay injection technique (https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

The shellcode is a cmd/exec calc.

What this code does :

1. Find the offset of the RWX section in the hardcoded DLL
2. Find the size of the RWX section in the hardcoded DLL
3. Write Shellcode into the RWX section of the hardcoded DLL
4. Execute Shellcode from the RWX section of the hardcoded DLL


#### TODO
- Remove the hardcoded DLL path and getting it from a command line argument.
