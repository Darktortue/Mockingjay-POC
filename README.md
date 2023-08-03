# Mockingjay-POC

Ugly PoC for the Mockingjay injection technique (https://www.securityjoes.com/post/process-mockingjay-echoing-rwx-in-userland-to-achieve-code-execution).

What this code does :

1. Find the offset of the RWX section in the hardcoded DLL
2. Find the size of the RWX section in the hardcoded DLL
3. Write Shellcode into the RWX section of the hardcoded DLL
4. Execute Shellcode from the RWX section of the hardcoded DLL


#### TODO
- Remove the hardcoded DLL path and get it from a command line argument
- Create a seperate THREAD to execute the shellcode
- Create 2 parts of the code :
	- 1st part will be to scan a given directory (and its subdirectories) to find RWX section in DLLs. Then it will compare the size of the RWX sections found and compare them to the size of the shellcode. Finally, it will output the DLL that have a RWX section big enough for the hardcoded shellcode.
	- 2nd part will be to perform the injection process by providing the path of DLL as an argument
