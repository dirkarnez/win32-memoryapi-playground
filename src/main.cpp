#include <Windows.h>
#include <iostream>

int main()
{
    unsigned char shellcode[] = {
        0xB8, 0x09, 0x00, 0x00, 0x00, // mov eax, 9
        0xC3                          // ret
    };

    // Allocate executable memory
    LPVOID allocatedMemory = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (allocatedMemory == NULL)
    {
        // Handle allocation failure
        return 1;
    }

    // Copy shellcode to allocated memory
    memcpy(allocatedMemory, shellcode, sizeof(shellcode));

    // Execute shellcode
    typedef int (*ShellcodeFunction)();
    ShellcodeFunction shellcodeFunction = (ShellcodeFunction)allocatedMemory;
    
    std::cout << "Hello World!" << std::endl;
    int result = shellcodeFunction();
    std::cout << "Returned: " << result << std::endl;
    std::cout << "Hello World!" << std::endl;

    // Free the allocated memory
    VirtualFree(allocatedMemory, 0, MEM_RELEASE);

    return 0;
}
