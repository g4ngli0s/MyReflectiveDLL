// dllmain.cpp : Defines the entry point for the DLL application.


#include "ReflectiveLoader.h"
#include <stdio.h>
void PartyTime()
{
    MessageBox(0, (LPCSTR)"PartyTime", (LPCSTR)"PartyTime", MB_OK);
    return;
}

extern "C" HINSTANCE hAppInstance;
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_QUERY_HMODULE:
        if (lpReserved != NULL)
        {
            *(HMODULE*)lpReserved = hAppInstance;
        }
        break;
    case DLL_PROCESS_ATTACH:
        hAppInstance = hModule;
        if (lpReserved != NULL)
        {
            printf("Parameter passed to Reflective DLL: %s", (char*)lpReserved);
            //printf("Parameter passed to Reflective DLL: %d", lpReserved);
        }
        else
        {
            printf("No parameter passed to Reflective DLL");
        }
        PartyTime();
        fflush(stdout);
        ExitProcess(0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}