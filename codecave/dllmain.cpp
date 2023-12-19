#include "framework.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "minhook/MinHook.h"
#include <vector>
#include "detours.h"
#include <winternl.h>
#include "menu/Menu.h"
#include <thread>
void entry()
{
   hooks->g_victim_pid = GetCurrentProcessId();
   SetConsoleTitleA("codecave injected");
   CreateThread(nullptr, 0, RenderThread, nullptr, 0, nullptr);
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:       
        DisableThreadLibraryCalls(hModule);
        entry();
        break;
    }
    return TRUE;
}
