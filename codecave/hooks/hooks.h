#include "../framework.h"
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include "../minhook/MinHook.h"
#include <vector>
#include "../detours.h"
#include <winternl.h>
#include <fstream>
#include "keyauthhook.h"
#include <Urlmon.h>
#include <Shlwapi.h>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <Psapi.h>
#include <sstream>
#include <string>
#include <chrono>
#include <thread>
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
typedef PIMAGE_NT_HEADERS(NTAPI* RtlImageNtHeaderPtr)(PVOID);
typedef void* (*CurlEasyInitPtr)();
typedef NTSTATUS(NTAPI* Rtl_AdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
typedef NTSTATUS(NTAPI* Nt_SetInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength);
typedef BOOL(NTAPI* IsDebuggerPresent_t)(VOID);
typedef BOOL(WINAPI* BlockInputType)(BOOL);
typedef HANDLE(WINAPI* CreateToolhelp32SnapshotPtr)(DWORD, DWORD);
typedef BOOL(WINAPI* Process32FirstPtr)(HANDLE, LPPROCESSENTRY32);
typedef BOOL(WINAPI* Process32NextPtr)(HANDLE, LPPROCESSENTRY32);
typedef HWND(WINAPI* FindWindowAPtr)(LPCSTR lpClassName, LPCSTR lpWindowName);
typedef ATOM(WINAPI* GlobalAddAtomAPtr)(LPCSTR lpString);
typedef std::vector<unsigned char>(*DownloadFunc)(std::string);
typedef void(*ExitFunc)(int);
typedef HRESULT(WINAPI* URLDownloadAType)(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPVOID lpfnCB);
typedef BOOL(WINAPI* VirtualFreeFn)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
typedef int(WINAPI* MemcmpType)(const void* ptr1, const void* ptr2, size_t num);
typedef __int64(WINAPI* LoginType)(std::string AppId, std::string Key, std::string AppVersion);
using PIMAGE_DOS_HEADER = IMAGE_DOS_HEADER*;
using PIMAGE_NT_HEADERS64 = IMAGE_NT_HEADERS64*;
using GetNtHeadersFn = PIMAGE_NT_HEADERS64(*)(void*);
using License_t = void (KeyAuth::api::*)(std::string);
using CreateFileWFunc = HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
using RemoveFunc = void(*)(void*, void*, const void*);
typedef void(WINAPI* DebugBreakOriginal)(void);

typedef HANDLE(WINAPI* CreateThread_t)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    __drv_aliasesMem LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );

typedef BOOL(WINAPI* CreateProcessWType)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    );

typedef LPVOID(WINAPI* VirtualAllocExType)(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
    );

typedef BOOL(WINAPI* WriteProcessMemoryType)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
    );

typedef BOOL(WINAPI* SetThreadContextType)(
    HANDLE hThread,
    const CONTEXT* lpContext
    );

typedef HANDLE(WINAPI* CreateEventW_t)(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCWSTR               lpName
    );

typedef HANDLE(WINAPI* CreateThread_t)(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
    );
class hooking
{

public:
    DWORD g_victim_pid;
	void hookdebuggercheck();
	void HookCreateProcess();
	void HookBSOD();
	void HookInput();
    void hook_process_hollowing();
    void dump_dlls();
    void hookcurl();
    void hookfind();
    void hookatoms();
    void hook_keyauth_download();
    void hook_exit_function();
    void hook_url_download_A();
    void dump_drivers();
    void bypass_auth_engineering();
    void InstallHook();
    void hook_file_drop_remove();
    void debug_break();
    void threads();
}; static hooking* hooks = new hooking();
