#include "hooks.h"
#include <Psapi.h>
#include "../lazy.h"

CreateThread_t pOriginalCreateThread = nullptr;

BlockInputType OriginalBlockInput = nullptr;
Rtl_AdjustPrivilege OriginalRtlAdjustPrivilege = nullptr;
Nt_SetInformationProcess OriginalNtSetInformationProcess = nullptr;
IsDebuggerPresent_t OriginalDebuggerPresent;

CreateProcessWType OriginalCreateProcessW = nullptr;
VirtualAllocExType OriginalVirtualAllocEx = nullptr;
WriteProcessMemoryType OriginalWriteProcessMemory = nullptr;
SetThreadContextType OriginalSetThreadContext = nullptr;

RtlImageNtHeaderPtr pOriginalRtlImageNtHeader = nullptr;
CurlEasyInitPtr pOriginalCurlEasyInit = nullptr;
CreateToolhelp32SnapshotPtr pOriginalCreateToolhelp32Snapshot = nullptr;
Process32FirstPtr pOriginalProcess32First = nullptr;
Process32NextPtr pOriginalProcess32Next = nullptr;
GlobalAddAtomAPtr pOriginalGlobalAddAtomA = nullptr;
FindWindowAPtr pOriginalFindWindowA = nullptr;
DownloadFunc pOriginalDownload = nullptr;
ExitFunc pOriginalExit = nullptr;
URLDownloadAType originalURLDownloadA = nullptr;
VirtualFreeFn OriginalVirtualFree = nullptr;
GetNtHeadersFn OriginalGetNtHeaders = nullptr;
MemcmpType originalMemcmp = nullptr;
LoginType originalLogin = nullptr;
License_t OriginalLicense = nullptr;
CreateFileWFunc OriginalCreateFileW = nullptr;
RemoveFunc OriginalRemove = nullptr;
DebugBreakOriginal pDebugBreak = nullptr;

CreateEventW_t pOriginalCreateEventW = nullptr;


LoadLibraryA_t originalLoadLibraryA = LoadLibraryA;
LoadLibraryW_t originalLoadLibraryW = LoadLibraryW;
LoadLibraryExA_t originalLoadLibraryExA = LoadLibraryExA;
LoadLibraryExW_t originalLoadLibraryExW = LoadLibraryExW;

std::string g_LastLoadedDLL;
template <typename ForwardIt, typename T>
ForwardIt RemoveWrapper(ForwardIt first, ForwardIt last, const T& value) {
    return std::remove(first, last, value);
}
void DetourLicense(KeyAuth::api* instance, std::string arg){
    // i gave up on this as i was too lazy
    MessageBoxA(NULL, "Detoured License Function", "Detour Message", MB_OK);
}
void hooking::InstallHook() {
    if (MH_Initialize() != MH_OK) {
        MessageBoxA(NULL, "Failed to initialize Minhook", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Get the address of the original function
    OriginalLicense = &KeyAuth::api::license;

    if (!OriginalLicense)
    {
        MessageBoxA(NULL, "Failed to Find Address", "Error", MB_OK | MB_ICONERROR);

    }
    // Create the hook
    if (MH_CreateHook(reinterpret_cast<LPVOID>(&OriginalLicense), &DetourLicense, reinterpret_cast<LPVOID*>(&OriginalLicense)) != MH_OK) {
        MessageBoxA(NULL, "Failed to create hook", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    // Enable the hook
    if (MH_EnableHook(reinterpret_cast<LPVOID*>(&OriginalLicense)) != MH_OK) {
        MessageBoxA(NULL, "Failed to enable hook", "Error", MB_OK | MB_ICONERROR);
        return;
    }

    MessageBoxA(NULL, "Hook successfully set up", "Success", MB_OK);

    // not used
}



HANDLE WINAPI DetourCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID)
{
    // do wtv u want but i turned it off

    return FALSE;
}

BOOL WINAPI DetourProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    // do wtv u want but i turned it off

    return FALSE;
}

BOOL WINAPI DetourProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe)
{
    // do wtv u want but i turned it off

    return FALSE;
}
HWND WINAPI DetourFindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName)
{
    // do wtv u want but i turned it off

    return FALSE;
}

NTSTATUS NTAPI DetouredRtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled)
{
   
    
      return STATUS_INVALID_PARAMETER;
    

    NTSTATUS status = STATUS_SUCCESS;
    __try
    {
        status = OriginalRtlAdjustPrivilege(Privilege, Enable, CurrentThread, Enabled);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        status = STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status))
    {
    }

    return status;
}

NTSTATUS NTAPI DetouredNtSetInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength)
{
 
    return STATUS_SUCCESS;
}

BOOL DetouredIsDebuggerPresent(void) {

    return FALSE;
}
int WINAPI DetouredMemcmp(const void* ptr1, const void* ptr2, size_t num) {
    return 1;
}
BOOL WINAPI DetouredBlockInput(BOOL fBlockIt)
{
   
    return FALSE;
}
ATOM WINAPI DetourGlobalAddAtomA(LPCSTR lpString)
{
    MessageBoxA(NULL, lpString, "ATOM ADDED - CODE CAVE HOOK", MB_OK);

    ATOM result = pOriginalGlobalAddAtomA(lpString);

    return result;
}

typedef BOOL(WINAPI* CreateProcessType)(
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

CreateProcessType OriginalCreateProcess = nullptr;

BOOL WINAPI DetouredCreateProcess(
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
)
{
    if (lpCommandLine != nullptr)
    {
        int result = MessageBoxW(NULL, lpCommandLine, L"Allow Command? - CodeCave-Hook", MB_YESNO | MB_ICONQUESTION);

        if (result == IDYES) {
            

            int size = WideCharToMultiByte(CP_UTF8, 0, lpCommandLine, -1, nullptr, 0, nullptr, nullptr);
            if (size > 0)
            {
                std::string commandString(size, '\0');
                WideCharToMultiByte(CP_UTF8, 0, lpCommandLine, -1, &commandString[0], size, nullptr, nullptr);

                std::ofstream outFile("dumped_commands.txt", std::ios::app);

                if (outFile.is_open())
                {
                    outFile << "Command: " << commandString << std::endl;

                    outFile.close();
                }
                return OriginalCreateProcess(lpApplicationName, lpCommandLine, lpProcessAttributes,
                    lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
                    lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
            }

            MessageBoxW(NULL, L"Command Executed.", L"CodeCave-Hook", MB_OK | MB_ICONINFORMATION);
        }
        else {
           
        }
    }

    return TRUE;
}

const wchar_t* droppedFilePath = L"C:\\seemo.exe";

#include <string>

BOOL WINAPI DetouredCreateProcessW(
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
)
{
    MessageBoxW(NULL, L"CreateProcessW hooked!", L"code cave hook", MB_OK | MB_ICONINFORMATION);



    std::wstring messageBoxText = L"Process Information:\n";
    messageBoxText += L"Application Name: " + std::wstring(lpApplicationName ? lpApplicationName : L"<nullptr>") + L"\n";
    messageBoxText += L"Command Line: " + std::wstring(lpCommandLine ? lpCommandLine : L"<nullptr>") + L"\n";
    messageBoxText += L"Current Directory: " + std::wstring(lpCurrentDirectory ? lpCurrentDirectory : L"<nullptr>") + L"\n";
    messageBoxText += L"\nCreated Process ID: " + std::to_wstring(lpProcessInformation->dwProcessId) + L"\n";
    messageBoxText += L"Created Thread ID: " + std::to_wstring(lpProcessInformation->dwThreadId);

    MessageBoxW(NULL, messageBoxText.c_str(), L"code cave hook", MB_OK | MB_ICONINFORMATION);
 
        wchar_t executablePath[MAX_PATH];
        DWORD pathSize = GetModuleFileNameEx(lpProcessInformation->hProcess, nullptr, reinterpret_cast<LPSTR>(executablePath), MAX_PATH);

        if (pathSize > 0)
        {
            std::ifstream inputFile(executablePath, std::ios::binary);

            if (inputFile.is_open())
            {
                std::wofstream outputFile(droppedFilePath, std::ios::binary);

                if (outputFile.is_open())
                {
                    outputFile << inputFile.rdbuf();
                    outputFile.close();
                    std::wcout << L"Executable dropped to disk: " << droppedFilePath << std::endl;
                }
                else
                {
                    std::cerr << "Failed to create output file." << std::endl;
                }

                inputFile.close();
            }
            else
            {
                std::cerr << "Failed to open input file." << std::endl;
            }
        }
        else
        {
            std::cerr << "Failed to get the path of the executable." << std::endl;
        }

        auto result = OriginalCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
            bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
        return result;
}
BOOL WINAPI DetourVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
    // Dump the DLL image to disk before freeing memory
    if (dwFreeType == MEM_RELEASE) {
        HMODULE dll_image = GetModuleHandle(NULL);
        const wchar_t* wDumpPath = L"DumpedDLL.dll";
        
        HANDLE hFile = CreateFileW(wDumpPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD dwBytesWritten;
            WriteFile(hFile, reinterpret_cast<void*>(dll_image), dwSize, &dwBytesWritten, NULL);
            CloseHandle(hFile);
        }
    }

    return OriginalVirtualFree(lpAddress, dwSize, dwFreeType);
}
HRESULT WINAPI DetouredURLDownloadA(LPUNKNOWN pCaller, LPCSTR szURL, LPCSTR szFileName, DWORD dwReserved, LPVOID lpfnCB)
{
    char exeName[MAX_PATH];
    GetModuleFileNameA(NULL, exeName, MAX_PATH);
    PathRemoveFileSpecA(exeName);
    std::string folderPath = std::string("C:\\") + PathFindFileNameA(exeName);

    if (!CreateDirectoryA(folderPath.c_str(), NULL) && ERROR_ALREADY_EXISTS != GetLastError())
    {
        MessageBoxA(NULL, "Failed to create directory.", "Error", MB_ICONERROR);
        return E_FAIL;
    }

    std::string destinationFilePath = folderPath + "\\" + PathFindFileNameA(szFileName);

    MessageBoxA(NULL, ("Downloading file from " + std::string(szURL) + " to " + destinationFilePath).c_str(), "Downloading", MB_OK);

    originalURLDownloadA = reinterpret_cast<URLDownloadAType>(GetProcAddress(GetModuleHandleA("urlmon.dll"), "URLDownloadA"));
    if (!originalURLDownloadA)
    {
        MessageBoxA(NULL, "Failed to get the address of URLDownloadA.", "Error", MB_ICONERROR);
        return E_FAIL;
    } 

    HRESULT result = originalURLDownloadA(pCaller, szURL, destinationFilePath.c_str(), dwReserved, lpfnCB);

    if (FAILED(result))
    {
        MessageBoxA(NULL, ("URLDownloadA failed with error code: " + std::to_string(result)).c_str(), "Error", MB_ICONERROR);
        return result;
    }

    MessageBoxA(NULL, "Download successful!", "Success", MB_OK);

    return result;
}

LPVOID WINAPI DetouredVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
)
{
    std::wcout << L"VirtualAllocEx hooked!" << std::endl;


    auto result = OriginalVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);


    std::wstring messageBoxText = L"VirtualAllocEx Information:\n";
    messageBoxText += L"Process Handle: " + std::to_wstring(reinterpret_cast<std::uintptr_t>(hProcess)) + L"\n";
    messageBoxText += L"Requested Address: " + std::to_wstring(reinterpret_cast<std::uintptr_t>(lpAddress)) + L"\n";
    messageBoxText += L"Size: " + std::to_wstring(dwSize) + L"\n";
    messageBoxText += L"Allocation Type: " + std::to_wstring(flAllocationType) + L"\n";
    messageBoxText += L"Protection: " + std::to_wstring(flProtect) + L"\n";
    messageBoxText += L"\nAllocated Memory: " + std::to_wstring(reinterpret_cast<std::uintptr_t>(result));

    MessageBoxW(NULL, messageBoxText.c_str(), L"VirtualAllocEx Information", MB_OK | MB_ICONINFORMATION);

    return result;
}
void HookedExit(int code)
{
    MessageBoxA(NULL, "exit call bypassed", "codecave hook", MB_OK);
}

std::vector<unsigned char> DetouredDownload(std::string fileid) {
    MessageBoxA(NULL, "DetouredDownload called!", "Detour", MB_OK);
        
    return pOriginalDownload(fileid);
}

PIMAGE_NT_HEADERS NTAPI DetourRtlImageNtHeader(PVOID Base)
{
    void* dll_image = Base;

    std::ofstream dllFile("C:\\dumped.dll", std::ios::binary | std::ios::out);
    if (dllFile.is_open())
    {
        dllFile.write(reinterpret_cast<const char*>(&dll_image), sizeof(dll_image));
        dllFile.close();
    }

    PIMAGE_NT_HEADERS result = pOriginalRtlImageNtHeader(Base);

    return result;
}
void* MyCurlEasyInit()
{
    MessageBoxA(NULL, "curl hooked", "codecave-hook", MB_OK);
    return FALSE;
}
__int64 WINAPI DetouredLogin(std::string AppId, std::string Key, std::string AppVersion) {
    MessageBoxA(NULL, "Login function was called!", "Detour Notification", MB_OK);
    return false;
}
BOOL WINAPI DetouredWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
)
{
    std::ofstream outputFile("C:\\File.exe", std::ios::binary | std::ios::app);

    if (outputFile.is_open()) {
        outputFile.write(reinterpret_cast<const char*>(lpBuffer), nSize);
        outputFile.close();

    }
    else {
        std::wcerr << L"Failed to open the file for writing." << std::endl;
        return FALSE; 
    }

    std::wcout << L"WriteProcessMemory hooked!" << std::endl;

    std::wcout << L"Process Handle: " << hProcess << std::endl;
    DWORD processId = GetProcessId(hProcess);

    std::wcout << L"lpBaseAddress: " << lpBaseAddress << std::endl;
    std::wcout << L"Buffer Size: " << nSize << std::endl;

    std::wstring messageBoxText = L"WriteProcessMemory Information:\n";
    messageBoxText += L"PID: " + std::to_wstring(processId) + L"\n";
    messageBoxText += L"Process Handle: " + std::to_wstring(reinterpret_cast<std::uintptr_t>(hProcess)) + L"\n";
    messageBoxText += L"lpBaseAddress: " + std::to_wstring(reinterpret_cast<std::uintptr_t>(lpBaseAddress)) + L"\n";
    messageBoxText += L"Buffer Size: " + std::to_wstring(nSize) + L"\n";

    MessageBoxW(NULL, messageBoxText.c_str(), L"WriteProcessMemory Information", MB_OK | MB_ICONINFORMATION);

    return OriginalWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

}
PIMAGE_NT_HEADERS64 DetourGetNtHeaders(void* image_base) {
    
    std::ofstream outfile("codecave_dump.sys", std::ios::binary);
    if (outfile.is_open()) {
        outfile.write(reinterpret_cast<char*>(image_base), sizeof(IMAGE_NT_HEADERS64));
        outfile.close();
    }

    return OriginalGetNtHeaders(image_base);
}
void WINAPI MyDebugBreak(void) {
    MessageBoxA(NULL, "DebugBreak Hooked", "Detour", MB_OK);

}
HANDLE WINAPI MyCreateEventW(
    LPSECURITY_ATTRIBUTES lpEventAttributes,
    BOOL                  bManualReset,
    BOOL                  bInitialState,
    LPCWSTR               lpName
)
{
  
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI MyCreateThread(
    LPSECURITY_ATTRIBUTES   lpThreadAttributes,
    SIZE_T                  dwStackSize,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    DWORD                   dwCreationFlags,
    LPDWORD                 lpThreadId
)
{
    
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI DetourCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{

    if (GetCurrentProcessId() == hooks->g_victim_pid)
    {
        std::wstring fileName(lpFileName);
        size_t dotPos = fileName.find_last_of(L".");
        if (dotPos != std::wstring::npos)
        {
            std::wstring extension = fileName.substr(dotPos + 1);

            // Check if the file extension is .sys, .exe, or .dll
            if (extension == L"sys" || extension == L"exe" || extension == L"dll")
            {
                // Display a MessageBox only for the specified file types
                MessageBoxW(NULL, lpFileName, L"File Dropping Detected, Grabbing file. - codecave hook", MB_OK);

                // Create a folder named "dumps" with the current date and time
                std::wstringstream ss;
                auto now = std::chrono::system_clock::now();
                std::time_t timeNow = std::chrono::system_clock::to_time_t(now);
                ss << L"dumps_" << std::put_time(std::localtime(&timeNow), L"%Y%m%d_%H%M%S");
                std::wstring dumpsFolder = ss.str();
                CreateDirectoryW(dumpsFolder.c_str(), NULL);

                // Construct the full path for the copied file
                std::wstring destPath = dumpsFolder + L"\\" + PathFindFileNameW(lpFileName);

                // Copy the file to the dumps folder
                CopyFileW(lpFileName, destPath.c_str(), FALSE);
            }
        }
    }

    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI DetouredSetThreadContext(
    HANDLE hThread,
    const CONTEXT* lpContext
)
{
    std::wcout << L"SetThreadContext hooked!" << std::endl;

    BOOL result = OriginalSetThreadContext(hThread, lpContext);

    if (result)
    {
        std::wcout << L"SetThreadContext succeeded!" << std::endl;
    }
    else
    {
        DWORD error = GetLastError();
        std::wcerr << L"SetThreadContext failed with error code " << error << L"." << std::endl;
    }

    return result;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {

    DWORD processID;
    GetWindowThreadProcessId(GetForegroundWindow(), &processID);

    if (processID) {

        std::ifstream file(lpLibFileName, std::ios::binary);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            g_LastLoadedDLL = buffer.str();
        }
        std::ofstream outputFile("Codecave_Dumped.dll", std::ios::binary);

        if (outputFile.is_open()) {
            outputFile << g_LastLoadedDLL;
            outputFile.close();
        }
        else {
            // Handle file open error
           // MessageBoxA(NULL, "Failed to open file for writing", "Error", MB_OK);
        }
    }
    return originalLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {

    DWORD processID;
    GetWindowThreadProcessId(GetForegroundWindow(), &processID);

    if (processID) {

        std::ifstream file(lpLibFileName, std::ios::binary);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            g_LastLoadedDLL = buffer.str();
        }
        std::ofstream outputFile(L"Codecave_Dumped.dll", std::ios::binary);

        if (outputFile.is_open()) {
            outputFile << g_LastLoadedDLL;
            outputFile.close();
        }
        else {
          
        }
    }
    return originalLoadLibraryW(lpLibFileName);
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {

    DWORD processID;
    GetWindowThreadProcessId(GetForegroundWindow(), &processID);

    if (processID) {

        std::ifstream file(lpLibFileName, std::ios::binary);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            g_LastLoadedDLL = buffer.str();
        }
        std::ofstream outputFile("Codecave_Dumped.dll", std::ios::binary);

        if (outputFile.is_open()) {
            outputFile << g_LastLoadedDLL;
            outputFile.close();
        }
        else {
        }
    }
    return originalLoadLibraryExA(lpLibFileName, hFile, dwFlags);
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {

    DWORD processID;
    GetWindowThreadProcessId(GetForegroundWindow(), &processID);

    if (processID) {

        std::ifstream file(lpLibFileName, std::ios::binary);
        if (file) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            g_LastLoadedDLL = buffer.str();
        }
        std::ofstream outputFile(L"Codecave_Dumped.dll", std::ios::binary);

        if (outputFile.is_open()) {
            outputFile << g_LastLoadedDLL;
            outputFile.close();
        }
        else {
        }
    }
    return originalLoadLibraryExW(lpLibFileName, hFile, dwFlags);
}
void hooking::hookdebuggercheck()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalDebuggerPresent = (IsDebuggerPresent_t)DetourFindFunction("kernel32.dll", "IsDebuggerPresent");
    MessageBoxA(NULL, "Hooked Debugger Checks", "codecave-hook", MB_OK);
    DetourAttach(&(PVOID&)OriginalDebuggerPresent, DetouredIsDebuggerPresent);
    DetourTransactionCommit();
    MessageBoxA(NULL, "Hooked Applied, ANTI ANTI DEBUGGER ENABLED", "codecave-hook", MB_OK);
}

void hooking::HookCreateProcess()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalCreateProcess = (CreateProcessType)DetourFindFunction("kernel32.dll", "CreateProcessW");
    DetourAttach(&(PVOID&)OriginalCreateProcess, DetouredCreateProcess);
    DetourTransactionCommit();
}

void hooking::HookBSOD()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalRtlAdjustPrivilege = (Rtl_AdjustPrivilege)DetourFindFunction("ntdll.dll", "RtlAdjustPrivilege");
    DetourAttach(&(PVOID&)OriginalRtlAdjustPrivilege, DetouredRtlAdjustPrivilege);
    MessageBoxA(NULL, "Hooked RtlAdjustPrivilege", "codecave-hook", MB_OK);
    OriginalNtSetInformationProcess = (Nt_SetInformationProcess)DetourFindFunction("ntdll.dll", "NtSetInformationProcess");
    DetourAttach(&(PVOID&)OriginalNtSetInformationProcess, DetouredNtSetInformationProcess);
    MessageBoxA(NULL, "Hooked NtSetInformationProcess", "codecave-hook", MB_OK);
    DetourTransactionCommit();
    MessageBoxA(NULL, "Hooked Applied, ANTI BSOD ENABLED", "codecave-hook", MB_OK);
}

void hooking::HookInput()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalBlockInput = (BlockInputType)DetourFindFunction("user32.dll", "BlockInput");
    DetourAttach(&(PVOID&)OriginalBlockInput, DetouredBlockInput);
    DetourTransactionCommit();
}

void hooking::hook_process_hollowing()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalVirtualAllocEx = reinterpret_cast<VirtualAllocExType>(DetourFindFunction("kernel32.dll", "VirtualAllocEx"));
    DetourAttach(&(PVOID&)OriginalVirtualAllocEx, DetouredVirtualAllocEx);
    OriginalWriteProcessMemory = reinterpret_cast<WriteProcessMemoryType>(DetourFindFunction("kernel32.dll", "WriteProcessMemory"));
    DetourAttach(&(PVOID&)OriginalWriteProcessMemory, DetouredWriteProcessMemory);
    OriginalSetThreadContext = reinterpret_cast<SetThreadContextType>(DetourFindFunction("kernel32.dll", "SetThreadContext"));
    DetourAttach(&(PVOID&)OriginalSetThreadContext, DetouredSetThreadContext);
    DetourTransactionCommit();
}

void hooking::dump_dlls()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOriginalRtlImageNtHeader, DetourRtlImageNtHeader);
    DetourAttach(&(PVOID&)OriginalVirtualFree, DetourVirtualFree);
    DetourTransactionCommit();
}

void hooking::hookcurl()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    HMODULE hCurlModule = GetModuleHandle(NULL); // Adjust the library name accordinglyA
    pOriginalCurlEasyInit = reinterpret_cast<CurlEasyInitPtr>(GetProcAddress(hCurlModule, "curl_easy_init"));
    DetourAttach(reinterpret_cast<PVOID*>(&pOriginalCurlEasyInit), MyCurlEasyInit);
    DetourTransactionCommit();
}

void hooking::hookfind()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    MessageBoxA(NULL, "Hooking Protection", "codecave-hook", MB_OK);
    pOriginalCreateToolhelp32Snapshot = reinterpret_cast<CreateToolhelp32SnapshotPtr>(DetourFindFunction("kernel32.dll", "CreateToolhelp32Snapshot"));
    pOriginalProcess32First = reinterpret_cast<Process32FirstPtr>(DetourFindFunction("kernel32.dll", "Process32First"));
    pOriginalProcess32Next = reinterpret_cast<Process32NextPtr>(DetourFindFunction("kernel32.dll", "Process32Next"));
    pOriginalFindWindowA = reinterpret_cast<FindWindowAPtr>(DetourFindFunction("user32.dll", "FindWindowA"));
    DetourAttach(&(PVOID&)pOriginalCreateToolhelp32Snapshot, DetourCreateToolhelp32Snapshot);
    DetourAttach(&(PVOID&)pOriginalProcess32First, DetourProcess32First);
    DetourAttach(&(PVOID&)pOriginalProcess32Next, DetourProcess32Next);
    DetourAttach(&(PVOID&)pOriginalFindWindowA, DetourFindWindowA);
    MessageBoxA(NULL, "Hooked Applied, Disabled all PC Searching", "codecave-hook", MB_OK);
    DetourTransactionCommit();
}

void hooking::hookatoms()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    pOriginalGlobalAddAtomA = reinterpret_cast<GlobalAddAtomAPtr>(DetourFindFunction("kernel32.dll", "GlobalAddAtomA"));
    DetourAttach(&(PVOID&)pOriginalGlobalAddAtomA, DetourGlobalAddAtomA);
    DetourTransactionCommit();
}

void hooking::hook_keyauth_download()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    LPBYTE pTarget = (LPBYTE)GetProcAddress(GetModuleHandle(NULL), "download");
    pOriginalDownload = (DownloadFunc)pTarget;
    if (DetourAttach((PVOID*)&pTarget, DetouredDownload) != NO_ERROR) {

        auto error = GetLastError();
        char errorMessage[256];  

        sprintf_s(errorMessage, "Failed to detour download function! Error code: %lu", error);

        MessageBoxA(NULL, errorMessage, "Error", MB_ICONERROR);
        return;
    }
    DetourTransactionCommit();
}
void hooking::hook_exit_function()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    pOriginalExit = reinterpret_cast<ExitFunc>(DetourFindFunction("msvcrt.dll", "exit"));
    DetourAttach(&(PVOID&)pOriginalExit, &HookedExit);
    DetourTransactionCommit();
}

void hooking::hook_url_download_A()
{
    HMODULE hUrlmon = GetModuleHandleA("urlmon.dll");
    if (hUrlmon)
    {
        if (originalURLDownloadA)
        {
            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)originalURLDownloadA, DetouredURLDownloadA);
            DetourTransactionCommit();
        }
        else
        {
            MessageBoxA(NULL, "Failed to get the address of URLDownloadA.", "Error", MB_ICONERROR);
            return;
        }
    }
}

void hooking::dump_drivers()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalGetNtHeaders = reinterpret_cast<GetNtHeadersFn>(GetProcAddress(GetModuleHandle("codecave_victim.exe"), "GetNtHeaders"));
     
    if (!OriginalGetNtHeaders)
    {
        MessageBoxA(NULL, "Failed to get the address of OriginalGetNtHeaders.", "Error", MB_ICONERROR);
    }
    DetourAttach(&(PVOID&)OriginalGetNtHeaders, DetourGetNtHeaders);
    DetourTransactionCommit();
}

void hooking::bypass_auth_engineering()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    originalLogin = reinterpret_cast<LoginType>(DetourFindFunction("Auth.dll", "Login"));
    DetourAttach(&(PVOID&)originalLogin, DetouredLogin);
    originalMemcmp = reinterpret_cast<MemcmpType>(DetourFindFunction("msvcrt.dll", "memcmp"));
    DetourAttach(&(PVOID&)originalMemcmp, DetouredMemcmp);
    DetourTransactionCommit();
}


void hooking::hook_file_drop_remove()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    OriginalCreateFileW = reinterpret_cast<CreateFileWFunc>(GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateFileW"));
    if (!OriginalCreateFileW) {
        MessageBoxA(NULL, "Failed to get the address of OriginalCreateFileW.", "Error", MB_ICONERROR);
    }
    DetourAttach(&(PVOID&)OriginalCreateFileW, DetourCreateFileW);
    DetourTransactionCommit();
}

void hooking::debug_break()
{
    pDebugBreak = DebugBreak;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pDebugBreak, MyDebugBreak);
    DetourTransactionCommit();
}
void hooking::threads()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOriginalCreateEventW, MyCreateEventW);
    DetourAttach(&(PVOID&)pOriginalCreateThread, MyCreateThread);
    DetourTransactionCommit();
}
void hooking::LoadLibrary_hook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(reinterpret_cast<PVOID*>(&originalLoadLibraryA), HookedLoadLibraryA);
    DetourAttach(reinterpret_cast<PVOID*>(&originalLoadLibraryW), HookedLoadLibraryW);
    DetourAttach(reinterpret_cast<PVOID*>(&originalLoadLibraryExA), HookedLoadLibraryExA);
    DetourAttach(reinterpret_cast<PVOID*>(&originalLoadLibraryExW), HookedLoadLibraryExW);
    DetourTransactionCommit();
}
