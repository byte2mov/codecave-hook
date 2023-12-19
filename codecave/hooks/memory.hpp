#include "hooks.h"
class Config {
public:
    nlohmann::json data;

    void LoadConfig(const std::string& filename) {
        std::ifstream file(filename);
        if (file.is_open()) {
            file >> data;
            file.close();
        }
    }

    void SaveConfig(const std::string& filename) const {
        std::ofstream file(filename);
        if (file.is_open()) {
            file << std::setw(4) << data << std::endl;
            file.close();
        }
    }

    nlohmann::json GetPreset(const std::string& name) const {
        return data.value(name, nlohmann::json::object());
    }

    void SetPreset(const std::string& name, const nlohmann::json& presetData) {
        data[name] = presetData;
    }
};   static Config* config = new Config();
typedef struct _RFW_UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} RFW_UNICODE_STRING, * PRFW_UNICODE_STRING;

typedef const RFW_UNICODE_STRING* PCRFW_UNICODE_STRING;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;


typedef struct _RTL_BALANCED_NODE
{
    union
    {
        struct _RTL_BALANCED_NODE* Children[2];
        struct
        {
            struct _RTL_BALANCED_NODE* Left;
            struct _RTL_BALANCED_NODE* Right;
        } s;
    };
    union
    {
        UCHAR Red : 1;
        UCHAR Balance : 2;
        ULONG_PTR ParentValue;
    } u;
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;


typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;
typedef struct _RFW_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    RFW_UNICODE_STRING FullDllName;
    RFW_UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        } s;
    } u;
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; 
} RFW_LDR_DATA_TABLE_ENTRY, * RFW_PLDR_DATA_TABLE_ENTRY;


class memory
{

public:

    struct ThreadInfo
    {
        DWORD id;
        float cpuUsage;
        float ioUsage;
    };
    std::vector<ThreadInfo> threads;
    int GetInstructionLength(DWORD_PTR address) {
       
        const int bufferSize = 15;
        unsigned char buffer[bufferSize];

        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), buffer, bufferSize, nullptr)) {
            return -1;
        }

        int length = 0;
        while (length < bufferSize && buffer[length] != 0xC3) {  
            length++;
        }

        return length;
    }
    char* PatternScan(const char* pattern, const char* mask, char* begin, intptr_t size)
    {
        intptr_t patternLen = strlen(mask);

        for (int i = 0; i < size; i++)
        {
            bool found = true;
            for (int j = 0; j < patternLen; j++)
            {
                if (mask[j] != '?' && pattern[j] != *(char*)((intptr_t)begin + i + j))
                {
                    found = false;
                    break;
                }
            }
            if (found)
            {
                return (begin + i);
            }
        }
        return nullptr;
    }
    DWORD_PTR GetModuleBase(const char* moduleName) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());

        if (snapshot == INVALID_HANDLE_VALUE) {
            MessageBoxA(NULL, "Failed to create toolhelp snapshot", "codecave-hooker", MB_OK | MB_ICONERROR);
            return 0;
        }

        DWORD_PTR baseAddress = 0;
        while (Module32Next(snapshot, &moduleEntry)) {
            if (_stricmp(moduleEntry.szModule, moduleName) == 0) {
                baseAddress = reinterpret_cast<DWORD_PTR>(moduleEntry.modBaseAddr);
                break;
            }
        }

        CloseHandle(snapshot);

        return baseAddress;
    }
    void KillThread(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_TERMINATE, FALSE, threadId);
        if (hThread != NULL)
        {
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
        }
    }
    void SuspendThread_mem(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread != NULL)
        {
            SuspendThread(hThread);
            CloseHandle(hThread);
        }
    }
    void ResumeThread_mem(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (hThread != NULL)
        {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }
 

    bool NopMemory(DWORD_PTR address) 
    {
        DWORD oldProtect;

        size_t size = GetInstructionLength(address);


        if (size <= 0) {
            MessageBoxA(NULL, "Invalid instruction length", "codecave-hooker", MB_ICONERROR | MB_OK);
            return false;
        }
       
        if (VirtualProtect(reinterpret_cast<void*>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memset(reinterpret_cast<void*>(address), 0x90, size);
            VirtualProtect(reinterpret_cast<void*>(address), size, oldProtect, &oldProtect);
            return true;  
        }
        else {
            DWORD error = GetLastError();
            char errorMessage[256];
            sprintf_s(errorMessage, sizeof(errorMessage), "Failed to NOP memory at 0x%lX. Error code: %lu", address, error);
            MessageBoxA(NULL, errorMessage, "Error", MB_ICONERROR | MB_OK);
            return false; 
        }
    }

    size_t CalculateSizeFromRVAs(DWORD_PTR startRVA, DWORD_PTR endRVA) {
        if (endRVA < startRVA) {
            return 0;
        }

        return static_cast<size_t>(endRVA - startRVA);
    }
    bool switchinstruction(MODULEENTRY32 moduleEntry, DWORD_PTR rva)
    {
        DWORD_PTR address = reinterpret_cast<DWORD_PTR>(moduleEntry.modBaseAddr) + rva;

        const int buffer = 15;
        unsigned char bufferw[buffer];

        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), bufferw, buffer, nullptr))
        {
            MessageBoxA(NULL, "FAILED MEM", "bp", MB_OK);
        }

        auto JNE = 0x75;
        auto JE = 0x74;

        if (bufferw[0] == JNE) {

            DWORD old_prot;
            if (VirtualProtect(reinterpret_cast<void*>(address), 1, PAGE_EXECUTE_READWRITE, &old_prot)) {
                bufferw[0] = JE;
                VirtualProtect(reinterpret_cast<void*>(address), 1, old_prot, &old_prot);
                return true;
            }
        }
        return false;
    }
    void Patch(char* dst, char* src, int size)
    {
        DWORD oldprotect;
        VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldprotect);
        memcpy(dst, src, size);
        VirtualProtect(dst, size, oldprotect, &oldprotect);
    }

    void FillWithNops(DWORD_PTR startAddress, size_t size) {
        if (size <= 0) {
            return;
        }

        DWORD oldProtect;
        if (VirtualProtect(reinterpret_cast<void*>(startAddress), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            memset(reinterpret_cast<void*>(startAddress), 0x90, size);  // NOP instruction
            VirtualProtect(reinterpret_cast<void*>(startAddress), size, oldProtect, &oldProtect);
        }
        else {
        }
    }
    

    void SuspendProcess(DWORD processId, DWORD durationSeconds)
    {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, processId);

        if (hProcess == NULL)
        {
            std::cerr << "Failed to open process. Error code: " << GetLastError() << std::endl;
            return;
        }

        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap == INVALID_HANDLE_VALUE)
        {
            std::cerr << "Failed to create thread snapshot. Error code: " << GetLastError() << std::endl;
            CloseHandle(hProcess);
            return;
        }

        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hThreadSnap, &te32))
        {
            do
            {
                if (te32.th32OwnerProcessID == processId)
                {
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                    if (hThread != NULL)
                    {
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnap, &te32));
        }

        CloseHandle(hThreadSnap);

        Sleep(durationSeconds * 1000);

        if (hThreadSnap != INVALID_HANDLE_VALUE)
        {
            if (Thread32First(hThreadSnap, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == processId)
                    {
                        HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                        if (hThread != NULL)
                        {
                            ResumeThread(hThread);
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnap, &te32));
            }

            CloseHandle(hThreadSnap);
        }

        CloseHandle(hProcess);
    }

    void start_crack(DWORD_PTR startRVA, DWORD_PTR  endRVA, DWORD_PTR  start_integrity, DWORD_PTR end_integrity)
    {
        

        DWORD currentProcessId = GetCurrentProcessId();
        char processIdStr[10]; 

        sprintf_s(processIdStr, sizeof(processIdStr), "%lu", currentProcessId);

        MessageBoxA(NULL, processIdStr, "codecave-hooker", MB_OK);
        bool no_integ;
        if (start_integrity == 0 || end_integrity == 0) {
            MessageBoxA(NULL, "Integrity RVAs are 0. No integrity bypasses will be performed.", "codecave-hooker", MB_OK);
            no_integ = true;
        }


        MessageBoxA(NULL, "Calculating size", "codecave-hooker", MB_OK);

        DWORD_PTR base =  GetModuleBase("codecave_victim.exe");

        size_t size = CalculateSizeFromRVAs(startRVA, endRVA);

        size_t size_of_integrity = CalculateSizeFromRVAs(start_integrity, end_integrity);

        if (!no_integ && size_of_integrity > 0)
        {
            MessageBoxA(NULL, "Size calculated", "codecave-hooker", MB_OK);

            FillWithNops(base + start_integrity, size_of_integrity);


            MessageBoxA(NULL, "integrity Bypassed", "codecave-hooker", MB_OK);
        }
        else if (!no_integ)
        {
            MessageBoxA(NULL, "Auth failed: Invalid size", "codecave-hooker", MB_OK | MB_ICONERROR);
        }
        if (size > 0)
        {
            MessageBoxA(NULL, "Size calculated", "codecave-hooker", MB_OK);

            FillWithNops(base + startRVA, size);
       

            MessageBoxA(NULL, "Auth Bypassed", "codecave-hooker", MB_OK);
        }
        else {
            MessageBoxA(NULL, "Auth failed: Invalid size", "codecave-hooker", MB_OK | MB_ICONERROR);
        }

    }
   

    class MemoryScanner
    {
    public:

        std::vector<byte> SearchMemory(const char* pattern, size_t size) {
            std::vector<byte> result;

            HMODULE hModule = GetModuleHandle(NULL);
            if (hModule == NULL) {
                return result;  
            }

            MODULEINFO moduleInfo;
            if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
                return result;  
            }

            for (uintptr_t address = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
                address < reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll) + moduleInfo.SizeOfImage - size;
                ++address) {
                byte buffer[256]; 
                SIZE_T bytesRead;
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), buffer, sizeof(buffer), &bytesRead) &&
                    bytesRead == sizeof(buffer)) {
                    for (size_t i = 0; i < sizeof(buffer) - size; ++i) {
                        if (memcmp(buffer + i, pattern, size) == 0) {
                            for (size_t j = 0; j < size; ++j) {
                                result.push_back(buffer[i + j]);
                            }
                            return result;
                        }
                    }
                }
            }

            return result; 
        }
        std::atomic<bool> found{ false };

        void searchRange(int start, int end)
        {
            const int maxDigits = 6;

            for (int i = start; i <= end && !found; ++i)
            {
                std::ostringstream oss;
                oss << std::setw(6) << std::setfill('0') << i;
                std::string formattedNumber = oss.str();

                std::vector<byte> result = SearchMemory(formattedNumber.c_str(), formattedNumber.size());

                if (!result.empty())
                {
                    MessageBoxA(NULL, formattedNumber.c_str(), "Search Result", MB_OK);
                    found = true;
                }
            }
        }
    };

    MemoryScanner scanner;

    void scan_keyauth_download_parallel(const int startRange, const int endRange, int numThreads)
    {
        const int rangeSize = (endRange - startRange + 1) / numThreads;

        std::vector<std::unique_ptr<std::thread>> threads;

        for (int i = 0; i < numThreads; ++i)
        {
            int threadStart = startRange + i * rangeSize;
            int threadEnd = (i == numThreads - 1) ? endRange : threadStart + rangeSize - 1;

            threads.push_back(std::make_unique<std::thread>(&MemoryScanner::searchRange, &scanner, threadStart, threadEnd));
        }

        for (auto& thread : threads)
        {
            thread->detach();
        }
    }




    bool IsDigits(const std::string& str) {
        return str.find_first_not_of("0123456789") == std::string::npos;
    }

    void ScanMemoryForNumbers() {
        const int startRange = 164000;
        const int endRange = 999999;

        for (BYTE* addr = nullptr; ; addr += 0x1000) {
            MEMORY_BASIC_INFORMATION memInfo;

            if (VirtualQuery(addr, &memInfo, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION)) {
                break; 
            }

            std::vector<byte> buffer(memInfo.RegionSize);
            SIZE_T bytesRead;
            if (ReadProcessMemory(GetCurrentProcess(), addr, buffer.data(), memInfo.RegionSize, &bytesRead) && bytesRead > 0) {
                std::string data(reinterpret_cast<char*>(buffer.data()), bytesRead);

                for (size_t i = 0; i < data.size() - 5; ++i) {
                    std::string candidate = data.substr(i, 6);
                    if (std::all_of(candidate.begin(), candidate.end(), ::isdigit)) {
                        MessageBoxA(NULL, candidate.c_str(), "Keyauth Download Found", MB_OK);
                    }
                }
            }
        }
    }
    char* TO_CHAR(wchar_t* string)
    {
        size_t len = wcslen(string) + 1;
        char* c_string = new char[len];
        size_t numCharsRead;
        wcstombs_s(&numCharsRead, c_string, len, string, _TRUNCATE);
        return c_string;
    }

    void scan_text(const std::string& searchText)
    {
        std::vector<byte> textResult = scanner.SearchMemory(searchText.c_str(), searchText.size());

        if (!textResult.empty())
        {
            MessageBoxA(NULL, searchText.c_str(), "Search Result", MB_OK);
        }
    }
    
    RFW_LDR_DATA_TABLE_ENTRY* GetLDREntry(std::string moduleName)
    {
        auto pebPtr = (PEB*)__readgsqword(0x60);
        LIST_ENTRY head = pebPtr->Ldr->InMemoryOrderModuleList;
        LIST_ENTRY curr = head;

        RFW_LDR_DATA_TABLE_ENTRY* foundLdr = nullptr;
        while (curr.Flink != head.Blink) {

            RFW_LDR_DATA_TABLE_ENTRY* ldrDataTablePtr = (RFW_LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(curr.Flink, RFW_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

            if (ldrDataTablePtr->FullDllName.Buffer)
            {

                char* cName = TO_CHAR(ldrDataTablePtr->BaseDllName.Buffer);
                if (_stricmp(cName, moduleName.c_str()) == 0)
                {
                    foundLdr = ldrDataTablePtr;
                    break;
                }
                delete[] cName;
            }
            curr = *curr.Flink;
        }
        return foundLdr;
    }

    void hook_NTGlobalFlag()
    {
        auto peb = (char*)__readgsqword(0x60);
        *(peb + 0x68) = (*(peb + 0x68) &= ~(1UL << 5));
    }

}; static memory* mem_hook = new memory();