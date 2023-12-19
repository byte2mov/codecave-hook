# codecave-hook
developer : Seemo/byte2mov
credits : fiz for keyauth download idea, zer0condition for ImGui Styling Color.
codecave hook reverse engineering toolkit.

**codecave hook is a reverse engineering toolkit i made to make my life easier which soon expanded into full blown bypasses of loaders.**

**Built in DLL dumper** **Built in Driver Dumper**
**Built In Debugger hooking and bypass**
**Built in Process Searching Bypass**
**Built in KeyAuth Download Finder**
**Built in Curl Detection**
**Built in Command Dumper for CMD and CreateProcess**
**Built in Process Hollowing Dumper (RUNPE and its other forms.)**
**Built in URLDownloadA Hook**
**Built in BlockInput Disabler**
**Built in Anti BSOD**
**Built in File Dumper**
**Memory Nop**
**Memory String Searcher**
**Memory Fill with Nops.**

**How?**

well codecave is mostly relient on detouring functions to do what you want, for example i hooked WriteProcessMemory to dump Process Hollowing which can also be used for dumping DLL

it relies on detour hooks, minhook whilst also being able to read and write memory.

**NOTE: You cannot use memory writing or reading after placing a detour hook, this needs to be fixed, you can simply set your memory patches before detouring.**

Showcase : 



https://github.com/byte2mov/codecave-hook/assets/146471523/942e0f2d-5c05-42b6-ab96-7e2766cea81a



