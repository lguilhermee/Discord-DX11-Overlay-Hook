#include <cstdint>
#include <Windows.h>
#include <Discord.h>
#include "Helper.h"

#define DEVELOPER

uintptr_t ResolveRelative(_In_ const uintptr_t adressPointer, _In_ const ULONG offsetCount,
                                  _In_ const ULONG sizeOfInstruction)
{
    const ULONG_PTR adressToResolve = adressPointer;
    const LONG totalBytesFromSpecifiedAdress = *(PLONG)(adressToResolve + offsetCount);
    const uintptr_t resultFinal = (adressToResolve + sizeOfInstruction + totalBytesFromSpecifiedAdress
    );

    return resultFinal;
}

uintptr_t Discord::GetDiscordModuleBase()
{
    // This is static because we only need to get once.
    static uintptr_t discordModuleBase = 0;

    // If its false, we use GetModuleHandle to grab the Module Base adress. 
    if (!discordModuleBase)
        discordModuleBase = (uintptr_t)GetModuleHandleA("DiscordHook64.dll");

    return discordModuleBase;
}

bool Discord::CreateHook(uintptr_t originalPresent, uintptr_t hookFunction, uintptr_t pOriginal)
{

    // Static because we only need to get once.
    static uintptr_t addrCreateHook = NULL;

    // If its false, its mean that its our first time executing this function, so we need to grab its adress on memory.
    if (!addrCreateHook)
    {
        // This function Search a sequences of bytes in memory. The sequence of bytes we found by reversing engineering the DiscordHook64.dll
        addrCreateHook = ResolveRelative(Helper::PatternScan(GetDiscordModuleBase(),"E8 ? ? ? ? 85 C0 74 53"),0x1,0x5);

        #ifdef DEVELOPER
        printf("CreateHook: 0x%p\n", addrCreateHook);
        #endif
    }

    // If this is false, its mean, that we could't find the function, that could be for alot of reasons, one of them is that the DLL could be updated, function changed or removed.
    if (!addrCreateHook)
        return false;

    // This is our function Template. We find this by reverse engineering the DiscordHook64.dll
    // Its easy, it to understand. Its return a uint64_t, the calling type its __fastcall, and it has 3 parameters.
    // For understand fastcall you can use msdn: https://docs.microsoft.com/pt-br/cpp/cpp/fastcall?view=vs-2019
    using CreateHook_t = uint64_t(__fastcall*)(LPVOID, LPVOID, LPVOID*);
    auto fnCreateHook = (CreateHook_t)addrCreateHook; // Here we set the adress that we found with our pattern scanning.

    // Then, we just call the function as we usually do.
    return fnCreateHook((void*)originalPresent, (void*)hookFunction, (void**)pOriginal) == 0 ? true : false;
}

bool Discord::EnableHook(uintptr_t pTarget, bool toggle)
{
    static uintptr_t addrEnableHook = NULL;

    if (!addrEnableHook)
    {
        addrEnableHook = Helper::PatternScan(GetDiscordModuleBase(),
                                             "41 56 56 57 53 48 83 EC 28 49 89 CE BF ? ? ? ? 31 C0 F0 0F B1 3D ? ? ? ? 74 2E 31 DB 48 8B 35 ? ? ? ? 66 2E 0F 1F 84 00 ? ? ? ? 31 C9 48 83 FB 1F 0F 97 C1 FF D6 48 83 C3 01 31 C0 F0 0F B1 3D ? ? ? ? 75 E5 48 83 3D ? ? ? ? ? 74 40 4D 85 F6 74 42 8B 15 ? ? ? ? B8 ? ? ? ? 48 85 D2 74 70 48 8B 0D ? ? ? ? 48 83 C1 20 48 F7 DA 31 DB 66 0F 1F 44 00 ? 4C 39 71 E0 74 4A 48 83 C1 38 48 83 C3 FF 48 39 DA 75 ED EB 45 B8 ? ? ? ? EB 3E 83 3D ? ? ? ? ? 74 33 B9 ? ? ? ? 31 C0 31 D2 66 90 48 8B 1D ? ? ? ? 80 24 0B FB"
        );

        #ifdef DEVELOPER
        printf("EnableHook: 0x%p\n", addrEnableHook);
        #endif
    }

    if (!addrEnableHook)
        return false;

    using EnableHook_t = uint64_t(__fastcall*)(LPVOID, bool);
    auto fnEnableHook = (EnableHook_t)addrEnableHook;

    return fnEnableHook((void*)pTarget, toggle) == 0 ? true : false;
}

bool Discord::EnableHookQue()
{
    static uintptr_t addrEnableHookQueu = NULL;

    if (!addrEnableHookQueu)
    {
        addrEnableHookQueu = ResolveRelative(Helper::PatternScan(GetDiscordModuleBase(),"E8 ? ? ? ? 85 C0 74 60"),0x1,0x5);

        #ifdef DEVELOPER
        printf("EnableHookQueu: 0x%p\n", addrEnableHookQueu);
        #endif
    }

    if (!addrEnableHookQueu)
        return false;

    using EnableHookQueu_t = uint64_t(__stdcall*)(VOID);
    auto fnEnableHookQueu = (EnableHookQueu_t)addrEnableHookQueu;

    return fnEnableHookQueu() == 0 ? true : false;
}

short Discord::GetAsyncKeyState(const int vKey)
{
    static uintptr_t addrGetAsyncKeyState = NULL;

    if (!addrGetAsyncKeyState)
    {
        addrGetAsyncKeyState = Helper::PatternScan(GetDiscordModuleBase(),
                                                   "56 48 83 EC 20 89 CE");

        #ifdef DEVELOPER
        printf("GetAsyncKeyState: 0x%p\n", addrGetAsyncKeyState);
        #endif
    }

    if (!addrGetAsyncKeyState)
        return false;

    using GetAsyncKeyState_t = short(__fastcall*)(int);
    auto fnGetAyncKeyState = (GetAsyncKeyState_t)addrGetAsyncKeyState;

    return fnGetAyncKeyState(vKey);
}

short Discord::SetCursorPos(int x, int y)
{
    static uintptr_t addrSetCursorPos = NULL;

    if (!addrSetCursorPos)
    {
        addrSetCursorPos = Helper::PatternScan(GetDiscordModuleBase(),
                                               "8A 05 ? ? ? ? 84 C0 74 12");

        #ifdef DEVELOPER
        printf("SetCursorPos: 0x%p\n", addrSetCursorPos);
        #endif
    }

    if (!addrSetCursorPos)
        return false;

    using SetCursorPos_t = short(__fastcall*)(int, int);
    auto fnSetCursorPos = (SetCursorPos_t)addrSetCursorPos;

    return fnSetCursorPos(x, y);
}


bool Discord::GetCursorPos(LPPOINT lpPoint)
{
    static uintptr_t addrGetCursorPos = NULL;

    if (!addrGetCursorPos)
    {
        addrGetCursorPos = Helper::PatternScan(GetDiscordModuleBase(),
                                               "56 48 83 EC 20 48 89 CE FF 15 ? ? ? ? 8A 15");

        #ifdef DEVELOPER
        printf("GetCursorPos: 0x%p\n", addrGetCursorPos);
        #endif
    }

    if (!addrGetCursorPos)
        return false;

    using GetCursorPos_t = short(__fastcall*)(LPPOINT);
    auto fnGetCursorPos = (GetCursorPos_t)addrGetCursorPos;

    return fnGetCursorPos(lpPoint);
}

HCURSOR Discord::SetCursor(HCURSOR hCursor)
{
    static uintptr_t addrSetCursor = NULL;

    if (!addrSetCursor)
    {
        addrSetCursor = Helper::PatternScan(GetDiscordModuleBase(),
                                            "56 57 48 83 EC 28 48 89 CE 8A 05 ? ? ? ? 48 8B 15");

        #ifdef DEVELOPER
        printf("SetCursor: 0x%p\n", addrSetCursor);
        #endif
    }

    if (!addrSetCursor)
        return false;

    using SetCursor_t = HCURSOR(__fastcall*)(HCURSOR);
    auto fnSetCursor = (SetCursor_t)addrSetCursor;

    return fnSetCursor(hCursor);
}

bool Discord::HookFunction(uintptr_t originalFunction, uintptr_t hookedFunction, uintptr_t pOriginalPresent)
{
    #ifdef DEVELOPER
    printf("OriginalPresent: 0x%p \n", originalFunction);
    #endif


    if (DISCORD.CreateHook(originalFunction, hookedFunction, pOriginalPresent))
    {
        #ifdef DEVELOPER
        printf("Hook created with success \n.");
        #endif
        if (DISCORD.EnableHook(originalFunction, true))
        {
            #ifdef DEVELOPER
            printf("Hook enabled with success. \n.");
            #endif

            if (DISCORD.EnableHookQue())
            {
                #ifdef DEVELOPER
                printf("Hook queued with success. \n.");
                #endif
                return true;
            }
        }
    }

    return false;
}
