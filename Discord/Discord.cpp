#include <cstdint>
#include <Windows.h>
#include <Discord.h>
#include "Helper.h"

#define DEVELOPER

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
        addrCreateHook = Helper::PatternScan(GetDiscordModuleBase(),"40 53 55 56 57 41 54 41 56 41 57 48 83 EC 60");

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
                                             "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 33 F6 8B FA"
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
        addrEnableHookQueu = Helper::PatternScan(GetDiscordModuleBase(),
                                                 "48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 57");

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
                                                   "40 53 48 83 EC 20 8B D9 FF 15 ? ? ? ?");

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
                                               "44 0F B6 05 ? ? ? ? 45 84 C0");

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
                                               "40 53 48 83 EC 20 48 8B D9 FF 15 ? ? ? ? 0F B6 15 ? ? ? ?");

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
                                            "40 53 48 83 EC 20 0F B6 05 ? ? ? ? 48 8B D9 84 C0 74 4F");

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
        printf("Hook created with sucess \n.");
        #endif
        if (DISCORD.EnableHook(originalFunction, true))
        {
            #ifdef DEVELOPER
            printf("Hook enabled with sucess. \n.");
            #endif

            if (DISCORD.EnableHookQue())
            {
                #ifdef DEVELOPER
                printf("Hook qued with sucess. \n.");
                #endif
                return true;
            }
        }
    }

    return false;
}
