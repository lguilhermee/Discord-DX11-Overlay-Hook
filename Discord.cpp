#include <Imports.h>
#include <Discord.h>


bool Discord::CreateHook(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pOriginal)
{
    static uintptr_t addrCreateHook = NULL;

    if (!IsValidPtr(addrCreateHook))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrCreateHook     = HELPER.PatternScan(hookedDiscord,
                                                xorstr_("40 53 55 56 57 41 54 41 56 41 57 48 83 EC 60").c_str());

        #ifdef DEVELOPER
        printf(xorstr_("CreateHook: 0x%p\n").c_str(), addrCreateHook);
        #endif
    }

    if (!IsValidPtr(addrCreateHook))
        return false;

    using CreateHook_t = uint64_t(__fastcall*)(LPVOID, LPVOID, LPVOID*);
    CreateHook_t fnCreateHook = (CreateHook_t)addrCreateHook;

    return fnCreateHook((void*)originalPresent, (void*)originalHooked, (void**)pOriginal) == 0 ? true : false;
}

bool Discord::EnableHook(uintptr_t pTarget, bool toggle)
{
    static uintptr_t addrEnableHook = NULL;

    if (!IsValidPtr(addrEnableHook))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrEnableHook     = HELPER.PatternScan(hookedDiscord,
                                                xorstr_(
                                                    "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC 20 33 F6 8B FA")
                                               .c_str());

        #ifdef DEVELOPER
        printf(xorstr_("EnableHook: 0x%p\n").c_str(), addrEnableHook);
        #endif
    }

    if (!IsValidPtr(addrEnableHook))
        return false;

    using EnableHook_t = uint64_t(__fastcall*)(LPVOID, bool);
    EnableHook_t fnEnableHook = (EnableHook_t)addrEnableHook;

    return fnEnableHook((void*)pTarget, toggle) == 0 ? true : false;
}

bool Discord::EnableHookQue()
{
    static uintptr_t addrEnableHookQueu = NULL;

    if (!IsValidPtr(addrEnableHookQueu))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrEnableHookQueu = HELPER.PatternScan(hookedDiscord,
                                                xorstr_("48 89 5C 24 ? 48 89 6C 24 ? 48 89 7C 24 ? 41 57").c_str());

        #ifdef DEVELOPER
        printf(xorstr_("EnableHookQueu: 0x%p\n").c_str(), addrEnableHookQueu);
        #endif
    }

    if (!IsValidPtr(addrEnableHookQueu))
        return false;

    using EnableHookQueu_t = uint64_t(__stdcall*)(VOID);
    EnableHookQueu_t fnEnableHookQueu = (EnableHookQueu_t)addrEnableHookQueu;

    return fnEnableHookQueu() == 0 ? true : false;
}

short Discord::GetAsyncKeyState(const int vKey)
{
    static uintptr_t addrGetAsyncKeyState = NULL;

    if (!IsValidPtr(addrGetAsyncKeyState))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrGetAsyncKeyState = HELPER.PatternScan(hookedDiscord,
            xorstr_("40 53 48 83 EC 20 8B D9 FF 15 ? ? ? ?").c_str());

#ifdef DEVELOPER
        printf(xorstr_("GetAsyncKeyState: 0x%p\n").c_str(), addrGetAsyncKeyState);
#endif
    }

    if (!IsValidPtr(addrGetAsyncKeyState))
        return false;

    using GetAsyncKeyState_t = short(__fastcall*)(int);
    GetAsyncKeyState_t fnGetAyncKeyState = (GetAsyncKeyState_t)addrGetAsyncKeyState;

    return fnGetAyncKeyState(vKey);
}

short Discord::SetCursorPos(int x, int y)
{
    static uintptr_t addrSetCursorPos = NULL;

    if (!IsValidPtr(addrSetCursorPos))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrSetCursorPos = HELPER.PatternScan(hookedDiscord,
            xorstr_("44 0F B6 05 ? ? ? ? 45 84 C0").c_str());

#ifdef DEVELOPER
        printf(xorstr_("SetCursorPos: 0x%p\n").c_str(), addrSetCursorPos);
#endif
    }

    if (!IsValidPtr(addrSetCursorPos))
        return false;

    using SetCursorPos_t = short(__fastcall*)(int, int);
    SetCursorPos_t fnSetCursorPos = (SetCursorPos_t)addrSetCursorPos;

    return fnSetCursorPos(x,y);
}

bool Discord::GetCursorPos(LPPOINT lpPoint)
{
    static uintptr_t addrGetCursorPos = NULL;

    if (!IsValidPtr(addrGetCursorPos))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrGetCursorPos = HELPER.PatternScan(hookedDiscord,
            xorstr_("40 53 48 83 EC 20 48 8B D9 FF 15 ? ? ? ? 0F B6 15 ? ? ? ?").c_str());

#ifdef DEVELOPER
        printf(xorstr_("GetCursorPos: 0x%p\n").c_str(), addrGetCursorPos);
#endif
    }

    if (!IsValidPtr(addrGetCursorPos))
        return false;

    using GetCursorPos_t = short(__fastcall*)(LPPOINT);
    GetCursorPos_t fnGetCursorPos = (GetCursorPos_t)addrGetCursorPos;

    return fnGetCursorPos(lpPoint);
}

HCURSOR Discord::SetCursor(HCURSOR hCursor)
{
    static uintptr_t addrSetCursor = NULL;

    if (!IsValidPtr(addrSetCursor))
    {
        auto hookedDiscord = (uintptr_t)HELPER.GetModuleBaseAddress(xorstr_(L"DiscordHook64.dll").c_str());
        addrSetCursor = HELPER.PatternScan(hookedDiscord,
            xorstr_("40 53 48 83 EC 20 0F B6 05 ? ? ? ? 48 8B D9 84 C0 74 4F").c_str());

#ifdef DEVELOPER
        printf(xorstr_("SetCursor: 0x%p\n").c_str(), addrSetCursor);
#endif
    }

    if (!IsValidPtr(addrSetCursor))
        return false;

    using SetCursor_t = HCURSOR(__fastcall*)(HCURSOR);
    SetCursor_t fnSetCursor = (SetCursor_t)addrSetCursor;

    return fnSetCursor(hCursor);
}

bool Discord::HookDiscord(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pOriginal)
{
    #ifdef DEVELOPER
    printf(xorstr_("OriginalPresent: 0x%p \n").c_str(), originalPresent);
    #endif


    if (DISCORD.CreateHook(originalPresent, originalHooked, pOriginal))
    {
        #ifdef DEVELOPER
        printf(xorstr_("Hook created with sucess \n.").c_str());
        #endif
        if (DISCORD.EnableHook(originalPresent, true))
        {
            #ifdef DEVELOPER
            printf(xorstr_("Hook enabled with sucess. \n.").c_str());
            #endif

            if (DISCORD.EnableHookQue())
            {
                #ifdef DEVELOPER
                printf(xorstr_("Hook qued with sucess. \n.").c_str());
                #endif
                return true;
            }
        }
    }

    return false;
}
