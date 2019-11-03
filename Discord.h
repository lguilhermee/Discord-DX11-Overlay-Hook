#pragma once

#define DISCORD Discord::Instance()

class Discord
{
public:
    bool CreateHook(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pOriginal);
    bool EnableHook(uintptr_t pTarget, bool toggle);
    bool EnableHookQue();
    short GetAsyncKeyState(int vKey);
    short SetCursorPos(int x, int y);
    bool GetCursorPos(LPPOINT lpPoint);
    HCURSOR SetCursor(HCURSOR hCursor);

    bool HookDiscord(uintptr_t originalPresent, uintptr_t originalHooked, uintptr_t pOriginal);

    static Discord& Instance()
    {
        static Discord handle;
        return handle;
    }
};
