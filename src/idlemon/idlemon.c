#include <windows.h>

/*
 * Track keyboard activity and mouse movement across processes. Keep the two
 * most recent event times so AIM can ask how long the user has been idle.
 */

/* Hook callbacks run in multiple processes. The shared section lets them
 * update the same event history and hook state.
 */
#pragma data_seg(".aimshar")

DWORD owner_process = 0;
POINT last_mouse = { 0, 0 };

HHOOK keyboard_hook = NULL;
HHOOK mouse_hook = NULL;

DWORD last_input = 0;
DWORD previous_input = 0;
DWORD unused_state = 0;

#pragma data_seg()

/* Return milliseconds since the latest event. Read the shared timestamp each
 * time; another process's hook callback may have updated it.
 */
DWORD IdleTimeSinceLastInput(void) {
    return GetTickCount() - *(volatile DWORD *)&last_input;
}

DWORD IdleTimeSinceNextToLastInput(void) {
    return GetTickCount() - *(volatile DWORD *)&previous_input;
}

/* Retain the preceding event time before recording the new one. */
void IdleSetEvent(void) {
    previous_input = last_input;
    last_input = GetTickCount();
}

LRESULT CALLBACK IdleKeybdHook(int code, WPARAM wparam, LPARAM lparam) {
    /* Forward notifications that must not be processed by this hook. */
    if (code < 0)
        return CallNextHookEx(keyboard_hook, code, wparam, lparam);

    if (code == HC_ACTION)
        IdleSetEvent();

    return CallNextHookEx(keyboard_hook, code, wparam, lparam);
}

LRESULT CALLBACK IdleMouseHook(int code, WPARAM wparam, LPARAM lparam) {
    volatile MOUSEHOOKSTRUCT *mouse;

    /* This mouse path unexpectedly forwards using the keyboard hook handle. */
    if (code < 0)
        return CallNextHookEx(keyboard_hook, code, wparam, lparam);

    mouse = (volatile MOUSEHOOKSTRUCT *)lparam;

    /* Stationary clicks and wheel events do not reset the idle timer. */
    if (mouse && (mouse->pt.x != last_mouse.x || mouse->pt.y != last_mouse.y)) {
        last_mouse.x = mouse->pt.x;
        last_mouse.y = mouse->pt.y;
        IdleSetEvent();
    }

    return CallNextHookEx(mouse_hook, code, wparam, lparam);
}

/* Install global input hooks and initialize both event times to startup. */
int IdleStartup(void) {
    HMODULE module;
    HOOKPROC proc;

    owner_process = GetCurrentProcessId();
    module = GetModuleHandleA("IDLEMON.DLL");

    /* Locate the hook callbacks through this DLL's exports. */
    keyboard_hook = NULL;
    proc = (HOOKPROC)GetProcAddress(module, "IdleKeybdHook");
    if (proc)
        keyboard_hook = SetWindowsHookExA(WH_KEYBOARD, proc, module, 0);

    mouse_hook = NULL;
    proc = (HOOKPROC)GetProcAddress(module, "IdleMouseHook");
    if (proc)
        mouse_hook = SetWindowsHookExA(WH_MOUSE, proc, module, 0);

    last_input = previous_input = GetTickCount();
    unused_state = 0;

    /* Failed lookups or hook installations still return success. */
    return 0;
}

/* Remove installed hooks and clear the recorded process ID. */
void AimIdleShutdown(void) {
    if (keyboard_hook) {
        UnhookWindowsHookEx(keyboard_hook);
        keyboard_hook = NULL;
    }

    if (mouse_hook) {
        UnhookWindowsHookEx(mouse_hook);
        mouse_hook = NULL;
    }

    owner_process = 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    /* Suppress thread notifications; input hooks are started explicitly. */
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);

    return TRUE;
}
