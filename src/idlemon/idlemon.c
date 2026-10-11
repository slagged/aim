#include <windows.h>

/*
 * AIM's idle monitor records keyboard activity and changes in mouse position.
 * Hook callbacks update shared timestamps; the exported queries return the
 * elapsed time since the latest two recorded events.
 *
 * This is a matching reconstruction. Original private names and source types
 * are unknown, and observed quirks are deliberately retained.
 */

/* The linker marks .aimshar readable, writable, and shared between processes.
 * Keep the declaration order: these globals' offsets are part of the match.
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

/* Preserve the observed memory read when querying a timestamp that hook
 * callbacks in other processes can update. DWORD subtraction wraps naturally.
 */
DWORD IdleTimeSinceLastInput(void) {
    return GetTickCount() - *(volatile DWORD *)&last_input;
}

DWORD IdleTimeSinceNextToLastInput(void) {
    return GetTickCount() - *(volatile DWORD *)&previous_input;
}

void IdleSetEvent(void) {
    previous_input = last_input;
    last_input = GetTickCount();
}

LRESULT CALLBACK IdleKeybdHook(int code, WPARAM wparam, LPARAM lparam) {
    /* Negative hook codes are forwarded without recording an event. */
    if (code < 0)
        return CallNextHookEx(keyboard_hook, code, wparam, lparam);

    if (code == HC_ACTION)
        IdleSetEvent();

    return CallNextHookEx(keyboard_hook, code, wparam, lparam);
}

LRESULT CALLBACK IdleMouseHook(int code, WPARAM wparam, LPARAM lparam) {
    volatile MOUSEHOOKSTRUCT *mouse;

    /* The original uses keyboard_hook on this path, even in the mouse hook. */
    if (code < 0)
        return CallNextHookEx(keyboard_hook, code, wparam, lparam);

    /* The volatile source shape preserves the original structure accesses;
     * it does not establish that AOL used this declaration.
     */
    mouse = (volatile MOUSEHOOKSTRUCT *)lparam;

    /* Only a position change counts here; the mouse message itself is unused. */
    if (mouse && (mouse->pt.x != last_mouse.x || mouse->pt.y != last_mouse.y)) {
        last_mouse.x = mouse->pt.x;
        last_mouse.y = mouse->pt.y;
        IdleSetEvent();
    }

    return CallNextHookEx(mouse_hook, code, wparam, lparam);
}

int IdleStartup(void) {
    HMODULE module;
    HOOKPROC proc;

    owner_process = GetCurrentProcessId();
    module = GetModuleHandleA("IDLEMON.DLL");

    /* Resolve the exported callbacks from the loaded DLL before installing
     * global hooks. Failed lookups/installations leave the hook handles NULL.
     */
    keyboard_hook = NULL;
    proc = (HOOKPROC)GetProcAddress(module, "IdleKeybdHook");
    if (proc)
        keyboard_hook = SetWindowsHookExA(WH_KEYBOARD, proc, module, 0);

    mouse_hook = NULL;
    proc = (HOOKPROC)GetProcAddress(module, "IdleMouseHook");
    if (proc)
        mouse_hook = SetWindowsHookExA(WH_MOUSE, proc, module, 0);

    /* Both queries initially measure elapsed time since startup. */
    last_input = previous_input = GetTickCount();
    unused_state = 0;

    /* The original reports success even if a hook could not be installed. */
    return 0;
}

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
    /* Hook installation is explicit through IdleStartup, not DLL attachment. */
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(instance);

    return TRUE;
}
