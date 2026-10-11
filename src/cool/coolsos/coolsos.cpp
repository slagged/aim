#include <windows.h>

/* This build exposes an empty component server: registration succeeds, but
 * requests for a class factory fail without writing to the output pointer.
 */

/* Only the instance field is used. The remaining original storage has no
 * observed accesses, so its internal layout is not yet known.
 */
struct ModuleState {
    HINSTANCE instance;
    BYTE reserved[96];
};

ModuleState module;

bool ModuleInit(HINSTANCE instance);
void ModuleTerm(void);

extern "C" BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    BOOL result = TRUE;

    if (reason == DLL_PROCESS_ATTACH) {
        module.instance = instance;
        DisableThreadLibraryCalls(instance);
        result = ModuleInit(module.instance);
    } else if (reason == DLL_PROCESS_DETACH) {
        ModuleTerm();
    }

    return result;
}

/* Forward loader notifications without starting the C runtime. */
extern "C" BOOL WINAPI DllEntryPoint(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    return DllMain(instance, reason, reserved);
}

