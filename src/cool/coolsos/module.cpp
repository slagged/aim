#include <windows.h>

/* The component has no initialization or shutdown work in this build. */
bool ModuleInit(HINSTANCE instance) {
    return true;
}

void ModuleTerm(void) {
}

extern "C" HRESULT WINAPI DllCanUnloadNow(void) {
    return S_OK;
}

extern "C" HRESULT WINAPI DllRegisterServer(void) {
    return S_OK;
}

extern "C" HRESULT WINAPI DllUnregisterServer(void) {
    return S_OK;
}

/* No classes are available. The original leaves the output pointer untouched. */
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID clsid, REFIID iid, LPVOID *object) {
    return E_FAIL;
}
