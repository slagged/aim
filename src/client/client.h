#ifndef AIM_CLIENT_CLIENT_H
#define AIM_CLIENT_CLIENT_H

#include "xprt.h"
#include <stddef.h>

// These declarations describe DLL call boundaries, not recovered class trees.
extern "C" {
int __stdcall OscoreRun(HINSTANCE, const char *, int);
int __stdcall OscoreInitLpShare(HINSTANCE, const char *);
int __stdcall OscoreShutdownOtherInstance(int);
int __cdecl ErrorBox(HMODULE, unsigned int, ...);
int __stdcall PHSetString(const char *, const char *, const char *);
int __cdecl PHSetGeneralInfo();
HRESULT __cdecl AimAppAddManagedComponent(const char *,
    const char *, const char *, const char *, int, int, int, int, int);
int __cdecl AIMToday_init();
int __stdcall AIMToday_createWindow(int);
int __cdecl AIMToday_destroyWindow();
int __cdecl AIMToday_uninit();
int __stdcall RDBLoadString(HINSTANCE, unsigned int, char *, int);

typedef int (__stdcall *RegistrationVisitor)(const GUID *, const unsigned short *, void *);
__declspec(dllimport) int __stdcall XpcsInitialize(int);
__declspec(dllimport) int __stdcall XpcsUninitialize();
__declspec(dllimport) int __stdcall XpcsEnumRegistrations(RegistrationVisitor, void *);
__declspec(dllimport) HRESULT __stdcall XpcsRegisterClass(const GUID *, const unsigned short *);
__declspec(dllimport) HRESULT __stdcall XpcsUnregisterClass(const GUID *);
__declspec(dllimport) HRESULT __stdcall XpcsRegisterServer(const unsigned short *);
__declspec(dllimport) HRESULT __stdcall XpcsCLSIDFromString(const unsigned short *, GUID *);
__declspec(dllimport) HRESULT __stdcall XpcsCreateSimpleInstance(const GUID *, const GUID *, void **);

// XPRT exports these as pointer-valued data, rather than function entry points.
__declspec(dllimport) extern unsigned int (__cdecl *xprt_strlcpy)(char *, const char *, unsigned int);
__declspec(dllimport) extern unsigned short *(__cdecl *xprt_wcscpy)(unsigned short *, const unsigned short *);

typedef void *XmlParser;
typedef void (__cdecl *XmlStart)(void *, const char *, const char **);
typedef void (__cdecl *XmlEnd)(void *, const char *);
XmlParser __cdecl XML_ParserCreate(const char *);
void __cdecl XML_SetUserData(XmlParser, void *);
void __cdecl XML_SetElementHandler(XmlParser, XmlStart, XmlEnd);
int __cdecl XML_Parse(XmlParser, const char *, int, int);
int __cdecl XML_GetCurrentLineNumber(XmlParser);
int __cdecl XML_GetErrorCode(XmlParser);
const char *__cdecl XML_ErrorString(int);
void __cdecl XML_ParserFree(XmlParser);
}

int guid_equal(const GUID *, const GUID *);
bool file_time_before(const FILETIME *, const FILETIME *);
void *allocate_zeroed(unsigned int);
int registry_writable(const char *);

// An XML parse record has no observed vptr. Keep its byte layout explicit;
// these descriptive field names do not assert the original source types.
struct ComponentContext {
    char name[0x80];
    char version[0x80];
    char class_token[0x80];
    char version_query[0x104];
    char class_query[0x104];
    char filename[0x105];
    char leaf_name[0x105];
    char padding[2];
    int register_needed;
    int load;
    int check_version;
    int required;
    int xpcs_directory;
    int depth;
    int errors;
    char app_directory[0x104];
    char registry_directory[0x104];
    char error_path[0x180];
};
typedef char ContextSizeCheck[sizeof(ComponentContext) == 0x938 ? 1 : -1];
typedef char ContextOffsetCheck[offsetof(ComponentContext, register_needed) == 0x594 ? 1 : -1];

extern HINSTANCE client_instance;
extern unsigned int component_error;
extern int registrations_changed;
extern char error_path[0x100];
extern char expected_version[0x80];
extern char actual_version[0x80];
extern const GUID build_registration;

int __stdcall unregister_component(const GUID *, const unsigned short *, void *);
int __stdcall copy_dll_registration(const GUID *, const unsigned short *, void *);
int __stdcall copy_build_version(const GUID *, const unsigned short *, void *);
void __stdcall register_protocols(HMODULE, const char *);
int register_servers(HMODULE, const char *);
void register_cool_utils(const char *);
int restore_backups(HINSTANCE);
int show_startup_error();
int show_component_error();
int initialize_components(HINSTANCE, int);
int classify_command(const char *);
int load_oscore(HMODULE);
int forward_to_instance(HMODULE, const char *);
int enable_aim_today(int);
int explorer_installed();
void repair_shortcut();
void install_exception_filter();

#endif
