#include "client.h"
#include <shlobj.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static HMODULE oscore_module;
static char installation_directory[0x104];
static char oscore_filename[0x104];

// move an AIM shortcut out of a nested desktop directory.
void repair_shortcut()
{
    IMalloc *allocator;
    if (SHGetMalloc(&allocator)) allocator = 0;
    char shortcut[0x104];
    RDBLoadString(0, 0xff, shortcut, sizeof(shortcut));
    lstrcatA(shortcut, ".lnk");
    const int folders[] = {CSIDL_COMMON_DESKTOPDIRECTORY, CSIDL_DESKTOPDIRECTORY, 0};
    int found = 0;
    for (int i = 0; folders[i] && !found; ++i) {
        LPITEMIDLIST id;
        if (SHGetSpecialFolderLocation(0, folders[i], &id)) continue;
        char destination[0x104];
        char pattern[0x104];
        SHGetPathFromIDListA(id, destination);
        lstrcatA(destination, "\\");
        lstrcpyA(pattern, destination);
        int directory_length = strlen(pattern);
        lstrcatA(pattern, "*");
        lstrcatA(destination, shortcut);
        if (GetFileAttributesA(pattern) != INVALID_FILE_ATTRIBUTES) {
            found = 1;
        } else {
            WIN32_FIND_DATAA entry;
            HANDLE search = FindFirstFileA(pattern, &entry);
            if (search != INVALID_HANDLE_VALUE) {
                do {
                    if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && entry.cFileName[0] != '.') {
                        lstrcpyA(pattern + directory_length, entry.cFileName);
                        lstrcatA(pattern, "\\");
                        lstrcatA(pattern, shortcut);
                        if (GetFileAttributesA(pattern) != INVALID_FILE_ATTRIBUTES) {
                            MoveFileA(pattern, destination);
                            found = 1;
                            break;
                        }
                    }
                } while (FindNextFileA(search, &entry));
                FindClose(search);
            }
        }
        if (allocator) allocator->Free(id);
    }
    if (allocator) allocator->Release();
}

// resource 1 lists commands that bypass normal component startup.
int classify_command(const char *command)
{
    char token[0x108] = " ";
    lstrcpynA(token + 1, command, 0x104);
    lstrcatA(token, " ");
    char *query = strchr(token, '?');
    if (query) lstrcpyA(query, " ");
    _strupr(token);
    char commands[0x1450];
    LoadStringA(0, 1, commands, sizeof(commands));
    return strstr(commands, token) != 0;
}

// load OSCORE beside this executable and retain its module handle.
int load_oscore(HMODULE instance)
{
    if (oscore_module) return 1;
    if (!GetModuleFileNameA(instance, installation_directory, sizeof(installation_directory))) return 0;
    char *slash = strrchr(installation_directory, '\\');
    if (slash) *slash = 0;
    lstrcpyA(oscore_filename, installation_directory);
    lstrcatA(oscore_filename, "\\oscore.dll");
    oscore_module = LoadLibraryA(oscore_filename);
    return oscore_module != 0;
}

// ordinary commands are sent to the existing shim window. Restart
// commands first ask OSCORE to shut that instance down.
int forward_to_instance(HMODULE instance, const char *command)
{
    if (command) while (isspace(static_cast<signed char>(*command))) ++command;
    if (_strnicmp(command, "aim:", lstrlenA("aim") + 1) && strstr(command, "-restart")) {
        if (load_oscore(instance)) return !OscoreShutdownOtherInstance(1);
    } else {
        HWND window = FindWindowA("_Oscar_OMShim", 0);
        if (window) {
            HMODULE user32 = LoadLibraryA("User32.DLL");
            if (user32) {
                typedef BOOL (WINAPI *AllowForeground)(DWORD);
                AllowForeground allow = reinterpret_cast<AllowForeground>(GetProcAddress(user32, "AllowSetForegroundWindow"));
                DWORD process;
                GetWindowThreadProcessId(window, &process);
                if (allow) allow(process);
                FreeLibrary(user32);
            }
            COPYDATASTRUCT message;
            message.dwData = 1;
            message.cbData = command ? lstrlenA(command) + 1 : 0;
            message.lpData = const_cast<char *>(command);
            SendMessageA(window, WM_COPYDATA, reinterpret_cast<WPARAM>(window), reinterpret_cast<LPARAM>(&message));
        }
    }
    return 1;
}

// AIMToday reports successful initialization with zero.
int enable_aim_today(int enable)
{
    if (!enable) {
        AIMToday_destroyWindow();
        AIMToday_uninit();
    } else if (!AIMToday_init() && !AIMToday_createWindow(0)) {
        return 1;
    }
    return 0;
}

// presence of an AOL Explorer browser path enables AIMToday startup.
int explorer_installed()
{
    HKEY key = 0;
    char path[0x104];
    path[0] = 0;
    if (!RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\America Online\\Products\\AOL Explorer\\1.0", 0, KEY_READ, &key)) {
        DWORD length = sizeof(path);
        RegQueryValueExA(key, "BrowserPath", 0, 0, reinterpret_cast<BYTE *>(path), &length);
    }
    if (key) RegCloseKey(key);
    return path[0] != 0;
}

// prepare the command line, enforce one instance, register servers,
// initialize components, and hand control to the installed OSCORE client.
int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR command, int show)
{
    OleInitialize(0);
    XpcsInitialize(0);
    if (command) while (isspace(static_cast<signed char>(*command))) ++command;
    int length = command ? lstrlenA(command) : 0;
    while (length && isspace(static_cast<signed char>(command[length - 1]))) command[--length] = 0;
    int registration_only = !_strnicmp(command, "REGISTERONLY", strlen("REGISTERONLY"));
    const char *procedure = 0;
    if (registration_only) {
        procedure = command + strlen("REGISTERONLY");
        while (isspace(static_cast<signed char>(*procedure))) ++procedure;
    }
    char *allocated_command = 0;
    char *extension = length ? strrchr(command, '.') : 0;
    if (length && command[0] == '"' && command[length - 1] == '"') {
        allocated_command = static_cast<char *>(malloc(strlen(command) + 3));
        if (allocated_command) {
            sprintf(allocated_command, "-I%s", command);
            command = allocated_command;
        }
    } else if (length >= lstrlenA(".blt") + 2 && command[1] == ':' && extension && !_stricmp(extension, ".blt")) {
        allocated_command = static_cast<char *>(malloc(strlen(command) * 5));
        if (allocated_command) {
            sprintf(allocated_command, "-I\"%s\"", command);
            command = allocated_command;
        }
    }
    restore_backups(instance);
    HANDLE mutex = CreateMutexA(0, FALSE, "_Oscar_AppMutex");
    DWORD mutex_error = GetLastError();
    int result = 0;
    if (mutex_error != ERROR_ALREADY_EXISTS || (!registration_only && !forward_to_instance(instance, command))) {
        int today = explorer_installed();
        if (today) enable_aim_today(1);
        register_servers(instance, procedure);
        if (!lstrcmpiA(command, "unload")) {
            result = 0;
        } else if (!load_oscore(instance)) {
            result = -1;
        } else {
            result = reinterpret_cast<int>(instance);
            if (!classify_command(command)) {
                if (initialize_components(instance, registration_only) && !registration_only)
                    result = OscoreRun(instance, command, show);
                OSVERSIONINFOA version;
                memset(&version, 0, sizeof(version));
                version.dwOSVersionInfoSize = sizeof(version);
                GetVersionExA(&version);
                if (version.dwMajorVersion > 5 || (version.dwMajorVersion == 5 && version.dwMinorVersion >= 1))
                    repair_shortcut();
                // Shutdown changes the current directory before deleting AIM
                // temporary files. This is observable process-wide behavior.
                char temporary[0x104];
                GetTempPathA(sizeof(temporary), temporary);
                SetCurrentDirectoryA(temporary);
                WIN32_FIND_DATAA entry;
                HANDLE search = FindFirstFileA("AIM*.*", &entry);
                if (search != INVALID_HANDLE_VALUE) {
                    do { DeleteFileA(entry.cFileName); } while (FindNextFileA(search, &entry));
                    FindClose(search);
                }
            }
            if (allocated_command) free(allocated_command);
            if (today) enable_aim_today(0);
        }
    }
    CloseHandle(mutex);
    XpcsUninitialize();
    OleUninitialize();
    return result;
}
