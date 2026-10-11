#include "client.h"
#include <stdio.h>
#include <string.h>
#include <io.h>

// Publish the aim: URL handler and its automation COM identity. Failed writes
// do not prevent attempts to register the remaining keys.
void __stdcall register_protocols(HMODULE instance, const char *directory)
{
    char command[0x10c];
    char value[0x104];
    HKEY key;
    HKEY child;
    DWORD disposition;
    if (!GetModuleFileNameA(instance, command, 0x104))
        return;
    // The command leaves both the executable path and argument unquoted.
    lstrcatA(command, " %1");
    if (!RegCreateKeyExA(HKEY_CLASSES_ROOT, "aim", 0, "", 0,
            KEY_READ | KEY_WRITE, 0, &key, &disposition)) {
        lstrcpyA(value, "URL: AOL Instant Messenger Protocol");
        RegSetValueExA(key, "", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
        value[0] = 0;
        RegSetValueExA(key, "URL Protocol", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), 1);
        if (!RegCreateKeyExA(key, "shell\\open\\command", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(command), lstrlenA(command) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (key)
            RegCloseKey(key);
    }

    if (!RegCreateKeyExA(HKEY_CLASSES_ROOT, "AIM.Protocol", 0, "", 0,
            KEY_READ | KEY_WRITE, 0, &key, &disposition)) {
        lstrcpyA(value, "AIM OLE Automation Protocol Handler");
        RegSetValueExA(key, "", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
        if (!RegCreateKeyExA(key, "CurVer", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>("AIM.Protocol.1"), lstrlenA("AIM.Protocol.1") + 1);
            if (child)
                RegCloseKey(child);
        }
        wsprintfA(value, "{%s}", "BAEB32D0-732D-11d2-8BF4-0060B0A4A9EA");
        if (!RegCreateKeyExA(key, "CLSID", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "NotInsertable", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            value[0] = 0;
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (key)
            RegCloseKey(key);
    }

    if (!RegCreateKeyExA(HKEY_CLASSES_ROOT, "AIM.Protocol.1", 0, "", 0,
            KEY_READ | KEY_WRITE, 0, &key, &disposition)) {
        lstrcpyA(value, "AIM OLE Automation Protocol Handler");
        RegSetValueExA(key, "", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
        wsprintfA(value, "{%s}", "BAEB32D0-732D-11d2-8BF4-0060B0A4A9EA");
        if (!RegCreateKeyExA(key, "CLSID", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "NotInsertable", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            value[0] = 0;
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (key)
            RegCloseKey(key);
    }

    wsprintfA(value, "CLSID\\{%s}", "BAEB32D0-732D-11d2-8BF4-0060B0A4A9EA");
    if (!RegCreateKeyExA(HKEY_CLASSES_ROOT, value, 0, "", 0,
            KEY_READ | KEY_WRITE, 0, &key, &disposition)) {
        lstrcpyA(value, "AIM OLE Automation Protocol Handler");
        RegSetValueExA(key, "", 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
        if (!RegCreateKeyExA(key, "Programmable", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            value[0] = 0;
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "ProgID", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>("AIM.Protocol.1"), lstrlenA("AIM.Protocol.1") + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "VersionIndependentProgID", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>("AIM.Protocol"), lstrlenA("AIM.Protocol") + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "InprocHandler32", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            lstrcpyA(value, "ole32.dll");
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (!RegCreateKeyExA(key, "LocalServer32", 0, "", 0,
                KEY_READ | KEY_WRITE, 0, &child, &disposition)) {
            wsprintfA(value, "%s%s", directory, "aimauto.exe");
            RegSetValueExA(child, "", 0, REG_SZ,
                reinterpret_cast<const BYTE *>(value), lstrlenA(value) + 1);
            if (child)
                RegCloseKey(child);
        }
        if (key)
            RegCloseKey(key);
    }

    if (!RegOpenKeyA(HKEY_CURRENT_USER,
        "Software\\Netscape\\Netscape Navigator\\Automation Protocols", &key)) {
        RegSetValueExA(key, "aim", 0, REG_SZ,
            reinterpret_cast<const BYTE *>("AIM.Protocol.1"), lstrlenA("AIM.Protocol.1") + 1);
        if (key)
            RegCloseKey(key);
    }

    return;
}


// recover a missing installed file from the newest six-character
// backup stem, then remove leftover backups matching that stem.
int restore_backups(HINSTANCE instance)
{
    char filename[0x104];
    char pattern[0x104];
    if (!GetModuleFileNameA(GetModuleHandleA(0), filename, sizeof(filename)))
        return show_startup_error();
    char *leaf = strrchr(filename, '\\');
    if (leaf)
        leaf[1] = 0;
    lstrcpyA(pattern, filename);
    int directory_length = lstrlenA(filename);
    unsigned int id = 2;
    while (LoadStringA(instance, id, filename + directory_length,
            sizeof(filename) - directory_length)) {
        ++id;
        if (!lstrlenA(filename + directory_length))
            break;
        lstrcpyA(pattern + directory_length, filename + directory_length);
        HANDLE search;
        char *extension = strrchr(filename, '.');
        pattern[directory_length + 6] = 0;
        lstrcatA(pattern, "~*");
        if (extension)
            lstrcatA(pattern, extension);
        WIN32_FIND_DATAA entry;
        if (_access(filename, 0) != 0) {
            FILETIME newest = {0, 0};
            search = FindFirstFileA(pattern, &entry);
            if (search != INVALID_HANDLE_VALUE) {
                do {
                    // This tests the working path, which changes when a newer
                    // backup is selected, rather than the current search result.
                    if (pattern[directory_length + 6] == '~'
                            && file_time_before(&newest, &entry.ftLastWriteTime)) {
                        newest = entry.ftLastWriteTime;
                        lstrcpyA(pattern + directory_length, entry.cFileName);
                    }
                    if (!FindNextFileA(search, &entry)) {
                        FindClose(search);
                        search = INVALID_HANDLE_VALUE;
                    }
                } while (search != INVALID_HANDLE_VALUE);
                if (newest.dwLowDateTime || newest.dwHighDateTime)
                    MoveFileA(pattern, filename);
            }
        }
        pattern[directory_length + 6] = 0;
        lstrcatA(pattern, "~*");
        if (extension)
            lstrcatA(pattern, extension);
        search = FindFirstFileA(pattern, &entry);
        if (search != INVALID_HANDLE_VALUE) {
            do {
                lstrcpyA(pattern + directory_length, entry.cFileName);
                if (!FindNextFileA(search, &entry)) {
                    FindClose(search);
                    search = INVALID_HANDLE_VALUE;
                }
                if (pattern[directory_length + 6] == '~')
                    DeleteFileA(pattern);
            } while (search != INVALID_HANDLE_VALUE);
        }
    }
    return 1;
}

// register the API/video servers, and repair the Boxely COM server
// when its activation fails. Missing libraries do not themselves set failure.
int register_servers(HMODULE instance, const char *procedure)
{
    char executable[0x104];
    if (!GetModuleFileNameA(GetModuleHandleA(0), executable, sizeof(executable)))
        return show_startup_error();
    XPRT::TBstr directory(executable);
    directory.Assign(directory.Left(directory.ReverseFind('\\') + 1));
    register_protocols(instance, directory.GetMultibyteString());
    if (!procedure || !*procedure)
        procedure = "DllRegisterServer";
    typedef HRESULT (__stdcall *RegisterServer)();
    const char *servers[] = {"AimApi.dll", "rtvideo.dll", 0};
    const char *server_name = servers[0];
    const char **server;
    int result = 1;
    server = servers;
    do {
        {
        XPRT::TBstr filename(directory);
        filename.Append(server_name);
        HMODULE library = LoadLibraryA(filename.GetMultibyteString());
        if (library) {
            RegisterServer registration = reinterpret_cast<RegisterServer>(GetProcAddress(library, procedure));
            if (registration) registration();
            else result = 0;
        }
        FreeLibrary(library);
        }
        server_name = *++server;
    } while (server_name);
    static const GUID boxely_class = {0x189504b8, 0x50d1, 0x4aa8, {0xb4, 0xd6, 0x95, 0xc8, 0xf5, 0x8a, 0x64, 0x14}};
    IUnknown *object;
    if (CoCreateInstance(boxely_class, 0, CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
            IID_IUnknown, reinterpret_cast<void **>(&object)) < 0) {
        XPRT::TBstr filename(directory);
        filename.Append("sb.dll");
        HMODULE library = LoadLibraryA(filename.GetMultibyteString());
        if (library) {
            RegisterServer registration = reinterpret_cast<RegisterServer>(GetProcAddress(library, procedure));
            if (registration) registration();
            else result = 0;
            FreeLibrary(library);
        }
    } else {
        object->Release();
    }
    return result;
}

// An existing registry must be writable. If it is absent, check whether its
// containing directory is writable so the registry can be created there.
int registry_writable(const char *directory)
{
    XPRT::TBstr registry(directory);
    registry.Append("\\Xpcs Registry.dat");

    int writable;
    if (_access(registry.GetMultibyteString(), 2) != -1)
        writable = 1;
    else if (_access(registry.GetMultibyteString(), 0) == -1
            && _access(directory, 2) != -1)
        writable = 1;
    else
        writable = 0;

    return writable;
}

// Associate three utility classes with the installed CoolUtils DLL in XPCS.
void register_cool_utils(const char *directory)
{
    XPRT::TBstr filename(directory);
    filename.Append("CoolUtils.dll");

    // Conversion and registration failures are ignored. Each temporary string
    // is destroyed after conversion, while the DLL path remains live throughout.
    GUID id;
    XpcsCLSIDFromString(
        XPRT::TBstr("{648EDF60-2501-11d3-90DC-0060B088CB02}").GetString(), &id);
    XpcsRegisterClass(&id, filename.GetString());

    XpcsCLSIDFromString(
        XPRT::TBstr("{8C18D311-BF86-11d2-8AA9-0060B0A4B986}").GetString(), &id);
    XpcsRegisterClass(&id, filename.GetString());

    XpcsCLSIDFromString(
        XPRT::TBstr("{99485411-9FF2-11d2-8A80-0060B0A4B986}").GetString(), &id);
    XpcsRegisterClass(&id, filename.GetString());
}
