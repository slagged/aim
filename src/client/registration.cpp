#include "client.h"
#include <stdio.h>
#include <string.h>
#include <io.h>

// Write a string value only after opening its key successfully.
static LONG registry_string(HKEY root, const char *path, const char *name, const char *value)
{
    HKEY key = 0;
    DWORD disposition;
    LONG result = RegCreateKeyExA(root, path, 0, 0, REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS, 0, &key, &disposition);
    if (!result)
        result = RegSetValueExA(key, name, 0, REG_SZ,
            reinterpret_cast<const BYTE *>(value), strlen(value) + 1);
    if (key)
        RegCloseKey(key);
    return result;
}

// publish the aim: URL handler and its automation COM identity.
int __stdcall register_protocols(HMODULE instance, const char *directory)
{
    char command[0x104];
    if (!GetModuleFileNameA(instance, command, sizeof(command)))
        return 0;
    // The historical command uses an unquoted executable path and argument.
    lstrcatA(command, " %1");
    registry_string(HKEY_CLASSES_ROOT, "aim", "", "URL: AOL Instant Messenger Protocol");
    registry_string(HKEY_CLASSES_ROOT, "aim", "URL Protocol", "");
    registry_string(HKEY_CLASSES_ROOT, "aim\\shell\\open\\command", "", command);

    const char *class_id = "{BAEB32D0-732D-11d2-8BF4-0060B0A4A9EA}";
    const char *description = "AIM OLE Automation Protocol Handler";
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol", "", description);
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol\\CurVer", "", "AIM.Protocol.1");
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol\\CLSID", "", class_id);
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol\\NotInsertable", "", "");
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol.1", "", description);
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol.1\\CLSID", "", class_id);
    registry_string(HKEY_CLASSES_ROOT, "AIM.Protocol.1\\NotInsertable", "", "");

    char path[0x104];
    sprintf(path, "CLSID\\%s", class_id);
    registry_string(HKEY_CLASSES_ROOT, path, "", description);
    const char *keys[] = {"Programmable", "ProgID", "VersionIndependentProgID", "InprocHandler32", "LocalServer32"};
    char server[0x104];
    sprintf(server, "%saimauto.exe", directory);
    const char *values[] = {"", "AIM.Protocol.1", "AIM.Protocol", "ole32.dll", server};
    for (int i = 0; i < 5; ++i) {
        sprintf(path, "CLSID\\%s\\%s", class_id, keys[i]);
        registry_string(HKEY_CLASSES_ROOT, path, "", values[i]);
    }
    HKEY navigator = 0;
    LONG result = RegOpenKeyA(HKEY_CURRENT_USER,
        "Software\\Netscape\\Netscape Navigator\\Automation Protocols", &navigator);
    if (!result)
        result = RegSetValueExA(navigator, "aim", 0, REG_SZ,
            reinterpret_cast<const BYTE *>("AIM.Protocol.1"), strlen("AIM.Protocol.1") + 1);
    if (navigator) RegCloseKey(navigator);
    return result;
}

// recover a missing installed file from the newest six-character
// backup stem, then remove leftover backups matching that stem.
int restore_backups(HINSTANCE instance)
{
    char filename[0x104];
    char pattern[0x104];
    if (!GetModuleFileNameA(0, filename, sizeof(filename)))
        return show_startup_error();
    char *leaf = strrchr(filename, '\\');
    if (leaf)
        leaf[1] = 0;
    int directory_length = strlen(filename);
    strcpy(pattern, filename);
    for (unsigned int id = 2; LoadStringA(instance, id, filename + directory_length,
            sizeof(filename) - directory_length); ++id) {
        strcpy(pattern + directory_length, filename + directory_length);
        char *extension = strrchr(filename, '.');
        pattern[directory_length + 6] = 0;
        lstrcatA(pattern, "~*");
        if (extension) lstrcatA(pattern, extension);
        WIN32_FIND_DATAA entry;
        if (_access(filename, 0) != 0) {
            FILETIME newest = {0, 0};
            char backup[0x104] = "";
            HANDLE search = FindFirstFileA(pattern, &entry);
            if (search != INVALID_HANDLE_VALUE) {
                do {
                    if (entry.cFileName[6] == '~' && file_time_before(&newest, &entry.ftLastWriteTime)) {
                        newest = entry.ftLastWriteTime;
                        strcpy(backup, entry.cFileName);
                    }
                } while (FindNextFileA(search, &entry));
                FindClose(search);
            }
            if (newest.dwHighDateTime || newest.dwLowDateTime) {
                char source[0x104];
                strncpy(source, filename, directory_length);
                strcpy(source + directory_length, backup);
                MoveFileA(source, filename);
            }
        }
        HANDLE search = FindFirstFileA(pattern, &entry);
        if (search != INVALID_HANDLE_VALUE) {
            do {
                if (entry.cFileName[6] == '~') {
                    char backup[0x104];
                    strncpy(backup, filename, directory_length);
                    strcpy(backup + directory_length, entry.cFileName);
                    DeleteFileA(backup);
                }
            } while (FindNextFileA(search, &entry));
            FindClose(search);
        }
    }
    return 1;
}

// register the API/video servers, and repair the Boxely COM server
// when its activation fails. Missing libraries do not themselves set failure.
int register_servers(HMODULE instance, const char *procedure)
{
    char executable[0x104];
    GetModuleFileNameA(GetModuleHandleA(0), executable, sizeof(executable));
    XPRT::TBstr directory(executable);
    directory.Assign(directory.Left(directory.ReverseFind('\\') + 1));
    register_protocols(instance, directory.GetMultibyteString());
    if (!procedure || !*procedure)
        procedure = "DllRegisterServer";
    typedef HRESULT (__stdcall *RegisterServer)();
    int result = 1;
    const char *servers[] = {"AimApi.dll", "rtvideo.dll"};
    for (int i = 0; i < 2; ++i) {
        XPRT::TBstr filename(directory);
        filename.Append(servers[i]);
        HMODULE library = LoadLibraryA(filename.GetMultibyteString());
        if (library) {
            RegisterServer registration = reinterpret_cast<RegisterServer>(GetProcAddress(library, procedure));
            if (registration) registration();
            else result = 0;
        }
        FreeLibrary(library);
    }
    const GUID boxely_class = {0x189504b8, 0x50d1, 0x4aa8, {0xb4, 0xd6, 0x95, 0xc8, 0xf5, 0x8a, 0x64, 0x14}};
    IUnknown *object;
    if (CoCreateInstance(boxely_class, 0, CLSCTX_INPROC_SERVER | CLSCTX_INPROC_HANDLER,
            IID_IUnknown, reinterpret_cast<void **>(&object)) >= 0) {
        object->Release();
    } else {
        XPRT::TBstr filename(directory);
        filename.Append("sb.dll");
        HMODULE library = LoadLibraryA(filename.GetMultibyteString());
        if (library) {
            RegisterServer registration = reinterpret_cast<RegisterServer>(GetProcAddress(library, procedure));
            if (registration) registration();
            else result = 0;
            FreeLibrary(library);
        }
    }
    return result;
}
