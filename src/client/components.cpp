#define WINVERAPI
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <new>

static char *component_xml;
HINSTANCE client_instance;
unsigned int component_error;
int registrations_changed;
char error_path[0x100];
char expected_version[0x80];
char actual_version[0x80];

const GUID build_registration =
    {0xd5ddcef8, 0x17c0, 0x4d33, {0xba, 0x01, 0x93, 0x38, 0x59, 0x8d, 0xe6, 0xef}};

// enumeration continues after unregistering each class.
int __stdcall unregister_component(const GUID *id, const unsigned short *, void *)
{
    XpcsUnregisterClass(id);
    return 0;
}

// 0x402185 and 0x4021b4 distinguish the build marker from DLL registrations.
int __stdcall copy_dll_registration(const GUID *id, const unsigned short *value, void *destination)
{
    if (guid_equal(id, &build_registration))
        return 0;
    xprt_wcscpy(static_cast<unsigned short *>(destination), value);
    return 1;
}

int __stdcall copy_build_version(const GUID *id, const unsigned short *value, void *destination)
{
    int result;
    if (guid_equal(id, &build_registration)) {
        xprt_wcscpy(static_cast<unsigned short *>(destination), value);
        result = 1;
    } else {
        result = 0;
    }
    return result;
}

// each dependency supplies the version scheme used by its children.
const char **dependency_attributes(ComponentContext *context, const char **attributes)
{
    context->register_needed = 0;
    context->load = 0;
    context->check_version = 1;
    context->xpcs_directory = 0;
    context->class_token[0] = 0;

    const char **cursor = attributes;
    if (*cursor) {
        do {
        const char *name = cursor[0];
        const char *value = cursor[1];
        if (!_stricmp("version", name)) {
            if (!_stricmp("cool_build_number", value)) {
                value = "2289";
                strcpy(context->version_query, "\\StringFileInfo\\040904b0\\ProductVersion");
                strcpy(context->class_query, "\\StringFileInfo\\040904b0\\ModuleClassID");
            } else if (!_stricmp("version_build_number", value)) {
                value = "6089";
                sprintf(context->version_query, "\\StringFileInfo\\%s\\ProductVersion", "040904E4");
                sprintf(context->class_query, "\\StringFileInfo\\%s\\ModuleClassID", "040904E4");
            } else {
                value = "UNKNOWN VERSION TAG";
            }
            strcpy(context->version, value);
        } else if (!_stricmp("name", name)) {
            strcpy(context->name, value);
        } else if (!_stricmp("regNeeded", name)) {
            if (!_stricmp("Y", value))
                context->register_needed = registrations_changed;
        } else if (!_stricmp("load", name)) {
            if (!_stricmp("Y", value))
                context->load = 1;
        } else if (!_stricmp("checkVersion", name)) {
            if (!_stricmp("N", value))
                context->check_version = 0;
        } else if (!_stricmp("xpcsDir", name)) {
            if (!_stricmp("Y", value))
                context->xpcs_directory = 1;
        }
        cursor = attributes + 2;
        attributes = cursor;
    } while (*cursor);
    }
    return cursor;
}

// return the final dotted component of a version-resource string.
int query_file_version(const char *filename, const char *query, char *value, int capacity)
{
    int found = 0;
    DWORD ignored;
    DWORD bytes = GetFileVersionInfoSizeA(filename, &ignored);
    char *resource = static_cast<char *>(operator new[](bytes));
    if (resource) {
        char *text;
        UINT length;
        if (GetFileVersionInfoA(filename, ignored, bytes, resource)) {
            char scratch[0xff];
            memset(scratch, 0, sizeof(scratch));
            if (VerQueryValueA(resource, const_cast<char *>(query), reinterpret_cast<void **>(&text), &length)) {
            // The original copies before applying the capacity limit.
            sprintf(value, "%s", text);
            char *last_dot = strrchr(text, '.');
            if (last_dot)
                strncpy(value, last_dot + 1, capacity);
            else
                strncpy(value, text, capacity);
            found = 1;
            }
        }
        operator delete(resource);
    }
    return found;
}

// retain the most recent failure for the later localized error box.
int record_component_error(ComponentContext *context, const char *filename, const char *version)
{
    ++context->errors;
    if (filename) {
        if (!component_error)
            component_error = 0x771;
        strcpy(context->error_path, filename);
        strcpy(expected_version, context->version);
        strcpy(error_path, context->error_path);
        strcpy(actual_version, version);
    }
    return 0;
}

// configure the manager's creation and lifetime policies from XML.
int managed_component_attributes(ComponentContext *context, const char **attributes)
{
    char name[0x105];
    char clsid[0x105];
    int has_clsid = 0;
    int lifetime = 1;
    int creation = 2;
    int auto_listeners = 0;
    strcpy(name, "NO NAME");
    const char **cursor = attributes;
    if (*cursor) {
        do {
        const char *key = cursor[0];
        const char *value = cursor[1];
        if (!_stricmp("clsid", key)) {
            has_clsid = 1;
            xprt_strlcpy(clsid, value, sizeof(clsid));
        } else if (!_stricmp("name", key)) {
            xprt_strlcpy(name, value, sizeof(name));
        } else if (!_stricmp("create_option", key)) {
            if (!_stricmp("ON_DEMAND", value)) creation = 8;
            else if (!_stricmp("ON_SIGNEDON", value)) creation = 4;
            else if (!_stricmp("ON_SYSTEM_INIT", value)) creation = 1;
        } else if (!_stricmp("keep_alive", key)) {
            if (!_stricmp("UNTIL_NOTREFED", value)) lifetime = 4;
            else if (!_stricmp("UNTIL_SIGNOFF", value)) lifetime = 2;
        } else if (!_stricmp("auto_reg_listeners", key) && !_stricmp("Y", value)) {
            auto_listeners = 1;
        }
        cursor = attributes + 2;
        attributes = cursor;
    } while (*cursor);
    }
    int result;
    if (has_clsid && AimAppAddManagedComponent(clsid, context->filename, context->leaf_name, name,
            context->register_needed, context->required, creation, lifetime, auto_listeners) < 0) {
        component_error = 0x773;
        result = 0;
    } else {
        result = 1;
    }
    return result;
}

// the matching start callback increments this nesting depth.
void __cdecl component_end(void *user, const char *)
{
    --static_cast<ComponentContext *>(user)->depth;
}

// message text comes from the installed resource DLL.
int show_startup_error()
{
    HMODULE resources = LoadLibraryA("aimres.dll");
    OscoreInitLpShare(client_instance, 0);
    ErrorBox(resources, 0x770);
    FreeLibrary(resources);
    return 0;
}

int show_component_error()
{
    HMODULE resources = LoadLibraryA("aimres.dll");
    OscoreInitLpShare(client_instance, "");
    if (!component_error)
        component_error = 0x771;
    ErrorBox(resources, component_error, error_path, actual_version, expected_version);
    FreeLibrary(resources);
    return 0;
}

// a changed build marker requires a writable registry directory.
int registry_needs_update(const char *directory, int *update)
{
    unsigned short version[0x104];
    version[0] = 0;
    XpcsEnumRegistrations(copy_build_version, version);
    XPRT::TBstr previous(version);
    XPRT::TBstr current("6089");
    previous.GetMultibyteString();
    if (!previous.CompareNoCase(current.GetString())) {
        *update = 0;
        return 1;
    }
    *update = 1;
    XPRT::TBstr registry(directory);
    registry.Append("\\Xpcs Registry.dat");
    return registry_writable(directory);
}

// validate a dependency DLL, and register it when rebuilding XPCS.
int assembly_attributes(ComponentContext *context, const char **attributes)
{
    int check_version = context->check_version;
    context->required = 0;
    char name[0x108];
    name[0] = 0;
    const char **cursor = attributes;
    if (*cursor) {
        do {
            const char *key = cursor[0];
            const char *value = cursor[1];
            if (!_stricmp("name", key)) {
                strcpy(name, value);
            } else if (!_stricmp("ClassToken", key)) {
                strcpy(context->class_token, value);
            } else if (!_stricmp("Required", key)) {
                if (!_stricmp("Y", value)) context->required = 1;
            }
            cursor = attributes + 2;
            attributes = cursor;
        } while (*cursor);
    }
    char version[0x108];
    version[0] = 0;
    char filename[0x108];
    sprintf(filename, "%s%s", context->xpcs_directory ? context->registry_directory : context->app_directory, name);
    int result;
    if (_access(filename, 0) != -1 || context->required) {
        int found = query_file_version(filename, context->version_query, version, 0x104);
        if (!check_version || found || !context->required) {
            xprt_strlcpy(context->filename, filename, sizeof(context->filename));
            xprt_strlcpy(context->leaf_name, name, sizeof(context->leaf_name));
            if (check_version && (!found || strcmp(version, context->version))) {
                record_component_error(context, filename, version);
            } else if (context->register_needed) {
                bool failed = XpcsRegisterServer(XPRT::TBstr(filename).GetString()) < 0;
                if (failed) {
                    component_error = 0x773;
                    record_component_error(context, filename, version);
                }
            }
            result = 1;
        } else {
            component_error = 0x773;
            result = record_component_error(context, filename, version);
        }
    } else {
        result = 1;
    }
    return result;
}

// Expat supplies alternating attribute names and values.
void __cdecl component_start(void *user, const char *element, const char **attributes)
{
    ComponentContext *context = static_cast<ComponentContext *>(user);
    ++context->depth;
    if (!_stricmp("dependency", element)) dependency_attributes(context, attributes);
    else if (!_stricmp("assemblyIdentity", element)) assembly_attributes(context, attributes);
    else if (!_stricmp("aimManager", element)) managed_component_attributes(context, attributes);
}

// parser failures and component failures use different error IDs.
int parse_components(const char *app_directory, const char *registry_directory, const char *xml)
{
    XmlParser parser = XML_ParserCreate(0);
    ComponentContext *context = static_cast<ComponentContext *>(allocate_zeroed(sizeof(ComponentContext)));
    // The original assumes both allocations succeed.
    context->depth = 0;
    context->errors = 0;
    if (app_directory) strcpy(context->app_directory, app_directory);
    if (registry_directory) strcpy(context->registry_directory, registry_directory);
    XML_SetUserData(parser, context);
    XML_SetElementHandler(parser, component_start, component_end);
    int result;
    if (!XML_Parse(parser, xml, strlen(xml), 1)) {
        int line = XML_GetCurrentLineNumber(parser);
        strncpy(error_path, XML_ErrorString(XML_GetErrorCode(parser)), 0xff);
        _itoa(line, actual_version, 10);
        component_error = 0x772;
        result = 0;
    } else {
        result = context->errors == 0;
    }
    XML_ParserFree(parser);
    free(context);
    return result;
}

// the component inventory is an embedded XML resource.
int parse_component_resource(const char *app_directory, const char *registry_directory)
{
    HRSRC resource = FindResourceA(0, MAKEINTRESOURCEA(1000), "STRING");
    if (resource) {
    HGLOBAL data = LoadResource(0, resource);
    if (data && LockResource(data)) {
        DWORD length = SizeofResource(0, resource);
        component_xml = static_cast<char *>(allocate_zeroed(length + 1));
        strncpy(component_xml, static_cast<const char *>(data), length);
        component_xml[length] = 0;
        int result = parse_components(app_directory, registry_directory, component_xml);
        free(component_xml);
        component_xml = 0;
        return result;
    }
    if (data) FreeResource(data);
    }
    return 0;
}

// validate registration, retry once after rebuilding, then probe a
// core component. The probe only uses IUnknown::Release; no class is invented.
int initialize_components(HINSTANCE instance, int force_registration)
{
    client_instance = instance;
    int result = 1;
    int update = 0;
    registrations_changed = 0;
    component_error = 0;
    char app_filename[0x104];
    if (!GetModuleFileNameA(GetModuleHandleA(0), app_filename, sizeof(app_filename)))
        return show_startup_error();
    XPRT::TBstr app_directory(app_filename);
    app_directory.Assign(app_directory.Left(app_directory.ReverseFind('\\') + 1));
    HMODULE xpcs = LoadLibraryA("Xpcs.dll");
    char registry_filename[0x104];
    if (!xpcs || !GetModuleFileNameA(xpcs, registry_filename, sizeof(registry_filename))) {
        result = show_startup_error();
    } else {
        FreeLibrary(xpcs);
        XPRT::TBstr registry_directory(registry_filename);
        registry_directory.Assign(registry_directory.Left(registry_directory.ReverseFind('\\') + 1));
        unsigned short registered_path[0x104];
        registered_path[0] = 0;
        XpcsEnumRegistrations(copy_dll_registration, registered_path);
        XPRT::TBstr old_directory(registered_path);
        old_directory.Assign(old_directory.Left(old_directory.ReverseFind('\\') + 1));
        if (!registry_needs_update(registry_directory.GetMultibyteString(), &update)) {
            return show_startup_error();
        } else {
            if (registry_directory.CompareNoCase(old_directory.GetString())) update = 1;
            if (force_registration) update = 1;
            static const GUID probe_class = {0x9da00fb0, 0xbf6a, 0x11d2, {0xa0, 0x0c, 0x00, 0x60, 0xb0, 0x88, 0x3b, 0x25}};
            static const GUID probe_interface = {0xefd2eec0, 0xbc44, 0x11d2, {0xa0, 0x0a, 0x00, 0x60, 0xb0, 0x88, 0x3b, 0x25}};
            for (;;) {
                if (update) {
                    if (!registry_writable(app_directory.GetMultibyteString())) {
                        return show_startup_error();
                    }
                    registrations_changed = 1;
                    XpcsEnumRegistrations(unregister_component, 0);
                    register_cool_utils(app_directory.GetMultibyteString());
                }
                const char *app_path = app_directory.GetMultibyteString();
                const char *registry_path = registry_directory.GetMultibyteString();
                if (!parse_component_resource(app_path, registry_path))
                    return show_component_error();
                if (registrations_changed)
                    XpcsRegisterClass(&build_registration, XPRT::TBstr("6089").GetString());
                if (app_directory.CompareNoCase(registry_directory.GetString())) {
                    result = show_startup_error();
                }
                if (result == 1) {
                    IUnknown *probe;
                    if (XpcsCreateSimpleInstance(&probe_class, &probe_interface, reinterpret_cast<void **>(&probe)) >= 0) {
                        probe->Release();
                    } else {
                        update = !update;
                        if (!update) {
                            result = show_startup_error();
                        }
                        if (result == 1 && update == 1)
                            continue;
                    }
                }
                break;
            }
        }
    }
    return result;
}
