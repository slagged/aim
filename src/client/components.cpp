#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <new>

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
    if (!guid_equal(id, &build_registration))
        return 0;
    xprt_wcscpy(static_cast<unsigned short *>(destination), value);
    return 1;
}

// each dependency supplies the version scheme used by its children.
const char **dependency_attributes(ComponentContext *context, const char **attributes)
{
    context->register_needed = 0;
    context->load = 0;
    context->check_version = 1;
    context->xpcs_directory = 0;
    context->class_token[0] = 0;

    while (attributes && *attributes) {
        const char *name = attributes[0];
        const char *value = attributes[1];
        if (!_stricmp(name, "version")) {
            if (!_stricmp(value, "cool_build_number")) {
                strcpy(context->version, "2289");
                strcpy(context->version_query, "\\StringFileInfo\\040904b0\\ProductVersion");
                strcpy(context->class_query, "\\StringFileInfo\\040904b0\\ModuleClassID");
            } else if (!_stricmp(value, "version_build_number")) {
                strcpy(context->version, "6089");
                sprintf(context->version_query, "\\StringFileInfo\\%s\\ProductVersion", "040904E4");
                sprintf(context->class_query, "\\StringFileInfo\\%s\\ModuleClassID", "040904E4");
            } else {
                strcpy(context->version, "UNKNOWN VERSION TAG");
            }
        } else if (!_stricmp(name, "name")) {
            strcpy(context->name, value);
        } else if (!_stricmp(name, "regNeeded") && !_stricmp(value, "Y")) {
            context->register_needed = registrations_changed;
        } else if (!_stricmp(name, "load") && !_stricmp(value, "Y")) {
            context->load = 1;
        } else if (!_stricmp(name, "checkVersion") && !_stricmp(value, "N")) {
            context->check_version = 0;
        } else if (!_stricmp(name, "xpcsDir") && !_stricmp(value, "Y")) {
            context->xpcs_directory = 1;
        }
        attributes += 2;
    }
    return attributes;
}

// return the final dotted component of a version-resource string.
int query_file_version(const char *filename, const char *query, char *value, int capacity)
{
    DWORD ignored;
    DWORD bytes = GetFileVersionInfoSizeA(filename, &ignored);
    char *resource = static_cast<char *>(operator new[](bytes));
    int found = 0;
    if (resource) {
        char *text;
        UINT length;
        if (GetFileVersionInfoA(filename, ignored, bytes, resource)
                && VerQueryValueA(resource, const_cast<char *>(query), reinterpret_cast<void **>(&text), &length)) {
            // The original copies before applying the capacity limit.
            sprintf(value, "%s", text);
            char *last_dot = strrchr(text, '.');
            strncpy(value, last_dot ? last_dot + 1 : text, capacity);
            found = 1;
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
    char name[0x105] = "NO NAME";
    char clsid[0x105];
    int has_clsid = 0;
    int lifetime = 1;
    int creation = 2;
    int auto_listeners = 0;
    if (!attributes)
        return 1;
    for (; *attributes; attributes += 2) {
        const char *key = attributes[0];
        const char *value = attributes[1];
        if (!_stricmp(key, "clsid")) {
            xprt_strlcpy(clsid, value, sizeof(clsid));
            has_clsid = 1;
        } else if (!_stricmp(key, "name")) {
            xprt_strlcpy(name, value, sizeof(name));
        } else if (!_stricmp(key, "create_option")) {
            if (!_stricmp(value, "ON_DEMAND")) creation = 8;
            else if (!_stricmp(value, "ON_SIGNEDON")) creation = 4;
            else if (!_stricmp(value, "ON_SYSTEM_INIT")) creation = 1;
        } else if (!_stricmp(key, "keep_alive")) {
            if (!_stricmp(value, "UNTIL_NOTREFED")) lifetime = 4;
            else if (!_stricmp(value, "UNTIL_SIGNOFF")) lifetime = 2;
        } else if (!_stricmp(key, "auto_reg_listeners") && !_stricmp(value, "Y")) {
            auto_listeners = 1;
        }
    }
    if (!has_clsid)
        return 1;
    if (AimAppAddManagedComponent(clsid, context->filename, context->leaf_name, name,
            context->register_needed, context->required, creation, lifetime, auto_listeners) >= 0)
        return 1;
    component_error = 0x773;
    return 0;
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

// three utility classes share the same DLL registration path.
void register_cool_utils(const char *directory)
{
    XPRT::TBstr filename(directory);
    filename.Append("CoolUtils.dll");
    const char *ids[] = {
        "{648EDF60-2501-11d3-90DC-0060B088CB02}",
        "{8C18D311-BF86-11d2-8AA9-0060B0A4B986}",
        "{99485411-9FF2-11d2-8A80-0060B0A4B986}"
    };
    for (int i = 0; i < 3; ++i) {
        GUID id;
        XPRT::TBstr text(ids[i]);
        XpcsCLSIDFromString(text.GetString(), &id);
        XpcsRegisterClass(&id, filename.GetString());
    }
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
    char name[0x104] = "";
    char version[0x104] = "";
    char filename[0x104];
    context->required = 0;
    for (; attributes && *attributes; attributes += 2) {
        if (!_stricmp(attributes[0], "name")) strcpy(name, attributes[1]);
        else if (!_stricmp(attributes[0], "ClassToken")) strcpy(context->class_token, attributes[1]);
        else if (!_stricmp(attributes[0], "Required") && !_stricmp(attributes[1], "Y")) context->required = 1;
    }
    sprintf(filename, "%s%s", context->xpcs_directory ? context->registry_directory : context->app_directory, name);
    if (_access(filename, 0) == -1 && !context->required)
        return 1;
    int found = query_file_version(filename, context->version_query, version, sizeof(version));
    if (context->check_version && !found && context->required) {
        component_error = 0x773;
        return record_component_error(context, filename, version);
    }
    xprt_strlcpy(context->filename, filename, sizeof(context->filename));
    xprt_strlcpy(context->leaf_name, name, sizeof(context->leaf_name));
    if (context->check_version && (!found || strcmp(version, context->version))) {
        record_component_error(context, filename, version);
    } else if (context->register_needed) {
        XPRT::TBstr wide_filename(filename);
        if (XpcsRegisterServer(wide_filename.GetString()) < 0) {
            component_error = 0x773;
            record_component_error(context, filename, version);
        }
    }
    return 1;
}

// Expat supplies alternating attribute names and values.
void __cdecl component_start(void *user, const char *element, const char **attributes)
{
    ComponentContext *context = static_cast<ComponentContext *>(user);
    ++context->depth;
    if (!_stricmp(element, "dependency")) dependency_attributes(context, attributes);
    else if (!_stricmp(element, "assemblyIdentity")) assembly_attributes(context, attributes);
    else if (!_stricmp(element, "aimManager")) managed_component_attributes(context, attributes);
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
    if (XML_Parse(parser, xml, strlen(xml), 1)) {
        result = context->errors == 0;
    } else {
        int line = XML_GetCurrentLineNumber(parser);
        strncpy(error_path, XML_ErrorString(XML_GetErrorCode(parser)), 0xff);
        _itoa(line, actual_version, 10);
        component_error = 0x772;
        result = 0;
    }
    XML_ParserFree(parser);
    free(context);
    return result;
}

// the component inventory is an embedded XML resource.
int parse_component_resource(const char *app_directory, const char *registry_directory)
{
    HRSRC resource = FindResourceA(0, MAKEINTRESOURCEA(1000), "STRING");
    if (!resource)
        return 0;
    HGLOBAL data = LoadResource(0, resource);
    if (data && LockResource(data)) {
        DWORD length = SizeofResource(0, resource);
        char *xml = static_cast<char *>(allocate_zeroed(length + 1));
        strncpy(xml, static_cast<const char *>(data), length);
        xml[length] = 0;
        int result = parse_components(app_directory, registry_directory, xml);
        free(xml);
        return result;
    }
    if (data) FreeResource(data);
    return 0;
}

// validate registration, retry once after rebuilding, then probe a
// core component. The probe only uses IUnknown::Release; no class is invented.
int initialize_components(HINSTANCE instance, int force_registration)
{
    client_instance = instance;
    registrations_changed = 0;
    component_error = 0;
    char filename[0x104];
    if (!GetModuleFileNameA(GetModuleHandleA(0), filename, sizeof(filename)))
        return show_startup_error();
    XPRT::TBstr app_directory(filename);
    app_directory.Assign(app_directory.Left(app_directory.ReverseFind('\\') + 1));
    HMODULE xpcs = LoadLibraryA("Xpcs.dll");
    if (!xpcs || !GetModuleFileNameA(xpcs, filename, sizeof(filename)))
        return show_startup_error();
    FreeLibrary(xpcs);
    XPRT::TBstr registry_directory(filename);
    registry_directory.Assign(registry_directory.Left(registry_directory.ReverseFind('\\') + 1));
    unsigned short registered_path[0x104];
    registered_path[0] = 0;
    XpcsEnumRegistrations(copy_dll_registration, registered_path);
    XPRT::TBstr old_directory(registered_path);
    old_directory.Assign(old_directory.Left(old_directory.ReverseFind('\\') + 1));
    int update = 0;
    if (!registry_needs_update(registry_directory.GetMultibyteString(), &update))
        return show_startup_error();
    if (registry_directory.CompareNoCase(old_directory.GetString()) || force_registration)
        update = 1;
    const GUID probe_class = {0x9da00fb0, 0xbf6a, 0x11d2, {0xa0, 0x0c, 0x00, 0x60, 0xb0, 0x88, 0x3b, 0x25}};
    const GUID probe_interface = {0xefd2eec0, 0xbc44, 0x11d2, {0xa0, 0x0a, 0x00, 0x60, 0xb0, 0x88, 0x3b, 0x25}};
    for (;;) {
        if (update) {
            if (!registry_writable(app_directory.GetMultibyteString()))
                return show_startup_error();
            registrations_changed = 1;
            XpcsEnumRegistrations(unregister_component, 0);
            register_cool_utils(app_directory.GetMultibyteString());
        }
        if (!parse_component_resource(app_directory.GetMultibyteString(), registry_directory.GetMultibyteString()))
            return show_component_error();
        if (registrations_changed) {
            XPRT::TBstr version("6089");
            XpcsRegisterClass(&build_registration, version.GetString());
        }
        if (app_directory.CompareNoCase(registry_directory.GetString()))
            return show_startup_error();
        IUnknown *probe;
        if (XpcsCreateSimpleInstance(&probe_class, &probe_interface, reinterpret_cast<void **>(&probe)) >= 0) {
            probe->Release();
            return 1;
        }
        update = !update;
        if (!update)
            return show_startup_error();
    }
}
