#include <windows.h>
#include <string.h>

/* One source builds both helpers; the ShareFile build overrides this action. */
#ifndef AIM_ACTION
#define AIM_ACTION "SendFile"
#endif

/*
 * Forward a command-line file argument to the registered AIM URL handler:
 *     AIM:SendFile?FileName=<argument>
 * or AIM:ShareFile for the other build.
 *
 * The helper reads the handler's executable from the registry and constructs
 * a new process command line. This matching reconstruction preserves the
 * original parsing and cleanup quirks. It has been compiled and compared,
 * but has not been executed by the workbench.
 */
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    int result = -1;
    char *cursor = GetCommandLineA();
    char *application;
    char *command = cursor;
    bool quoted = false;

    if (cursor) {
        /* The original reserves this fixed amount beyond the input length.
         * The buffer first holds the registry value, then the launch command.
         */
        DWORD bytes = lstrlenA(cursor) + 0x10b;
        char *buffer = (char *)HeapAlloc(GetProcessHeap(), 0, bytes);

        application = buffer;

        if (buffer) {
            *buffer = 0;

            /* Skip our executable name, tracking quotes around that name.
             * Keep the original condition: there is no terminating-NUL guard,
             * so input without a separating space can read beyond the string.
             */
            while ((*cursor && quoted) || *cursor != ' ') {
                if (*cursor == '"')
                    quoted = !quoted;

                ++cursor;
            }

            /* Keep the separating space as part of the forwarded argument. */
            command = cursor;

            if (*cursor) {
                STARTUPINFOA startup;
                PROCESS_INFORMATION process;
                HKEY key;
                char executable[MAX_PATH];

                /* Statement order reproduces the original initialization. */
                executable[0] = 0;
                ZeroMemory(&startup, sizeof(startup));
                startup.cb = sizeof(startup);
                ZeroMemory(&process, sizeof(process));

                /* Use the executable registered for aim: URLs. The original
                 * does not check the value-query result before parsing it.
                 */
                if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "aim\\shell\\open\\command", 0, KEY_READ, &key) == ERROR_SUCCESS) {
                    LONG length = bytes;
                    RegQueryValueA(key, NULL, buffer, &length);
                    RegCloseKey(key);

                    if (*buffer == '"') {
                        /* Quoted registration: retain only the quoted path. */
                        char *end = buffer + 1;

                        application = end;

                        while (*end && *end != '"')
                            ++end;

                        *end = 0;
                    } else {
                        /* Unquoted registration: trim backwards until the
                         * remaining text ends in .exe, ignoring case. This
                         * also retains the original short-string assumptions.
                         */
                        char *end = buffer + strlen(buffer) - 4;

                        while (end > buffer) {
                            if (lstrcmpiA(end, ".exe") == 0)
                                break;

                            --end;
                            end[4] = 0;
                        }
                    }
                }

                if (lstrlenA(application) < MAX_PATH) {
                    lstrcpyA(executable, application);

                    /* Arguments go into the URL verbatim, without escaping.
                     * The original also leaves the returned process/thread
                     * handles open after a successful launch.
                     */
                    wsprintfA(
                        buffer,
                        "\"%s\"%s%s",
                        executable,
                        " AIM:" AIM_ACTION "?FileName=",
                        command
                    );

                    result = CreateProcessA(
                        executable, buffer, NULL, NULL, FALSE,
                        0, NULL, NULL, &startup, &process
                    ) ? 0 : -1;
                }

                /* Preserve the original cleanup scope: a path that skips
                 * this argument block also skips freeing the allocation.
                 */
                HeapFree(GetProcessHeap(), 0, buffer);
            }
        }
    }

    return result;
}
