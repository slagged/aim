#include <windows.h>
#include <string.h>

/* Select the AIM URL action for this helper. */
#ifndef AIM_ACTION
#define AIM_ACTION "SendFile"
#endif

/*
 * Open the command-line file argument in AIM's SendFile or ShareFile UI.
 * Find the registered AIM executable, then launch it with an action URL:
 *     AIM:SendFile?FileName=<argument>
 */
int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    int result = -1;
    char *cursor = GetCommandLineA();
    char *application;
    char *command = cursor;
    bool quoted = false;

    if (cursor) {
        /* Reuse one buffer for the registered handler and the launch command. */
        DWORD bytes = lstrlenA(cursor) + 0x10b;
        char *buffer = (char *)HeapAlloc(GetProcessHeap(), 0, bytes);

        application = buffer;

        if (buffer) {
            *buffer = 0;

            /* Find the first space outside the executable name's quotes.
             * There is no NUL stop: without a separating space, this loop
             * reads past the end of the command line.
             */
            while ((*cursor && quoted) || *cursor != ' ') {
                if (*cursor == '"')
                    quoted = !quoted;

                ++cursor;
            }

            /* Forward the remaining command line, including its leading space. */
            command = cursor;

            if (*cursor) {
                STARTUPINFOA startup;
                PROCESS_INFORMATION process;
                HKEY key;
                char executable[MAX_PATH];

                {{initialization}}

                /* Read the command registered for aim: URLs. A successful
                 * key open leads to parsing even if the value query fails.
                 */
                if (RegOpenKeyExA(HKEY_CLASSES_ROOT, "aim\\shell\\open\\command", 0, KEY_READ, &key) == ERROR_SUCCESS) {
                    LONG length = bytes;
                    RegQueryValueA(key, NULL, buffer, &length);
                    RegCloseKey(key);

                    if (*buffer == '"') {
                        /* Drop the opening quote and terminate at the closing
                         * quote, leaving only the executable path.
                         */
                        {{quoted_branch}}
                    } else {
                        /* Remove trailing handler arguments by searching
                         * backwards for .exe. Values shorter than four bytes
                         * put the starting pointer before the buffer.
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

                    /* Quote the executable and append the file-action URL.
                     * The argument is not URL-escaped: '&' and '?' in a file
                     * name can change how AIM interprets the URL.
                     */
                    wsprintfA(
                        buffer,
                        "\"%s\"%s%s",
                        executable,
                        " AIM:" AIM_ACTION "?FileName=",
                        command
                    );

                    /* Launch the registered executable directly. Returned
                     * process and thread handles are left open.
                     */
                    result = CreateProcessA(
                        executable, buffer, NULL, NULL, FALSE,
                        0, NULL, NULL, &startup, &process
                    ) ? 0 : -1;
                }

                /* Free the scratch buffer only on the argument-handling path. */
                HeapFree(GetProcessHeap(), 0, buffer);
            }
        }
    }

    return result;
}
