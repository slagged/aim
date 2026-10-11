#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Compare the complete GUID, including fields beyond its first DWORD.
int guid_equal(const GUID *left, const GUID *right)
{
    return memcmp(left, right, sizeof(GUID)) == 0;
}

// Compare the high halves first, then resolve ties with the low halves.
bool file_time_before(const FILETIME *left, const FILETIME *right)
{
    bool before = left->dwHighDateTime < right->dwHighDateTime;
    if (left->dwHighDateTime == right->dwHighDateTime)
        before = left->dwLowDateTime < right->dwLowDateTime;

    return before;
}

// Clear a successful allocation; preserve malloc's null result on failure.
void *allocate_zeroed(unsigned int bytes)
{
    void *buffer = malloc(bytes);
    if (buffer)
        memset(buffer, 0, bytes);

    return buffer;
}
