#include <windows.h>
#include <string.h>

// Compare the complete GUID, including fields beyond its first DWORD.
int guid_equal(const GUID *left, const GUID *right)
{
    return memcmp(left, right, sizeof(GUID)) == 0;
}
