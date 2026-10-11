#include <windows.h>

// Compare the high halves first, then resolve ties with the low halves.
bool file_time_before(const FILETIME *left, const FILETIME *right)
{
    bool before = left->dwHighDateTime < right->dwHighDateTime;
    if (left->dwHighDateTime == right->dwHighDateTime)
        before = left->dwLowDateTime < right->dwLowDateTime;

    return before;
}
