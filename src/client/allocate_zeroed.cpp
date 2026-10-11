#include <stdlib.h>
#include <string.h>

// Clear a successful allocation; preserve malloc's null result on failure.
void *allocate_zeroed(unsigned int bytes)
{
    void *buffer = malloc(bytes);
    if (buffer)
        memset(buffer, 0, bytes);

    return buffer;
}
