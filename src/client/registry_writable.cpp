#include "xprt.h"
#include <io.h>

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
