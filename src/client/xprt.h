#ifndef AIM_CLIENT_XPRT_H
#define AIM_CLIENT_XPRT_H

#include <windows.h>
#include <oleauto.h>

namespace XPRT {

// Imported string storage: a wide BSTR and a cached multibyte conversion.
// Eight bytes is the current complete-object hypothesis. These fields could
// have belonged to a nonvirtual base in the original class declaration.
class __declspec(dllimport) TBstr
{
    BSTR wide;
    char *multibyte;

public:
    TBstr(const char *text);
    ~TBstr();
    TBstr &Append(const char *text);
    const char *GetMultibyteString() const;
};

}

#endif
