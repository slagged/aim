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
    TBstr(const unsigned short *text);
    TBstr(const TBstr &text);
    ~TBstr();
    TBstr &Append(const char *text);
    TBstr &Assign(const TBstr &text);
    TBstr Left(int count) const;
    int ReverseFind(unsigned short character) const;
    const char *GetMultibyteString() const;
    const unsigned short *GetString() const;
    int CompareNoCase(const unsigned short *text) const;
};

}

#endif
