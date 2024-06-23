#ifndef __ENUMALGS_HPP__
#define __ENUMALGS_HPP__

#include <windows.h>
#include <wincrypt.h>

class EnumAlgs {
public:
    static void first();
    static void next();
    static bool read(PROV_ENUMALGS& alg);
    static bool read(PROV_ENUMALGS_EX& algEx);

    static const char* name_by_algid(uint32_t algid);
};

#endif // __ENUMALGS_HPP__
