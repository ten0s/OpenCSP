#include <algorithm>
#include <iterator> // std::size
#include <vector>

#include "enumalgs.hpp"

struct AlgInfo {
    uint32_t algid;   // Windows ALG_ID
    uint32_t bits;
    const char* name; // OpenSSL name
    const char* desc;
};

static std::vector<AlgInfo> algInfos {
    { 0x8003, 128, "md5"          , "Message Digest 5 (MD5)"           },
    { 0x800c, 256, "sha256"       , "Secure Hash Algorithm 2 (SHA256)" },
    { 0x8021, 256, "md_gost12_256", "GOST R 34.11-2012 256"            },
    { 0x8033, 256, "belt-hash"    , "STB 34.101.31-2020 256"           },
};

static size_t i = 0;

void EnumAlgs::first()
{
    i = 0;
}

void EnumAlgs::next()
{
    i++;
}

bool EnumAlgs::read(PROV_ENUMALGS& alg)
{
    if (i < std::size(algInfos)) {
        alg.aiAlgid   = algInfos[i].algid;
        alg.dwBitLen  = algInfos[i].bits;
        alg.dwNameLen = strlen(algInfos[i].name) + 1;
        strncpy(alg.szName, algInfos[i].name, sizeof(alg.szName));

        return true;
    }

    return false;
}

bool EnumAlgs::read(PROV_ENUMALGS_EX& alg)
{
    if (i < std::size(algInfos)) {
        alg.aiAlgid       = algInfos[i].algid;
        alg.dwDefaultLen  = algInfos[i].bits;
        alg.dwMinLen      = algInfos[i].bits;
        alg.dwMaxLen      = algInfos[i].bits;
        alg.dwProtocols   = 0;
        alg.dwNameLen     = strlen(algInfos[i].name) + 1;
        alg.dwLongNameLen = strlen(algInfos[i].desc) + 1;
        strncpy(alg.szName, algInfos[i].name, sizeof(alg.szName));
        strncpy(alg.szLongName, algInfos[i].desc, sizeof(alg.szLongName));

        return true;
    }

    return false;
}

const char* EnumAlgs::name_by_algid(uint32_t algid)
{
    auto it = std::find_if(
        std::begin(algInfos), std::end(algInfos),
        [algid](const auto& alg) { return alg.algid == algid; });

    if (it != std::end(algInfos)) {
        return it->name;
    }

    return nullptr;
}
