#include "hash.hpp"
#include "enumalgs.hpp"

Hash* Hash::from_algid(uint32_t algid)
{
    const char* name = EnumAlgs::name_by_algid(algid);
    if (name) {
        return new Hash{name};
    }
    return nullptr;
}

Hash::Hash(const std::string& name) : _name{name}
{
    const EVP_MD* md = EVP_get_digestbyname(name.c_str());
    _size = EVP_MD_size(md);
    _mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(_mdctx, md, NULL);
}

Hash::~Hash()
{
    EVP_MD_CTX_free(_mdctx);
}

void Hash::update(const uint8_t* buf, uint32_t size)
{
    if (!is_done()) {
        EVP_DigestUpdate(_mdctx, buf, size);
    }
}

void Hash::done(uint8_t* out, uint32_t& size)
{
    if (!is_done()) {
        EVP_DigestFinal_ex(_mdctx, out, &size);
        _is_done = true;
    }
}
