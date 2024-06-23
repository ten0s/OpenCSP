#ifndef __HASH_HPP__
#define __HASH_HPP__

#include <string>
#include <openssl/evp.h>

class Hash {
private:
    explicit Hash(const std::string& name);

public:
    static Hash* from_algid(uint32_t algid);
    ~Hash();

    void update(const uint8_t* buf, uint32_t size);
    void done(uint8_t* out, uint32_t& size);

    const std::string& name() const { return _name; }
    uint32_t size() const { return _size; }
    bool is_done() const { return _is_done; }

private:
    std::string _name;
    uint32_t _size;
    bool _is_done{false};
    EVP_MD_CTX* _mdctx{nullptr};
};

#endif // __HASH_HPP__
