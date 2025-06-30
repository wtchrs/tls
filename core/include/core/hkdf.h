#ifndef HKDF_H
#define HKDF_H


#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include "core/hmac.h"

template<HashFunction Hash>
class HKDF {
private:
    HMAC<Hash> hmac_;

public:
    void zero_salt();
    void salt(uint8_t *p, size_t sz);
    std::vector<uint8_t> extract(uint8_t *p, size_t sz);
    std::vector<uint8_t> derive_secret(std::string label, std::string msg);
    std::vector<uint8_t> expand(std::string info, size_t L);

private:
    std::vector<uint8_t> expand_label(std::string label, std::string context, size_t L);
};

template<HashFunction Hash>
void HKDF<Hash>::salt(uint8_t *p, size_t sz) {
    hmac_.key(p, p + sz);
}

template<HashFunction Hash>
void HKDF<Hash>::zero_salt() {
    uint8_t zeros[Hash::output_size] = {};
    hmac_.key(zeros, zeros + sizeof(zeros));
}

template<HashFunction Hash>
std::vector<uint8_t> HKDF<Hash>::extract(uint8_t *p, size_t sz) {
    auto a = hmac_.hash(p, p + sz);
    return std::vector<uint8_t>{a.begin(), a.end()};
}

template<HashFunction Hash>
std::vector<uint8_t> HKDF<Hash>::expand(std::string info, size_t L) {
    std::vector<uint8_t> r;
    size_t k = Hash::output_size + info.size() + 1;
    std::vector<uint8_t> t(k);
    std::copy(info.begin(), info.end(), t.begin() + Hash::output_size);
    t[k - 1] = 1;
    auto a = hmac_.hash(t.cbegin() + Hash::output_size, t.cend());
    r.insert(r.end(), a.begin(), a.end());
    while (r.size() < L) {
        std::copy(a.begin(), a.end(), t.begin());
        ++t[k - 1];
        a = hmac_.hash(t.cbegin(), t.cend());
        r.insert(r.end(), a.begin(), a.end());
    }
    r.resize(L);
    return r;
}

template<HashFunction Hash>
std::vector<uint8_t> HKDF<Hash>::derive_secret(std::string label, std::string msg) {
    auto a = hmac_.get_hash_obj()->hash(msg.begin(), msg.end());
    return expand_label(label, std::string{a.begin(), a.end()}, Hash::output_size);
}

template<HashFunction Hash>
std::vector<uint8_t> HKDF<Hash>::expand_label(std::string label, std::string context, size_t L) {
    std::string hkdf_label = "xxxtls13 " + label + 'x' + context;
    hkdf_label[0] = L / 0x100;
    hkdf_label[1] = L % 0x100;
    hkdf_label[2] = label.size() + 6;
    hkdf_label[9 + label.size()] = context.size();
    return expand(hkdf_label, L);
}


#endif
