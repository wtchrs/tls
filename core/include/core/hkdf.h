#ifndef HKDF_H
#define HKDF_H


#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include "core/hmac.h"

/**
 * @brief A class implementing the HMAC-based Key Derivation Function (HKDF).
 *
 * @tparam Hash The hash function to be used, which must conform to the {@ref HashFunction} interface.
 * @see HMAC
 */
template<HashFunction Hash>
class HKDF {
private:
    HMAC<Hash> hmac_; ///< Internal HMAC instance used for key derivation.

public:
    /**
     * @brief Resets the salt to a zeroed value.
     *
     * This method sets the salt to an array of zeros with a size equal to the hash function's output size.
     */
    void zero_salt();

    /**
     * @brief Sets the salt value for the HKDF.
     *
     * @param p Pointer to the salt data.
     * @param sz Size of the salt data in bytes.
     */
    void salt(uint8_t *p, size_t sz);

    /**
     * @brief Extracts a pseudorandom key from the input keying material.
     *
     * @param p Pointer to the input keying material.
     * @param sz Size of the input keying material in bytes.
     * @return A vector containing the extracted pseudorandom key.
     */
    std::vector<uint8_t> extract(uint8_t *p, size_t sz);

    /**
     * @brief Derives a secret using a label and a message.
     *
     * @param label A string label used in the derivation process.
     * @param msg A string message used in the derivation process.
     * @return A vector containing the derived secret.
     */
    std::vector<uint8_t> derive_secret(std::string_view label, std::string msg);

    /**
     * @brief Expands a pseudorandom key into output keying material.
     *
     * @param info A string containing context and application-specific information.
     * @param L The desired length of the output keying material in bytes.
     * @return A vector containing the expanded keying material.
     */
    std::vector<uint8_t> expand(std::string info, size_t L);

    /**
     * @brief Expands a pseudorandom key using a labeled context.
     *
     * @param label A string label used in the expansion process.
     * @param context A string context used in the expansion process.
     * @param L The desired length of the output keying material in bytes.
     * @return A vector containing the expanded keying material.
     */
    std::vector<uint8_t> expand_label(std::string_view label, std::string context, size_t L);

    /**
     * @brief Returns the pointer of the hash object.
     * @return The pointer of the hash object.
     */
    Hash *get_hash_obj();
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
std::vector<uint8_t> HKDF<Hash>::derive_secret(std::string_view label, std::string msg) {
    auto a = hmac_.get_hash_obj()->hash(msg.begin(), msg.end());
    return expand_label(label, std::string{a.begin(), a.end()}, Hash::output_size);
}

template<HashFunction Hash>
std::vector<uint8_t> HKDF<Hash>::expand_label(std::string_view label, std::string context, size_t L) {
    std::string hkdf_label = "xxxtls13 " + std::string{label} + 'x' + context;
    hkdf_label[0] = L / 0x100;
    hkdf_label[1] = L % 0x100;
    hkdf_label[2] = label.size() + 6;
    hkdf_label[9 + label.size()] = context.size();
    return expand(hkdf_label, L);
}

template<HashFunction Hash>
Hash *HKDF<Hash>::get_hash_obj() {
    return hmac_.get_hash_obj();
}


#endif
