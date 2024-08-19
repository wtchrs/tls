//
// Created by wtchr on 8/10/2024.
//

#ifndef CIPHER_MODE_H
#define CIPHER_MODE_H

#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <vector>
#include "mpz.h"


template<typename Cipher>
concept CIPHER = requires(Cipher c, const unsigned char *cp, unsigned char *p) {
    { c.set_key(cp) };
    { c.encrypt(p) };
    { c.decrypt(p) };
};


/**
 * @brief Template class for cipher modes.
 *
 * This class provides a base for different cipher modes of operation.
 *
 * @tparam Cipher The cipher algorithm to be used (e.g., aes128).
 */
template<CIPHER Cipher>
class cipher_mode {
public:
    /**
     * @brief Sets the encryption key for the cipher.
     * @param p Pointer to the key.
     */
    void set_key(const unsigned char *p) {
        cipher.set_key(p);
    }

protected:
    Cipher cipher; ///< The cipher algorithm instance
    unsigned char iv[16]; ///< The initialization vector
};


/**
 * @brief Cipher Block Chaining (CBC) mode class.
 *
 * This class implements the CBC mode of operation for block ciphers.
 *
 * @tparam Cipher The cipher algorithm to be used (e.g., AES).
 */
template<CIPHER Cipher>
class CBC : public cipher_mode<Cipher> {
public:
    /**
     * @brief Sets the initialization vector (IV) for CBC mode.
     * @param p Pointer to the IV.
     */
    void set_iv(const unsigned char *p);

    /**
     * @brief Encrypts data in CBC mode.
     * @param[in,out] p Pointer to the data to encrypt.
     * @param len Length of the data to encrypt (must be a multiple of 16).
     */
    void encrypt(unsigned char *p, size_t len) const;

    /**
     * @brief Decrypts data in CBC mode.
     * @param[in,out] p Pointer to the data to decrypt.
     * @param len Length of the data to decrypt (must be a multiple of 16).
     */
    void decrypt(unsigned char *p, size_t len) const;
};

template<CIPHER Cipher>
void CBC<Cipher>::set_iv(const unsigned char *p) {
    memcpy(this->iv, p, 16);
}

template<CIPHER Cipher>
void CBC<Cipher>::encrypt(unsigned char *p, const size_t len) const {
    assert(len % 16 == 0);
    for (int i = 0; i < 16; ++i)
        *(p + i) ^= this->iv[i];
    this->cipher.encrypt(p);
    p += 16;
    for (int i = 0; i < len / 16 - 1; ++i, p += 16) {
        for (int j = 0; j < 16; ++j)
            *(p + j) ^= *(p - 16 + j);
        this->cipher.encrypt(p);
    }
}

template<CIPHER Cipher>
void CBC<Cipher>::decrypt(unsigned char *p, const size_t len) const {
    // Optimization is possible by applying parallelism
    assert(len % 16 == 0);
    std::vector<unsigned char> tmp{};
    tmp.resize(len);
    memcpy(&tmp[0], p, len);
    for (int i = 0; i < len; i += 16)
        this->cipher.decrypt(p + i);
    for (int i = 0; i < 16; ++i)
        *p++ ^= this->iv[i];
    for (int i = 0; i < len - 16; ++i)
        *p++ ^= tmp[i];
}


/**
 * @brief Galois/Counter Mode (GCM) class.
 *
 * This class implements the Galois/Counter Mode (GCM) operation for block ciphers.
 *
 * @tparam Cipher The cipher algorithm to be used (e.g., AES).
 */
template<CIPHER Cipher>
class GCM : public cipher_mode<Cipher> {
public:
    /**
     * @brief Sets the initialization vector (IV) for GCM mode.
     * @param p Pointer to the IV.
     */
    void set_iv(const unsigned char *p);

    /**
     * @brief Sets the initialization vector (IV) for GCM mode with an offset.
     * @param p Pointer to the IV data.
     * @param offset The offset within the IV.
     * @param len Length of the IV data.
     */
    void set_iv(const unsigned char *p, int offset, size_t len);

    /**
     * @brief Sets the additional authenticated data (AAD) for GCM mode.
     * @param p Pointer to the AAD.
     * @param len Length of the AAD.
     */
    void set_aad(const unsigned char *p, size_t len);

    /**
     * @brief Encrypts data in GCM mode.
     * @param[in,out] p Pointer to the data to encrypt. The encrypted data overwrites the original data.
     * @param len Length of the data to encrypt.
     * @return The authentication tag.
     */
    std::array<unsigned char, 16> encrypt(unsigned char *p, size_t len);

    /**
     * @brief Decrypts data in GCM mode.
     * @param[in,out] p Pointer to the data to decrypt. The decrypted data overwrites the original data.
     * @param len Length of the data to decrypt.
     * @return The authentication tag.
     */
    std::array<unsigned char, 16> decrypt(unsigned char *p, size_t len);

protected:
    std::vector<unsigned char> aad; ///< Additional authenticated data
    unsigned char len_ac[16]; ///< Length of AAD and ciphertext in big-endian format

private:
    /**
     * @brief Applies XOR to the data using the encrypted IV and counter.
     * @param[in,out] p Pointer to the data. The data is modified in place.
     * @param len Length of the data.
     * @param ctr Counter value.
     */
    void xor_with_enc_iv_and_counter(unsigned char *p, size_t len, int ctr);

    /**
     * @brief Generates the authentication tag.
     * @param p Pointer to the data.
     * @param len Length of the data.
     * @return The authentication tag.
     */
    std::array<unsigned char, 16> generate_auth(const unsigned char *p, size_t len);

    /**
     * @brief Doubles the value within GF(2^128).
     * @param[in,out] p Pointer to the value. The doubled value overwrites the original value.
     */
    static void doub(unsigned char *p);

    /**
     * @brief Multiplies two values in GF(2^128).
     * @param[in,out] p Pointer to the first value. The result overwrites the first value.
     * @param q Pointer to the second value.
     */
    static void gf_mul(unsigned char *p, const unsigned char *q);
};

template<CIPHER Cipher>
void GCM<Cipher>::set_iv(const unsigned char *p) {
    // std::copy(p, p + 12, this->iv);
    std::copy_n(p, 12, this->iv);
}

template<CIPHER Cipher>
void GCM<Cipher>::set_iv(const unsigned char *p, int offset, const size_t len) {
    // std::copy(p, p + len, this->iv + offset);
    std::copy_n(p, len, this->iv + offset);
}

template<CIPHER Cipher>
void GCM<Cipher>::set_aad(const unsigned char *p, const size_t len) {
    aad = std::vector<unsigned char>{p, p + len};
    // Write the length of aad to the front of len_ac in big-endian format
    mpz2bnd(static_cast<unsigned long>(aad.size() * 8), len_ac, len_ac + 8);
    while (aad.size() % 16)
        aad.push_back(0);
}

template<CIPHER Cipher>
std::array<unsigned char, 16> GCM<Cipher>::encrypt(unsigned char *p, const size_t len) {
    for (size_t i = 0; i < len; i += 16)
        xor_with_enc_iv_and_counter(p + i, std::min(static_cast<size_t>(16), len - i), i / 16 + 2);
    return generate_auth(p, len);
}

template<CIPHER Cipher>
std::array<unsigned char, 16> GCM<Cipher>::decrypt(unsigned char *p, size_t len) {
    const auto auth = generate_auth(p, len);
    for (size_t i = 0; i < len; i += 16)
        xor_with_enc_iv_and_counter(p + 1, std::min(static_cast<size_t>(16), len - i), i / 16 + 2);
    return auth;
}

template<CIPHER Cipher>
void GCM<Cipher>::xor_with_enc_iv_and_counter(unsigned char *p, const size_t len, const int ctr) {
    unsigned char iv_and_counter[16];
    std::copy(this->iv, this->iv + 12, iv_and_counter);
    mpz2bnd(ctr, iv_and_counter + 12, iv_and_counter + 16);
    this->cipher.encrypt(iv_and_counter);
    for (int i = 0; i < len; ++i)
        p[i] ^= iv_and_counter[i];
}

template<CIPHER Cipher>
std::array<unsigned char, 16> GCM<Cipher>::generate_auth(const unsigned char *p, const size_t len) {
    // All operations are performed in GF(2^128) and may modify the operands in place.
    // clang-format off
    unsigned char H[16] = {0,};
    // clang-format on
    std::array<unsigned char, 16> auth{};
    // Generate H by encrypting the all-zero block by the cipher.
    this->cipher.encrypt(H);

    if (!aad.empty()) {
        gf_mul(&aad[0], H); // Multiply the AAD by H.
        for (int i = 0; i < aad.size() - 16; i += 16) {
            // XOR the next 16 bytes with previous ones and multiply by H.
            for (int j = 0; j < 16; ++j)
                aad[i + 16 + j] ^= aad[i + j];
            gf_mul(&aad[i + 16], H);
        }
        // Use the last result to generate the authentication tag.
        std::copy(aad.end() - 16, aad.end(), auth.begin());
    }

    for (int i = 0; i < len; i += 16) {
        // XOR the current ciphertext block with auth and multiply H.
        for (int j = 0; j < std::min(static_cast<size_t>(16), len - i); ++j)
            auth[j] ^= p[i + j];
        gf_mul(&auth[0], H);
    }

    // Write the length of ciphertext to the end of len_ac in big-endian format.
    mpz2bnd(static_cast<unsigned long>(len * 8), len_ac + 8, len_ac + 16);
    // XOR len_ac with auth and multiply by H.
    for (int i = 0; i < 16; ++i)
        auth[i] ^= len_ac[i];
    gf_mul(&auth[0], H);

    xor_with_enc_iv_and_counter(&auth[0], 16, 1);
    return auth;
}

template<CIPHER Cipher>
void GCM<Cipher>::doub(unsigned char *p) {
    const bool bit1 = p[15] & 1; // Check if the coefficient of x^127 is 1
    // Shift left by 1
    for (int i = 15; i > 0; --i) {
        p[i] >>= 1;
        if (p[i - 1] & 1)
            p[i] |= 0x80;
    }
    p[0] >>= 1;
    if (bit1)
        // Modulo reduction by the irreducible polynomial `x^128 + x^7 + x^2 + x + 1`
        // to ensure the result remains within GF(2^128).
        p[0] ^= 0xe1;
}

template<CIPHER Cipher>
void GCM<Cipher>::gf_mul(unsigned char *p, const unsigned char *q) {
    // clang-format off
    unsigned char r[16] = {0,};
    // clang-format on
    for (int i = 0; i < 16; ++i) {
        for (int j = 0, bit = 0x80; j < 8; ++j, bit >>= 1) {
            if (q[i] & bit) {
                for (int k = 0; k < 16; ++k) {
                    r[k] ^= p[k];
                }
            }
            doub(p);
        }
    }
    // Copy result to p
    std::copy_n(r, 16, p);
}


#endif
