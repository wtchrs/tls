//
// Created by wtchr on 8/10/2024.
//

#ifndef CIPHER_MODE_H
#define CIPHER_MODE_H

#include <array>
#include <cassert>
#include <cstring>
#include <vector>


/**
 * @brief Template class for cipher modes.
 * This class provides a base for different cipher modes of operation.
 * @tparam CIPHER The cipher algorithm to be used (e.g., aes128).
 */
template<class CIPHER>
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
    CIPHER cipher; ///< The cipher algorithm instance
    unsigned char iv[16]; ///< The initialization vector
};


/**
 * @brief Cipher Block Chaining (CBC) mode class.
 * This class implements the CBC mode of operation for block ciphers.
 * @tparam CIPHER The cipher algorithm to be used (e.g., AES).
 */
template<class CIPHER>
class CBC : public cipher_mode<CIPHER> {
public:
    /**
     * @brief Sets the initialization vector (IV) for CBC mode.
     * @param p Pointer to the IV.
     */
    void set_iv(const unsigned char *p);

    /**
     * @brief Encrypts data in CBC mode.
     * @param p Pointer to the data to encrypt.
     * @param len Length of the data to encrypt (must be a multiple of 16).
     */
    void encrypt(unsigned char *p, size_t len) const;

    /**
     * @brief Decrypts data in CBC mode.
     * @param p Pointer to the data to decrypt.
     * @param len Length of the data to decrypt (must be a multiple of 16).
     */
    void decrypt(unsigned char *p, size_t len) const;
};

template<class CIPHER>
void CBC<CIPHER>::set_iv(const unsigned char *p) {
    memcpy(this->iv, p, 16);
}

template<class CIPHER>
void CBC<CIPHER>::encrypt(unsigned char *p, const size_t len) const {
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

template<class CIPHER>
void CBC<CIPHER>::decrypt(unsigned char *p, const size_t len) const {
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


#endif
