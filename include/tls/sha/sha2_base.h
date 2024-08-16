//
// Created by wtchr on 8/15/2024.
//

#ifndef SHA2_BASE_H
#define SHA2_BASE_H

#include <array>
#include <cstdint>
#include <vector>
#include "tls/network_utils.h"

// Define the operations used in the SHA-2 hash computation.

static uint32_t rotr(const uint32_t x, const int n) {
    return x >> n | x << (32 - n);
}

static uint64_t rotr(const uint64_t x, const int n) {
    return x >> n | x << (64 - n);
}

static uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z) {
    return x & y ^ ~x & z;
}

static uint64_t ch(const uint64_t x, const uint64_t y, const uint64_t z) {
    return x & y ^ ~x & z;
}

static uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z) {
    return x & y ^ x & z ^ y & z;
}

static uint64_t maj(const uint64_t x, const uint64_t y, const uint64_t z) {
    return x & y ^ x & z ^ y & z;
}

static uint32_t bsig0(const uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint64_t bsig0(const uint64_t x) {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

static uint32_t bsig1(const uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint64_t bsig1(const uint64_t x) {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

static uint32_t ssig0(const uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ x >> 3;
}

static uint64_t ssig0(const uint64_t x) {
    return rotr(x, 1) ^ rotr(x, 8) ^ x >> 7;
}

static uint32_t ssig1(const uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ x >> 10;
}

static uint64_t ssig1(const uint64_t x) {
    return rotr(x, 19) ^ rotr(x, 61) ^ x >> 6;
}


template<typename T, bool condition, T t1, T t2>
struct conditional_value {
    static constexpr T value = t1;
};

template<typename T, T t1, T t2>
struct conditional_value<T, false, t1, t2> {
    static constexpr T value = t2;
};


/**
 * @brief Base class for SHA-2 (Secure Hash Algorithm 2) family.
 * This class provides common functionalities for SHA-2 hash algorithms.
 * @tparam Derived The derived class type (e.g., sha224, sha256).
 * @tparam BLOCK_SIZE The block size in bytes.
 * @tparam OUTPUT_SIZE The output size in bytes.
 */
template<class Derived, int BLOCK_SIZE, int OUTPUT_SIZE>
class sha2_base {
public:
    using BYTE = unsigned char;
    using WORD = std::conditional_t<BLOCK_SIZE == 64, uint32_t, uint64_t>;

    static constexpr size_t block_size = BLOCK_SIZE;
    static constexpr size_t W_SIZE = conditional_value<size_t, BLOCK_SIZE == 64, 64, 80>::value;

    sha2_base();

    /**
     * @brief Computes the SHA-2 hash of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The SHA-2 hash as an array of bytes.
     */
    template<class It>
    std::array<BYTE, OUTPUT_SIZE> hash(It begin, It end);

protected:
    bool big_endian = false; ///< Indicates if the system is big-endian.

    WORD H[8]; ///< Hash values
    WORD W[W_SIZE]; ///< Message schedule

private:
    /**
     * @brief Preprocesses the input data by padding.
     * @param v The input data to preprocess.
     */
    static void preprocess(std::vector<BYTE> &v);

    /**
     * @brief Processes a single chunk of the input data.
     * @param p Pointer to the chunk to process.
     */
    void process_chunk(BYTE *p);
};

template<class Derived, int BLOCK_SIZE, int OUTPUT_SIZE>
sha2_base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::sha2_base() {
    if (constexpr uint32_t k = 0x12345678; htonl(k) == k)
        big_endian = true;
}

template<class Derived, int BLOCK_SIZE, int OUTPUT_SIZE>
template<class It>
std::array<unsigned char, OUTPUT_SIZE> sha2_base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::hash(It begin, It end) {
    auto *t = reinterpret_cast<Derived *>(this);
    std::vector<BYTE> v{begin, end};
    preprocess(v);
    std::copy_n(t->h_stored_value, 8, H);
    for (int i = 0; i < v.size(); i += BLOCK_SIZE)
        t->process_chunk(&v[i]);
    if (!big_endian)
        for (auto &p : H)
            p = htonl(p);
    std::array<BYTE, OUTPUT_SIZE> digest{};
    auto *p = reinterpret_cast<BYTE *>(H);
    for (int i = 0; i < OUTPUT_SIZE; ++i, ++p)
        digest[i] = *p;
    return digest;
}

template<class Derived, int BLOCK_SIZE, int OUTPUT_SIZE>
void sha2_base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::preprocess(std::vector<BYTE> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    size_t padding_size = BLOCK_SIZE - (len + 1) % BLOCK_SIZE;
    if (padding_size < BLOCK_SIZE / 8)
        padding_size += BLOCK_SIZE;
    v.resize(len + 1 + padding_size, 0);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - BLOCK_SIZE / 8, v.end());
}

template<class Derived, int BLOCK_SIZE, int OUTPUT_SIZE>
void sha2_base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::process_chunk(BYTE *p) {
    auto *t = reinterpret_cast<Derived *>(this);
    // Prepare the message schedule W.
    std::copy_n(p, BLOCK_SIZE, reinterpret_cast<BYTE *>(W));
    if (!big_endian)
        for (auto &w : W)
            w = htonl(w);
    for (size_t i = 16; i < W_SIZE; ++i)
        W[i] = ssig1(W[i - 2]) + W[i - 7] + ssig0(W[i - 15]) + W[i - 16];

    // Initialize the working variables.
    WORD a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    // Perform the main hash computation.
    for (size_t i = 0; i < W_SIZE; ++i) {
        const WORD t1 = h + bsig1(e) + ch(e, f, g) + t->K[i] + W[i];
        const WORD t2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // Update the hash values.
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}


#endif
