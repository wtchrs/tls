//
// Created by wtchr on 8/15/2024.
//

#ifndef SHA2_BASE_H
#define SHA2_BASE_H

#include <array>
#include <cstdint>
#include <vector>

// Define the operations used in the SHA-2 hash computation.

static uint32_t rotr(const uint32_t x, const int n) {
    return x >> n | x << 32 - n;
}

static uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z) {
    return x & y ^ ~x & z;
}

static uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z) {
    return x & y ^ x & z ^ y & z;
}

static uint32_t bsig0(const uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t bsig1(const uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t ssig0(const uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ x >> 3;
}

static uint32_t ssig1(const uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ x >> 10;
}


/**
 * @brief Base class for SHA-2 (Secure Hash Algorithm 2) family.
 * This class provides common functionalities for SHA-2 hash algorithms.
 * @tparam Derived The derived class type (e.g., sha224, sha256).
 * @tparam block_size The block size in bytes.
 * @tparam output_size The output size in bytes.
 */
template<class Derived, int block_size, int output_size>
class sha2_base {
public:
    sha2_base();

    /**
     * @brief Computes the SHA-2 hash of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The SHA-2 hash as an array of bytes.
     */
    template<class It>
    std::array<unsigned char, output_size> hash(It begin, It end);

protected:
    bool big_endian = false; ///< Indicates if the system is big-endian.

private:
    /**
     * @brief Preprocesses the input data by padding.
     * @param v The input data to preprocess.
     */
    static void preprocess(std::vector<unsigned char> &v);

    /**
     * @brief Processes a single chunk of the input data.
     * @param p Pointer to the chunk to process.
     */
    void process_chunk(unsigned char *p);
};

template<class Derived, int block_size, int output_size>
sha2_base<Derived, block_size, output_size>::sha2_base() {
    if (constexpr int k = 0x12345678; htonl(k) == k)
        big_endian = true;
}

template<class Derived, int block_size, int output_size>
template<class It>
std::array<unsigned char, output_size> sha2_base<Derived, block_size, output_size>::hash(It begin, It end) {
    auto *t = reinterpret_cast<Derived *>(this);
    std::vector<unsigned char> v{begin, end};
    preprocess(v);
    std::copy_n(t->h_stored_value, 8, t->H);
    for (int i = 0; i < v.size(); i += block_size)
        t->process_chunk(&v[i]);
    if (!big_endian)
        for (auto &p : t->H)
            p = htonl(p);
    std::array<unsigned char, output_size> digest{};
    auto *p = reinterpret_cast<unsigned char *>(t->H);
    for (int i = 0; i < output_size; ++i, ++p)
        digest[i] = *p;
    return digest;
}

template<class Derived, int block_size, int output_size>
void sha2_base<Derived, block_size, output_size>::preprocess(std::vector<unsigned char> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    size_t padding_size = block_size - (len + 1) % block_size;
    if (padding_size < block_size / 8)
        padding_size += block_size;
    v.resize(len + 1 + padding_size, 0);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - block_size / 8, v.end());
}

template<class Derived, int block_size, int output_size>
void sha2_base<Derived, block_size, output_size>::process_chunk(unsigned char *p) {
    auto *t = reinterpret_cast<Derived *>(this);
    // Prepare the message schedule W.
    std::copy_n(p, 64, reinterpret_cast<unsigned char *>(t->W));
    if (!big_endian)
        for (auto &w : t->W)
            w = htonl(w);
    for (int i = 16; i < 64; ++i)
        t->W[i] = ssig1(t->W[i - 2]) + t->W[i - 7] + ssig0(t->W[i - 15]) + t->W[i - 16];

    // Initialize the working variables.
    uint32_t a = t->H[0], b = t->H[1], c = t->H[2], d = t->H[3], e = t->H[4], f = t->H[5], g = t->H[6], h = t->H[7];

    // Perform the main hash computation.
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = h + bsig1(e) + ch(e, f, g) + t->K[i] + t->W[i];
        const uint32_t t2 = bsig0(a) + maj(a, b, c);
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
    t->H[0] += a;
    t->H[1] += b;
    t->H[2] += c;
    t->H[3] += d;
    t->H[4] += e;
    t->H[5] += f;
    t->H[6] += g;
    t->H[7] += h;
}


#endif
