#ifndef SHA2_BASE_H
#define SHA2_BASE_H


#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>
#include "core/mpz.h"
#include "core/network_utils.h"
#include "core/sha/operations.h"


/**
 * @brief Base class for SHA-2 (Secure Hash Algorithm 2) family.
 *
 * This class provides common functionalities for SHA-2 hash algorithms.
 *
 * @tparam Derived The derived class type (e.g., sha224, sha256).
 * @tparam BLOCK_SIZE The block size in bytes.
 * @tparam OUTPUT_SIZE The output size in bytes.
 */
template<class Derived, size_t BLOCK_SIZE, size_t OUTPUT_SIZE>
class SHA2Base {
public:
    using BYTE = unsigned char;
    using WORD = std::conditional_t<BLOCK_SIZE == 64, uint32_t, uint64_t>;

    static constexpr size_t block_size = BLOCK_SIZE;
    static constexpr size_t output_size = OUTPUT_SIZE;
    static constexpr size_t W_SIZE = BLOCK_SIZE == 64 ? 64 : 80;

protected:
    bool big_endian_ = false; // Indicates if the system is big-endian.

    WORD H_[8] = {}; // Hash values
    WORD W_[W_SIZE] = {}; // Message schedule

public:
    SHA2Base();

    /**
     * @brief Computes the SHA-2 hash of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The SHA-2 hash as an array of bytes.
     */
    template<class It>
    std::array<BYTE, OUTPUT_SIZE> hash(It begin, It end);

private:
    /**
     * @brief Preprocesses the input data by padding.
     * @param[in,out] v The input data to preprocess.
     */
    static void preprocess(std::vector<BYTE> &v);

    /**
     * @brief Processes a single chunk of the input data.
     * @param[in,out] p Pointer to the chunk to process.
     */
    void process_chunk(BYTE *p);
};

template<class Derived, size_t BLOCK_SIZE, size_t OUTPUT_SIZE>
SHA2Base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::SHA2Base() {
    if (constexpr uint32_t k = 0x12345678; htonl(k) == k)
        big_endian_ = true;
}

template<class Derived, size_t BLOCK_SIZE, size_t OUTPUT_SIZE>
template<class It>
std::array<unsigned char, OUTPUT_SIZE> SHA2Base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::hash(It begin, It end) {
    auto *t = reinterpret_cast<Derived *>(this);
    std::vector<BYTE> v{begin, end};
    preprocess(v);
    std::copy_n(t->h_stored_value, 8, H_);
    for (size_t i = 0; i < v.size(); i += BLOCK_SIZE)
        t->process_chunk(&v[i]);
    if (!big_endian_)
        for (auto &p : H_)
            p = htonl(p);
    std::array<BYTE, OUTPUT_SIZE> digest{};
    auto *p = reinterpret_cast<BYTE *>(H_);
    for (size_t i = 0; i < OUTPUT_SIZE; ++i, ++p)
        digest[i] = *p;
    return digest;
}

template<class Derived, size_t BLOCK_SIZE, size_t OUTPUT_SIZE>
void SHA2Base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::preprocess(std::vector<BYTE> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    size_t padding_size = BLOCK_SIZE - (len + 1) % BLOCK_SIZE;
    if (padding_size < BLOCK_SIZE / 8)
        padding_size += BLOCK_SIZE;
    v.resize(len + 1 + padding_size, 0);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - BLOCK_SIZE / 8, v.end());
}

template<class Derived, size_t BLOCK_SIZE, size_t OUTPUT_SIZE>
void SHA2Base<Derived, BLOCK_SIZE, OUTPUT_SIZE>::process_chunk(BYTE *p) {
    auto *t = reinterpret_cast<Derived *>(this);
    // Prepare the message schedule W.
    std::copy_n(p, BLOCK_SIZE, reinterpret_cast<BYTE *>(W_));
    if (!big_endian_)
        for (auto &w : W_)
            w = htonl(w);
    for (size_t i = 16; i < W_SIZE; ++i)
        W_[i] = ssig1(W_[i - 2]) + W_[i - 7] + ssig0(W_[i - 15]) + W_[i - 16];

    // Initialize the working variables.
    WORD a = H_[0], b = H_[1], c = H_[2], d = H_[3], e = H_[4], f = H_[5], g = H_[6], h = H_[7];

    // Perform the main hash computation.
    for (size_t i = 0; i < W_SIZE; ++i) {
        const WORD t1 = h + bsig1(e) + ch(e, f, g) + t->K[i] + W_[i];
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
    H_[0] += a;
    H_[1] += b;
    H_[2] += c;
    H_[3] += d;
    H_[4] += e;
    H_[5] += f;
    H_[6] += g;
    H_[7] += h;
}


#endif
