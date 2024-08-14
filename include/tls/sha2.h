//
// Created by wtchr on 8/14/2024.
//

#ifndef SHA2_H
#define SHA2_H

#include <array>
#include <vector>

#include "network_utils.h"


/**
 * @brief SHA-256 (Secure Hash Algorithm 256) class.
 * This class provides functionalities for computing SHA-256 hashes.
 */
class sha256 {
public:
    static constexpr int block_size = 64; ///< Block size in bytes
    static constexpr int output_size = 32; ///< Output size in bytes

    /**
     * @brief Constructs a SHA-256 object.
     */
    sha256();

    /**
     * @brief Computes the SHA-256 hash of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The SHA-256 hash as an array of bytes.
     */
    template<class It>
    std::array<unsigned char, output_size> hash(It begin, It end);

protected:
    bool big_endian = false; ///< Indicates if the system is big-endian.

    uint32_t H[8]; ///< Hash values
    uint32_t W[64]; ///< Message schedule

    // Initial hash values
    static constexpr uint32_t h_stored_value[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    // Round constants
    static constexpr uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

private:
    /**
     * @brief Preprocesses the input data by padding.
     * @param v The input data to preprocess.
     */
    static void preprocess(std::vector<unsigned char> &v);

    /**
     * @brief Processes a single 512-bit chunk of the input data.
     * @param p Pointer to the chunk to process.
     */
    void process_chunk(unsigned char *p);
};

template<class It>
std::array<unsigned char, sha256::output_size> sha256::hash(It begin, It end) {
    std::vector<unsigned char> v{begin, end};
    preprocess(v);
    std::copy_n(h_stored_value, 8, H);
    for (int i = 0; i < v.size(); i += block_size)
        process_chunk(&v[i]);
    if (!big_endian)
        for (auto &p : H)
            p = htonl(p);
    std::array<unsigned char, output_size> digest{};
    auto *p = reinterpret_cast<unsigned char *>(H);
    for (int i = 0; i < output_size; ++i, ++p)
        digest[i] = *p;
    return digest;
}


#endif
