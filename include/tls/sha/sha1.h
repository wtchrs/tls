//
// Created by wtchr on 8/13/2024.
//

#ifndef SHA_H
#define SHA_H

#include <array>
#include <vector>
#include "tls/network_utils.h"


/**
 * @brief SHA-1 (Secure Hash Algorithm 1) class.
 * This class provides functionalities for computing SHA-1 hashes.
 */
class sha1 {
public:
    static constexpr size_t block_size = 64; ///< Block size in bytes
    static constexpr size_t output_size = 20; ///< Output size in bytes

    /**
     * @brief Constructs a SHA-1 object.
     */
    sha1();

    /**
     * @brief Computes the SHA-1 hash of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The SHA-1 hash digest as an array of bytes.
     */
    template<class It>
    std::array<unsigned char, output_size> hash(It begin, It end);

protected:
    bool big_endian = false; ///< Indicates if the system is big-endian.
    uint32_t h[5], w[80]; ///< Internal state and message schedule array.
    // Initial hash values
    static constexpr uint32_t h_stored_value[5] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};
    // Round constants
    static constexpr uint32_t k[4] = {0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6};

private:
    /**
     * @brief Preprocesses the input data by padding and appending the length.
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
std::array<unsigned char, sha1::output_size> sha1::hash(It begin, It end) {
    for (int i = 0; i < 5; ++i)
        h[i] = h_stored_value[i];
    std::vector<unsigned char> msg{begin, end};
    preprocess(msg);
    for (int i = 0; i < msg.size(); i += block_size)
        process_chunk(&msg[i]);
    if (!big_endian)
        for (auto &p : h)
            p = htonl(p);
    std::array<unsigned char, output_size> digest{};
    auto *p = reinterpret_cast<unsigned char *>(h);
    for (int i = 0; i < 20; ++i, ++p)
        digest[i] = *p;
    return digest;
}


#endif
