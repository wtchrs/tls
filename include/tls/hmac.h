//
// Created by wtchr on 8/16/2024.
//

#ifndef HMAC_H
#define HMAC_H

#include <algorithm>
#include <array>
#include <vector>


/**
 * @brief Concept for hash functions.
 *
 * This concept provide an interface for hash functions.
 *
 * @tparam Hash The hash function type.
 */
template<typename Hash>
concept HashFunction = requires(Hash h, const unsigned char *begin, const unsigned char *end) {
    { Hash::block_size } -> std::convertible_to<size_t>;
    { h.hash(begin, end) } -> std::convertible_to<std::array<unsigned char, Hash::output_size>>;
};


/**
 * @brief HMAC (Hash-based Message Authentication Code) class template.
 *
 * This class provides functionalities for computing HMAC using a specified hash function.
 *
 * @tparam Hash The hash function to be used (e.g., sha256).
 */
template<HashFunction Hash>
class hmac {
public:
    /**
     * @brief Constructs an HMAC object.
     */
    hmac() = default;

    /**
     * @brief Sets the key for HMAC.
     * @tparam It Iterator type for the key.
     * @param begin Iterator pointing to the beginning of the key.
     * @param end Iterator pointing to the end of the key.
     */
    template<typename It>
    void key(It begin, It end);

    /**
     * @brief Computes the HMAC of the input data.
     * @tparam It Iterator type for the input data.
     * @param begin Iterator pointing to the beginning of the input data.
     * @param end Iterator pointing to the end of the input data.
     * @return The HMAC as an array of bytes.
     */
    template<typename It>
    auto hash(It begin, It end);

protected:
    Hash hash_; ///< Hash function instance.
    std::array<unsigned char, Hash::block_size> o_key_pad; ///< Key XORed outer pad.
    std::array<unsigned char, Hash::block_size> i_key_pad; ///< Key XORed inner pad.
};

template<HashFunction Hash>
template<typename It>
void hmac<Hash>::key(const It begin, const It end) {
    std::array<unsigned char, Hash::block_size> key{}; // Zero-padded key
    // Hash the key if it is longer than the block size
    if (end - begin > Hash::block_size) {
        auto h = hash_.hash(begin, end);
        std::copy(h.begin(), h.end(), key.begin());
    } else {
        std::copy(begin, end, key.begin());
    }
    // XOR the key with the inner and outer pads:
    // inner pad = the byte 0x36 repeated Hash::block_size times,
    // outer pad = the byte 0x5c repeated Hash::block_size times.
    for (size_t i = 0; i < Hash::block_size; ++i) {
        i_key_pad[i] = key[i] ^ 0x36;
        o_key_pad[i] = key[i] ^ 0x5c;
    }
}

template<HashFunction Hash>
template<typename It>
auto hmac<Hash>::hash(It begin, It end) {
    // Append the message to the inner key pad and hash it
    std::vector<unsigned char> v{i_key_pad.begin(), i_key_pad.end()};
    v.insert(v.end(), begin, end);
    auto h = hash_.hash(v.begin(), v.end());
    // Append the previous hash result to the outer key pad and hash it
    v.clear();
    v.insert(v.end(), o_key_pad.begin(), o_key_pad.end());
    v.insert(v.end(), h.begin(), h.end());
    return hash_.hash(v.begin(), v.end());
}


#endif
