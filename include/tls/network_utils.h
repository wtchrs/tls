//
// Created by wtchr on 8/14/2024.
//

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <cstdint>

/**
 * @brief Converts a 32-bit integer from host byte order to network byte order (big-endian).
 * @param hostlong The 32-bit integer in host byte order.
 * @return The 32-bit integer in network byte order.
 */
inline uint32_t htonl(const uint32_t hostlong) {
    static constexpr uint32_t i = 1;
    if (*reinterpret_cast<const unsigned char *>(&i) == i) {
        // Little endian
        return hostlong >> 24 | hostlong << 24 | (hostlong & 0xff00) << 8 | (hostlong & 0xff0000) >> 8;
    }
    // Big endian
    return hostlong;
}

/**
 * @brief Converts a 64-bit integer from host byte order to network byte order (big-endian).
 * @param hostlong The 64-bit integer in host byte order.
 * @return The 64-bit integer in network byte order.
 */
inline uint64_t htonl(const uint64_t hostlong) {
    static constexpr uint32_t i = 1;
    if (*reinterpret_cast<const unsigned char *>(&i) == i) {
        // Little endian
        const uint32_t high_part = htonl(static_cast<uint32_t>(hostlong >> 32));
        const uint32_t low_part = htonl(static_cast<uint32_t>(hostlong & 0xFFFFFFFFLL));

        return (static_cast<uint64_t>(low_part) << 32) | high_part;

    }
    // Big endian
    return hostlong;
}

#endif
