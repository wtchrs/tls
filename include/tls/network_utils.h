//
// Created by wtchr on 8/14/2024.
//

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <bit>
#include <cstdint>

constexpr bool is_little_endian() {
    // C++20
    return std::endian::native == std::endian::little;
    // Pre-C++20
    // constexpr uint32_t i = 1;
    // return *reinterpret_cast<const uint8_t *>(&i) == 1;
}

/**
 * @brief Converts a 32-bit integer from host byte order to network byte order (big-endian).
 * @param hostlong The 32-bit integer in host byte order.
 * @return The 32-bit integer in network byte order.
 */
constexpr uint32_t htonl(const uint32_t hostlong) {
    if constexpr (is_little_endian()) {
        return hostlong >> 24 | hostlong << 24 | (hostlong & 0xff00) << 8 | (hostlong & 0xff0000) >> 8;
    }
    return hostlong;
}

/**
 * @brief Converts a 64-bit integer from host byte order to network byte order (big-endian).
 * @param hostlong The 64-bit integer in host byte order.
 * @return The 64-bit integer in network byte order.
 */
constexpr uint64_t htonl(const uint64_t hostlong) {
    if constexpr (is_little_endian()) {
        const uint32_t high_part = htonl(static_cast<uint32_t>(hostlong >> 32));
        const uint32_t low_part = htonl(static_cast<uint32_t>(hostlong & 0xFFFFFFFFLL));
        return (static_cast<uint64_t>(low_part) << 32) | high_part;
    }
    return hostlong;
}

// Alias for htonl
constexpr uint32_t ntohl(const uint32_t netlong) {
    return htonl(netlong);
}

// Alias for htonl
constexpr uint64_t ntohl(const uint64_t netlong) {
    return htonl(netlong);
}

#endif
