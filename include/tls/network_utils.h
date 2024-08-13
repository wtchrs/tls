//
// Created by wtchr on 8/14/2024.
//

#ifndef NETWORK_UTILS_H
#define NETWORK_UTILS_H

#include <cstdint>

inline uint32_t htonl(const uint32_t hostlong) {
    static constexpr uint32_t i = 1;
    if (*reinterpret_cast<const unsigned char *>(&i) == i) {
        // Little endian
        return hostlong >> 24 | hostlong << 24 | (hostlong & 0xff00) << 8 | (hostlong & 0xff0000) >> 8;
    }
    // Big endian
    return hostlong;
}

#endif
