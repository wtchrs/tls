//
// Created by wtchr on 8/13/2024.
//

#include "tls/sha.h"

#include <algorithm>
#include "tls/mpz.h"

static uint32_t left_rotate(const uint32_t a, const int bits) {
    return a << bits | a >> 32 - bits;
}

sha1::sha1() {
    if (constexpr int k = 0x12345678; htonl(k) == k)
        big_endian = true;
}

void sha1::preprocess(std::vector<unsigned char> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    while (v.size() % block_size != block_size - 8)
        v.push_back(0);
    v.resize(v.size() + 8);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - 8, v.end());
}

void sha1::process_chunk(unsigned char *p) {
    // Extend the 64-bytes block to 80 words (320 bytes).
    std::copy_n(p, 64, reinterpret_cast<unsigned char *>(w));
    if (!big_endian)
        for (int i = 0; i < 16; ++i)
            w[i] = htonl(w[i]);
    for (int i = 16; i < 80; ++i)
        w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    // Process the extended block.
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f;
        switch (i / 20) { // clang-format off
        case 0:  f = b & c | ~b & d;        break;
        case 1:  f = b ^ c ^ d;             break;
        case 2:  f = b & c | b & d | c & d; break;
        default: f = b ^ c ^ d;             break;
        } // clang-format on
        const uint32_t tmp = left_rotate(a, 5) + f + e + k[i / 20] + w[i];
        e = d;
        d = c;
        c = left_rotate(b, 30);
        b = a;
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}
