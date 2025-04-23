#include "core/sha/sha1.h"

#include <algorithm>
#include "core/mpz.h"

static uint32_t left_rotate(const uint32_t a, const int bits) {
    return a << bits | a >> (32 - bits);
}

// sha1

SHA1::SHA1() {
    if (constexpr uint32_t val = 0x12345678; htonl(val) == val)
        big_endian_ = true;
}

void SHA1::preprocess(std::vector<unsigned char> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    size_t padding_size = block_size - (len + 1) % block_size;
    if (padding_size < block_size / 8)
        padding_size += block_size;
    v.resize(len + 1 + padding_size, 0);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - block_size / 8, v.end());
}

void SHA1::process_chunk(unsigned char *p) {
    // Extend the 64-bytes block to 80 words (320 bytes).
    std::copy_n(p, 64, reinterpret_cast<unsigned char *>(w_));
    if (!big_endian_)
        for (int i = 0; i < 16; ++i)
            w_[i] = htonl(w_[i]);
    for (int i = 16; i < 80; ++i)
        w_[i] = left_rotate(w_[i - 3] ^ w_[i - 8] ^ w_[i - 14] ^ w_[i - 16], 1);

    // Process the extended block.
    uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f;
        switch (i / 20) { // clang-format off
        case 0:  f = (b & c) | (~b & d);          break;
        case 1:  f = b ^ c ^ d;                   break;
        case 2:  f = (b & c) | (b & d) | (c & d); break;
        default: f = b ^ c ^ d;                   break;
        } // clang-format on
        const uint32_t tmp = left_rotate(a, 5) + f + e + k[i / 20] + w_[i];
        e = d;
        d = c;
        c = left_rotate(b, 30);
        b = a;
        a = tmp;
    }
    h_[0] += a;
    h_[1] += b;
    h_[2] += c;
    h_[3] += d;
    h_[4] += e;
}
