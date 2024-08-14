//
// Created by wtchr on 8/14/2024.
//

#include "tls/sha2.h"

#include "tls/mpz.h"
#include "tls/network_utils.h"

// common

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

template<int BLOCK_SIZE>
static void preprocess(std::vector<unsigned char> &v) {
    const size_t len = v.size();
    v.push_back(0x80);
    size_t padding_size = BLOCK_SIZE - (len + 1) % BLOCK_SIZE;
    if (padding_size < BLOCK_SIZE / 8)
        padding_size += BLOCK_SIZE;
    v.resize(len + 1 + padding_size, 0);
    mpz2bnd(static_cast<unsigned long>(len * 8), v.end() - BLOCK_SIZE / 8, v.end());
}

// sha224

sha224::sha224() {
    if (constexpr int k = 0x12345678; htonl(k) == k)
        big_endian = true;
}

void sha224::preprocess(std::vector<unsigned char> &v) {
    ::preprocess<block_size>(v);
}

void sha224::process_chunk(unsigned char *p) {
    // Prepare the message schedule W.
    std::copy_n(p, 64, reinterpret_cast<unsigned char *>(W));
    if (!big_endian)
        for (auto &w : W)
            w = htonl(w);
    for (int i = 16; i < 64; ++i)
        W[i] = ssig1(W[i - 2]) + W[i - 7] + ssig0(W[i - 15]) + W[i - 16];

    // Initialize the working variables.
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    // Perform the main hash computation.
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = h + bsig1(e) + ch(e, f, g) + K[i] + W[i];
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
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}

// sha256

sha256::sha256() {
    if (constexpr int k = 0x12345678; htonl(k) == k)
        big_endian = true;
}

void sha256::preprocess(std::vector<unsigned char> &v) {
    ::preprocess<block_size>(v);
}

void sha256::process_chunk(unsigned char *p) {
    // Prepare the message schedule W.
    std::copy_n(p, 64, reinterpret_cast<unsigned char *>(W));
    if (!big_endian)
        for (auto &w : W)
            w = htonl(w);
    for (int i = 16; i < 64; ++i)
        W[i] = ssig1(W[i - 2]) + W[i - 7] + ssig0(W[i - 15]) + W[i - 16];

    // Initialize the working variables.
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

    // Perform the main hash computation.
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = h + bsig1(e) + ch(e, f, g) + K[i] + W[i];
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
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}
