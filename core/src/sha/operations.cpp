#include "core/sha/operations.h"

uint32_t rotr(const uint32_t x, const int n) {
    return x >> n | x << (32 - n);
}

uint64_t rotr(const uint64_t x, const int n) {
    return x >> n | x << (64 - n);
}

uint32_t ch(const uint32_t x, const uint32_t y, const uint32_t z) {
    return (x & y) ^ (~x & z);
}

uint64_t ch(const uint64_t x, const uint64_t y, const uint64_t z) {
    return (x & y) ^ (~x & z);
}

uint32_t maj(const uint32_t x, const uint32_t y, const uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint64_t maj(const uint64_t x, const uint64_t y, const uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t bsig0(const uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint64_t bsig0(const uint64_t x) {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

uint32_t bsig1(const uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint64_t bsig1(const uint64_t x) {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

uint32_t ssig0(const uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ x >> 3;
}

uint64_t ssig0(const uint64_t x) {
    return rotr(x, 1) ^ rotr(x, 8) ^ x >> 7;
}

uint32_t ssig1(const uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ x >> 10;
}

uint64_t ssig1(const uint64_t x) {
    return rotr(x, 19) ^ rotr(x, 61) ^ x >> 6;
}
