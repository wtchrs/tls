//
// Created by wtchr on 8/9/2024.
//

#include "tls/aes.h"

#include <cstring>

void aes128::set_key(const unsigned char *key) {
    memcpy(schedule, key, 16);
    for (int i = 1; i < ROUND; ++i) {
        unsigned char *it = schedule[i];
        // Rotate the last word of the previous round and use it as the first word of the new round.
        for (int j = 0; j < 3; ++j)
            *(it + j) = *(it - 3 + j);
        *(it + 3) = *(it - 4);
        // Substitute, add round constant, and add the first word of the previous round.
        for (int j = 0; j < 4; ++j, ++it)
            *it = sbox[*it] ^ rcon[i - 1][j] ^ *(it - 4 * N);
        // Generate the rest of the words in the round.
        for (int j = 0; j < 4 * (N - 1); ++j, ++it)
            *it = *(it - 4) ^ *(it - 4 * N);
    }
}

void aes128::encrypt(unsigned char *m) const {
    // Initial round
    add_round_key(m, 0);
    // Rounds 1 to (ROUND - 1)
    for (int i = 1; i < ROUND - 1; ++i) {
        substitute(m);
        shift_row(m);
        mix_column(m);
        add_round_key(m, i);
    }
    // Final round
    substitute(m);
    shift_row(m);
    add_round_key(m, ROUND - 1);
}

void aes128::decrypt(unsigned char *m) const {
    // Final round
    add_round_key(m, ROUND - 1);
    inv_shift_row(m);
    inv_substitute(m);
    // Rounds (ROUND - 1) to 1
    for (int i = ROUND - 2; i > 0; --i) {
        add_round_key(m, i);
        inv_mix_column(m);
        inv_shift_row(m);
        inv_substitute(m);
    }
    // Initial round
    add_round_key(m, 0);
}

void aes128::shift_row(unsigned char *msg) {
    unsigned char tmp, tmp2;
    tmp = msg[1], msg[1] = msg[5], msg[5] = msg[9], msg[9] = msg[13], msg[13] = tmp;
    tmp = msg[2], msg[2] = msg[10], msg[10] = tmp, tmp2 = msg[6], msg[6] = msg[14], msg[14] = tmp2;
    tmp = msg[15], msg[15] = msg[11], msg[11] = msg[7], msg[7] = msg[3], msg[3] = tmp;
}

void aes128::inv_shift_row(unsigned char *msg) {
    unsigned char tmp, tmp2;
    tmp = msg[13], msg[13] = msg[9], msg[9] = msg[5], msg[5] = msg[1], msg[1] = tmp;
    tmp = msg[2], msg[2] = msg[10], msg[10] = tmp, tmp2 = msg[6], msg[6] = msg[14], msg[14] = tmp2;
    tmp = msg[3], msg[3] = msg[7], msg[7] = msg[11], msg[11] = msg[15], msg[15] = tmp;
}

void aes128::substitute(unsigned char *msg) {
    for (unsigned char *it = msg; it < msg + 16; ++it)
        *it = sbox[*it];
}

void aes128::inv_substitute(unsigned char *msg) {
    for (unsigned char *it = msg; it < msg + 16; ++it)
        *it = inv_sbox[*it];
}

void aes128::mix_column(unsigned char *msg) {
    // Matrix multiplication on GF(2^8)
    static constexpr unsigned char mix[4][4] = {{2, 3, 1, 1}, {1, 2, 3, 1}, {1, 1, 2, 3}, {3, 1, 1, 2}};
    unsigned char c[4], result[16];
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; ++x) {
            for (int i = 0; i < 4; ++i) {
                const unsigned char d = msg[4 * x + i];
                switch (mix[y][i]) {
                case 1:
                    c[i] = d;
                    break;
                case 2:
                    c[i] = d << 1;
                    break;
                case 3:
                    c[i] = d << 1 ^ d;
                    break;
                default:;
                }
                if (d & 0x80 && mix[y][i] != 1)
                    c[i] ^= 0x1b;
            }
            result[4 * x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
        }
    }
    memcpy(msg, result, 16);
}

void aes128::inv_mix_column(unsigned char *msg) {
    // Matrix multiplication on GF(2^8)
    static constexpr unsigned char inv_mix[4][4] = {{14, 11, 13, 9}, {9, 14, 11, 13}, {13, 9, 14, 11}, {11, 13, 9, 14}};
    unsigned char c[4], result[16];
    for (int y = 0; y < 4; y++) {
        for (int x = 0; x < 4; ++x) {
            for (int i = 0; i < 4; ++i) {
                const unsigned char d = msg[4 * x + i];
                switch (inv_mix[y][i]) {
                case 9:
                    c[i] = doub(doub(doub(d))) ^ d;
                    break;
                case 11:
                    c[i] = doub(doub(doub(d)) ^ d) ^ d;
                    break;
                case 13:
                    c[i] = doub(doub(doub(d) ^ d)) ^ d;
                    break;
                case 14:
                    c[i] = doub(doub(doub(d) ^ d) ^ d);
                    break;
                default:;
                }
            }
            result[4 * x + y] = c[0] ^ c[1] ^ c[2] ^ c[3];
        }
    }
    memcpy(msg, result, 16);
}

void aes128::add_round_key(unsigned char *msg, const int round) const {
    // Forward and reverse transformations are the same.
    for (int i = 0; i < 4 * N; ++i)
        msg[i] ^= schedule[round][i];
}

unsigned char aes128::doub(const unsigned char c) {
    if (c & 0x80)
        return c << 1 ^ 0x1b;
    return c << 1;
}
