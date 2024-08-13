//
// Created by wtchr on 8/9/2024.
//

#include "tls/aes.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>

class aes128_test {
public:
    static void shift_row(unsigned char *msg) {
        aes128::shift_row(msg);
    }

    static void inv_shift_row(unsigned char *msg) {
        aes128::inv_shift_row(msg);
    }

    static void mix_column(unsigned char *msg) {
        aes128::mix_column(msg);
    }

    static void inv_mix_column(unsigned char *msg) {
        aes128::inv_mix_column(msg);
    }

    static const unsigned char *get_schedule(const aes128 &aes) {
        return aes.schedule[0];
    }
};

TEST_CASE("Inverse mix column matrix verify") {
    unsigned char inv[16] = {14, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14};
    unsigned char mix[16] = {2, 1, 1, 3, 3, 2, 1, 1, 1, 3, 2, 1, 1, 1, 3, 2};
    unsigned char o[16] = {1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1};
    aes128_test::mix_column(inv);
    aes128_test::inv_mix_column(mix);
    REQUIRE(std::equal(inv, inv + 16, o));
    REQUIRE(std::equal(mix, mix + 16, o));
}

TEST_CASE("Shift row and mix column") {
    unsigned char data[16], oneto16[16];
    for (int i = 0; i < 16; ++i)
        data[i] = oneto16[i] = i + 1;
    unsigned char shift_row_result[16] = {0x01, 0x06, 0x0b, 0x10, 0x05, 0x0a, 0x0f, 0x04,
                                          0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c};
    unsigned char mix_column_result[16] = {0x03, 0x04, 0x09, 0x0a, 0x0f, 0x08, 0x15, 0x1e,
                                           0x0b, 0x0c, 0x01, 0x02, 0x17, 0x10, 0x2d, 0x36};
    aes128_test::shift_row(data);
    REQUIRE(std::equal(data, data + 16, shift_row_result));
    aes128_test::inv_shift_row(data);
    REQUIRE(std::equal(data, data + 16, oneto16));

    aes128_test::mix_column(data);
    REQUIRE(std::equal(data, data + 16, mix_column_result));
    aes128_test::inv_mix_column(data);
    REQUIRE(std::equal(data, data + 16, oneto16));
}

unsigned char schedule[11 * 16] = {
        0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75, 0xE2, 0x32,
        0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88, 0xB1, 0x59, 0xE4, 0xE6, 0xD6, 0x79, 0xA2, 0x93, 0x56, 0x08, 0x20, 0x07,
        0xC7, 0x1A, 0xB1, 0x8F, 0x76, 0x43, 0x55, 0x69, 0xA0, 0x3A, 0xF7, 0xFA, 0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A,
        0xBC, 0x68, 0x63, 0x39, 0xE9, 0x01, 0xC3, 0x03, 0x1E, 0xFB, 0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1,
        0xD7, 0x51, 0x57, 0xA0, 0x14, 0x52, 0x49, 0x5B, 0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92, 0xD2, 0x10,
        0xD2, 0x32, 0xC6, 0x42, 0x9B, 0x69, 0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15, 0x6A, 0x6C, 0x95, 0x27,
        0xAC, 0x2E, 0x0E, 0x4E, 0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03, 0x1E, 0x86, 0x3F, 0x24, 0xB2, 0xA8,
        0x31, 0x6A, 0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22, 0xE4, 0x3D, 0x7A, 0x06, 0x56, 0x95, 0x4B, 0x6C,
        0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2, 0xA1, 0x64, 0x80, 0xB4, 0xF7, 0xF1, 0xCB, 0xD8, 0x28, 0xFD,
        0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A, 0xCC, 0xC0, 0xA4, 0xFE, 0x3B, 0x31, 0x6F, 0x26
};

TEST_CASE("Key scheduling") {
    aes128 aes; // NOLINT(*-pro-type-member-init)
    aes.set_key(schedule);
    REQUIRE(std::equal(schedule, schedule + 11 * 16, aes128_test::get_schedule(aes)));
}

TEST_CASE("Encrypt and Decrypt") {
    aes128 aes; // NOLINT(*-pro-type-member-init)
    const unsigned char key[16] = {0, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14};
    const unsigned char original[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    unsigned char block[16];
    std::copy_n(original, 16, block);
    aes.set_key(key);
    aes.encrypt(block);
    aes.decrypt(block);
    REQUIRE(std::equal(original, original + 16, block));
}
