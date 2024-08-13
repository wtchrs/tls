//
// Created by wtchr on 8/13/2024.
//

#include "tls/sha.h"
#include <catch2/catch_test_macros.hpp>
#include "tls/mpz.h"

TEST_CASE("SHA-1") {
    const std::string s[] = {
            "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstno"
            "pqrstu"
    };
    const char *result[] = {
            "0xa9993e364706816aba3e25717850c26c9cd0d89d", "0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
            "0xa49b2446a02c645bf419f995b67091253a04a259"
    };
    sha1 sha{};
    for (int i = 0; i < 3; ++i) {
        unsigned char nresult[20];
        mpz2bnd(mpz_class{result[i]}, nresult, nresult + 20);
        auto a = sha.hash(s[i].begin(), s[i].end());
        REQUIRE(std::equal(a.begin(), a.end(), nresult));
    }
}
