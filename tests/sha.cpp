//
// Created by wtchr on 8/13/2024.
//

#include <catch2/catch_test_macros.hpp>
#include "tls/mpz.h"
#include "tls/sha1.h"
#include "tls/sha2.h"

TEST_CASE("SHA") {
    const std::string s[] = {
            "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstno"
            "pqrstu"
    };

    SECTION("SHA-1") {
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

    SECTION("SHA-2") {
        SECTION("SHA-224") {
            const char *result[] = {
                    "0x23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
                    "0x75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525",
                    "0xc97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3"
            };
            sha224 sha{};
            for (int i = 0; i < 3; ++i) {
                unsigned char nresult[28];
                mpz2bnd(mpz_class{result[i]}, nresult, nresult + 28);
                auto a = sha.hash(s[i].begin(), s[i].end());
                REQUIRE(std::equal(a.begin(), a.end(), nresult));
            }
        }

        SECTION("SHA-256") {
            const char *result[] = {
                    "0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    "0x248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
                    "0xcf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
            };
            sha256 sha{};
            for (int i = 0; i < 3; ++i) {
                unsigned char nresult[32];
                mpz2bnd(mpz_class{result[i]}, nresult, nresult + 32);
                auto a = sha.hash(s[i].begin(), s[i].end());
                REQUIRE(std::equal(a.begin(), a.end(), nresult));
            }
        }
    }
}
