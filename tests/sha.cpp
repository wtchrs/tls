//
// Created by wtchr on 8/13/2024.
//

#include <catch2/catch_test_macros.hpp>
#include "tls/mpz.h"
#include "tls/sha/sha1.h"
#include "tls/sha/sha2.h"

TEST_CASE("SHA") {
    const std::string s[] = {// clang-format off
            "abc",
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    }; // clang-format on

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

        SECTION("SHA-384") {
            const char *result[] = {
                    // clang-format off
                    "0xcb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                    "0x3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b",
                    "0x09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
            }; // clang-format on
            sha384 sha{};
            for (int i = 0; i < 3; ++i) {
                unsigned char nresult[48];
                mpz2bnd(mpz_class{result[i]}, nresult, nresult + 48);
                auto a = sha.hash(s[i].begin(), s[i].end());
                REQUIRE(std::equal(a.begin(), a.end(), nresult));
            }
        }

        SECTION("SHA-512") {
            const char *result[] = {// clang-format off
                    "0xddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                    "0x204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445",
                    "0x8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
            }; // clang-format on
            sha512 sha{};
            for (int i = 0; i < 3; ++i) {
                unsigned char nresult[64];
                mpz2bnd(mpz_class{result[i]}, nresult, nresult + 64);
                auto a = sha.hash(s[i].begin(), s[i].end());
                REQUIRE(std::equal(a.begin(), a.end(), nresult));
            }
        }
    }
}
