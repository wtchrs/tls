//
// Created by wtchr on 8/8/2024.
//

#include "tls/ecdsa.h"
#include <array>
#include <catch2/catch_test_macros.hpp>
#include <nettle/sha.h>
#include "tls/mpz.h"

TEST_CASE("ECDSA") {
    const ec_field secp256r1{
            mpz_class{"0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc"},
            mpz_class{"0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"},
            mpz_class{"0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"}
    };
    const ec_point G{
            mpz_class{"0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"},
            mpz_class{"0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}, secp256r1
    };
    const auto n = mpz_class{"0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"};
    const mpz_class d = random_prime(31); // Random private key
    const auto Q = d * G; // Public key

    const ecdsa_class ecdsa{G, n};

    const auto message = "Hello, world!";
    unsigned char digest[SHA256_DIGEST_SIZE];

    sha256_ctx ctx; // NOLINT(*-pro-type-member-init)
    sha256_init(&ctx);
    sha256_update(&ctx, strlen(message), reinterpret_cast<const uint8_t *>(message));
    sha256_digest(&ctx, SHA256_DIGEST_SIZE, digest);

    const auto z = bnd2mpz(digest, digest + SHA256_DIGEST_SIZE);
    const auto sign = ecdsa.sign(z, d);
    REQUIRE(ecdsa.verify(z, sign, Q));
}
