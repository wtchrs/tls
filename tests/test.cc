//
// Created by wtchr on 8/5/2024.
//

#include <iostream>
#include <rsa.h>
#include <catch2/catch_test_macros.hpp>
#include "diffie_hellman.h"
#include "mpz.h"

TEST_CASE("mpz") {
    uint8_t arr[8];
    mpz_class a{"0x1234567890abcdef"};
    mpz2bnd(a, arr, arr + 8);
    mpz_class b = bnd2mpz(arr, arr + 8);
    REQUIRE(a == b);
}

TEST_CASE("Diffie Hellman Key Exchange") {
    diffie_hellman alice, bob;
    REQUIRE(alice.set_peer_public_key(bob.y) == bob.set_peer_public_key(alice.y));
    REQUIRE(alice.K == bob.K);
}

TEST_CASE("RSA") {
    const rsa_class rsa{256};
    const auto a = rsa.encode(mpz_class{"0x23423423"});
    REQUIRE(0x23423423 == rsa.decode(a));

    const auto msg = mpz_class{"0x143214324234"};
    const auto b = rsa.sign(msg);
    REQUIRE(rsa.encode(b) == msg);
}
