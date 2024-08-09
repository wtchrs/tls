//
// Created by wtchr on 8/9/2024.
//

#include <catch2/catch_test_macros.hpp>
#include "rsa.h"

TEST_CASE("RSA") {
    const rsa_class rsa{256};
    const auto a = rsa.encode(mpz_class{"0x23423423"});
    REQUIRE(0x23423423 == rsa.decode(a));

    const auto msg = mpz_class{"0x143214324234"};
    const auto b = rsa.sign(msg);
    REQUIRE(rsa.encode(b) == msg);
}
