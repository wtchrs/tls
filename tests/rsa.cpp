#include "core/rsa.h"
#include <catch2/catch_test_macros.hpp>
#include <iostream>

TEST_CASE("RSA") {
    const RSA rsa{256};
    const auto original = mpz_class{"0x23423423"};
    const auto encoded = rsa.encode(original);
    const auto decoded = rsa.decode(encoded);
    std::cerr << "original value = 0x" << original.get_str(16) << std::endl;
    std::cerr << "encoded = 0x" << encoded.get_str(16) << std::endl;
    std::cerr << "decoded = 0x" << decoded.get_str(16) << std::endl;
    REQUIRE(0x23423423 == decoded);

    const auto msg = mpz_class{"0x143214324234"};
    const auto sign = rsa.sign(msg);
    REQUIRE(rsa.encode(sign) == msg);
}
