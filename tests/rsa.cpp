#include "core/rsa.h"
#include <catch2/catch_test_macros.hpp>
#include <spdlog/spdlog.h>

TEST_CASE("RSA") {
    const RSA rsa{256};
    const auto original = mpz_class{"0x23423423"};
    const auto encoded = rsa.encode(original);
    const auto decoded = rsa.decode(encoded);
    spdlog::info("original value = 0x{}", original.get_str(16));
    spdlog::info("encoded = 0x{}", encoded.get_str(16));
    spdlog::info("decoded = 0x{}", decoded.get_str(16));
    REQUIRE(0x23423423 == decoded);

    const auto msg = mpz_class{"0x143214324234"};
    const auto sign = rsa.sign(msg);
    REQUIRE(rsa.encode(sign) == msg);
}
