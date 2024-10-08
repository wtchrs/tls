//
// Created by wtchr on 8/9/2024.
//

#include "tls/mpz.h"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("mpz") {
    uint8_t arr[8];
    mpz_class a{"0x1234567890abcdef"};
    mpz2bnd(a, arr, arr + 8);
    mpz_class b = bnd2mpz(arr, arr + 8);
    REQUIRE(a == b);
}
