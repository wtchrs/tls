#include "tls/base64.h"
#include <catch2/catch_test_macros.hpp>

TEST_CASE("BASE64 encode and decode") {
    std::vector<unsigned char> v;
    for (int i = 0; i < 256; ++i)
        v.push_back(i);
    std::string s = base64_encode(v);
    std::vector<unsigned char> v2 = base64_decode(s);
    REQUIRE(v == v2);
}
