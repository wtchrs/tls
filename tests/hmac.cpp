//
// Created by wtchr on 8/16/2024.
//

#include "tls/hmac.h"
#include <catch2/catch_test_macros.hpp>

#include "tls/mpz.h"
#include "tls/sha/sha1.h"

TEST_CASE("HMAC-SHA1") {
    const std::string data[] = {
            "Sample message for keylen=blocklen", "Sample message for keylen<blocklen",
            "Sample message for keylen=blocklen", "Sample message for keylen<blocklen, with truncated tag"
    };
    const char *key[] = {
            "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233"
            "3435363738393A3B3C3D3E3F",
            "0x000102030405060708090A0B0C0D0E0F10111213",
            "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233"
            "3435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263",
            "0x000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30"
    };
    const char *expected[] = {
            "0x5FD596EE78D5553C8FF4E72D266DFD192366DA29", "0x4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807",
            "0x2D51B2F7750E410584662E38F133435F4C4FD42A", "0xFE3529565CD8E28C5FA79EAC9D8023B53B289D96"
    };

    // constexpr size_t data_len[] = {34, 34, 34, 54};
    constexpr size_t key_len[] = {64, 20, 100, 49};

    hmac<sha1> hmac;
    for (int i = 0; i < 4; ++i) {
        unsigned char nkey[100], nresult[20];
        mpz2bnd(mpz_class{key[i]}, nkey, nkey + key_len[i]);
        mpz2bnd(mpz_class{expected[i]}, nresult, nresult + 20);
        hmac.key(nkey, nkey + key_len[i]);
        auto h = hmac.hash(data[i].begin(), data[i].end());
        REQUIRE(std::equal(h.begin(), h.end(), nresult));
    }
}
