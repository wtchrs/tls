//
// Created by wtchr on 8/10/2024.
//

#include "tls/cipher_mode.h"
#include <catch2/catch_test_macros.hpp>
#include "tls/aes.h"

TEST_CASE("CBC") {
    CBC<aes128> cbc;
    const unsigned char key[16] = {0, 9, 13, 11, 11, 14, 9, 13, 13, 11, 14, 9, 9, 13, 11, 14};
    const unsigned char iv[16] = {14, 21, 13, 11, 11, 7, 9, 13, 0, 11, 14, 9, 9, 13, 11, 14};
    cbc.set_key(key);
    cbc.set_iv(iv);

    std::string msg = "Hello this is a test";
    // PKCS7 padding
    const size_t padding_size = 16 - msg.size() % 16;
    msg.append(padding_size, static_cast<char>(padding_size));
    auto p = reinterpret_cast<unsigned char *>(msg.data());
    cbc.encrypt(p, msg.size());
    cbc.decrypt(p, msg.size());
    // PKCS7 unpadding
    for (int pad = static_cast<unsigned char>(msg.back()); pad > 0; --pad)
        msg.pop_back();
    REQUIRE(msg == "Hello this is a test");
}
