//
// Created by wtchr on 8/10/2024.
//

#include "tls/cipher_mode.h"
#include <catch2/catch_test_macros.hpp>
#include <nettle/gcm.h>
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

TEST_CASE("GCM") {
    // K: key, A: authenticated data, IV: initialization vector, P: plaintext, Z: authentication tag, C: ciphertext
    unsigned char K[16], A[70], IV[12], P[48], Z[64], C[48];
    mpz2bnd(random_prime(16), K, K + 16);
    mpz2bnd(random_prime(70), A, A + 70);
    mpz2bnd(random_prime(12), IV, IV + 12);
    mpz2bnd(random_prime(48), P, P + 48);
    SECTION("GCM compare with nettle") {
        gcm_aes128_ctx ctx; // NOLINT(*-pro-type-member-init)
        gcm_aes128_set_key(&ctx, K);
        gcm_aes128_set_iv(&ctx, 12, IV);
        gcm_aes128_update(&ctx, 28, A);
        gcm_aes128_encrypt(&ctx, 48, C, P);
        gcm_aes128_digest(&ctx, 16, Z);

        GCM<aes128> gcm;
        gcm.set_iv(IV);
        gcm.set_key(K);
        gcm.set_aad(A, 28);
        auto a = gcm.encrypt(P, 48); // Overwrite P with ciphertext

        REQUIRE(std::equal(P, P + 48, C));
        REQUIRE(std::equal(a.begin(), a.end(), Z));
    }
}
