#include "tls/tls.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <iostream>
#include "aes_test.h"
#include "tls/aes.h"
#include "tls/cipher_mode.h"
#include "util.h"

class GCMTest : public GCM<AES128> {
public:
    const AES128 &get_cipher() const {
        return this->cipher_;
    }
};

template<bool SV>
class TLSTest : public TLS<SV> {
public:
    // Access to protected members through inheritance
    mpz_class get_enc_seq_num() const {
        return this->enc_seq_num_;
    }
    mpz_class get_dec_seq_num() const {
        return this->dec_seq_num_;
    }

    const ECPoint &get_public_key() const {
        return this->P_;
    }
    mpz_class get_private_key() const {
        return this->prv_key_;
    }

    const std::vector<unsigned char> &get_master_secret() const {
        return this->master_secret_;
    }
    const std::string &get_accumulated_handshakes() const {
        return this->accumulated_handshakes_;
    }

    const std::array<unsigned char, 32> &get_server_random() const {
        return this->server_random_;
    }
    const std::array<unsigned char, 32> &get_client_random() const {
        return this->client_random_;
    }
    const std::array<unsigned char, 32> &get_session_id() const {
        return this->session_id_;
    }

    // Access to protected AES instances
    const GCM<AES128> &get_aes(int index) const {
        return this->aes_[index];
    }

    void set_aes(int i, GCM<AES128> aes) {
        this->aes_[i] = aes;
    }
};

TEST_CASE("Test TLS without other layer") {
    TLSTest<true> server;
    TLSTest<false> client;

    GCMTest server_aes[2];
    GCMTest client_aes[2];
    for (int i = 0; i < 2; ++i) {
        server.set_aes(i, server_aes[i]);
        client.set_aes(i, client_aes[i]);
    }

    // ========== Perform TLS handshake ==========

    if (!server.client_hello(client.client_hello()).empty()) {
        FAIL("Failed CLIENT_HELLO");
    }
    if (!client.server_hello(server.server_hello()).empty()) {
        FAIL("Failed SERVER_HELLO");
    }
    if (!client.server_certificate(server.server_certificate()).empty()) {
        FAIL("Failed SERVER_CERTIFICATE");
    }
    if (!client.server_key_exchange(server.server_key_exchange()).empty()) {
        FAIL("Failed SERVER_KEY_EXCHANGE");
    }
    if (!client.server_hello_done(server.server_hello_done()).empty()) {
        FAIL("Failed SERVER_HELLO_DONE");
    }
    if (!server.client_key_exchange(client.client_key_exchange()).empty()) {
        FAIL("Failed CLIENT_KEY_EXCHANGE");
    }
    if (!server.change_cipher_spec(client.change_cipher_spec()).empty()) {
        FAIL("Failed CLIENT_CHANGE_CIPHER_SPEC");
    }
    if (!server.finished(client.finished()).empty()) {
        FAIL("Failed CLIENT_FINISHED");
    }
    if (!client.change_cipher_spec(server.change_cipher_spec()).empty()) {
        FAIL("Failed SERVER_CHANGE_CIPHER_SPEC");
    }
    if (!client.finished(server.finished()).empty()) {
        FAIL("Failed SERVER_FINISHED");
    }

    REQUIRE(std::equal(
            server.get_master_secret().begin(), server.get_master_secret().end(), client.get_master_secret().begin()
    ));
    REQUIRE(std::equal(
            server.get_client_random().begin(), server.get_client_random().end(), client.get_client_random().begin()
    ));
    REQUIRE(std::equal(
            server.get_server_random().begin(), server.get_server_random().end(), client.get_server_random().begin()
    ));

    for (int i = 0; i < 2; i++) {
        REQUIRE(std::equal(
                AES128Test::get_schedule(((const GCMTest &) (server.get_aes(i))).get_cipher()),
                AES128Test::get_schedule(((const GCMTest &) (server.get_aes(i))).get_cipher()) + 11 * 16,
                AES128Test::get_schedule(((const GCMTest &) (client.get_aes(i))).get_cipher())
        ));
    }

    auto opt_cli_msg = server.decode(client.encode("hello world"));
    if (!opt_cli_msg) {
        FAIL("Failed to decode client message");
    }
    if (std::string{"hello world"} != *opt_cli_msg) {
        EXPECTED("hello world", *opt_cli_msg);
    }

    auto opt_srv_msg = client.decode(server.encode("Hello, world!"));
    if (!opt_srv_msg) {
        FAIL("Failed to decode server message");
    }
    if (std::string{"Hello, world!"} != *opt_srv_msg) {
        EXPECTED("Hello, world!", *opt_srv_msg);
    }
}
