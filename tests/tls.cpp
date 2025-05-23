#include "core/tls.h"
#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <spdlog/spdlog.h>
#include "aes_test.h"
#include "core/aes.h"
#include "core/cipher_mode.h"
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
    [[nodiscard]]
    mpz_class get_enc_seq_num() const {
        return this->enc_seq_num_;
    }
    [[nodiscard]]
    mpz_class get_dec_seq_num() const {
        return this->dec_seq_num_;
    }

    [[nodiscard]]
    const ECPoint &get_public_key() const {
        return this->P_;
    }
    [[nodiscard]]
    mpz_class get_private_key() const {
        return this->prv_key_;
    }

    [[nodiscard]]
    const std::vector<unsigned char> &get_master_secret() const {
        return this->master_secret_;
    }
    [[nodiscard]]
    const std::string &get_accumulated_handshakes() const {
        return this->accumulated_handshakes_;
    }

    [[nodiscard]]
    const std::array<unsigned char, 32> &get_server_random() const {
        return this->server_random_;
    }
    [[nodiscard]]
    const std::array<unsigned char, 32> &get_client_random() const {
        return this->client_random_;
    }
    [[nodiscard]]
    const std::array<unsigned char, 32> &get_session_id() const {
        return this->session_id_;
    }

    // Access to protected AES instances
    [[nodiscard]]
    const GCM<AES128> &get_aes(int index) const {
        return this->aes_[index];
    }
    void set_aes(int i, GCM<AES128> aes) {
        this->aes_[i] = aes;
    }

    [[nodiscard]]
    const RSA &get_rsa() const {
        return this->rsa_;
    }
};

TEST_CASE("Test TLS without other layer") {
    TLSTest<true> server;
    TLSTest<false> client;

    GCMTest client_aes[2];
    GCMTest server_aes[2];
    for (int i = 0; i < 2; ++i) {
        server.set_aes(i, server_aes[i]);
        client.set_aes(i, client_aes[i]);
    }

    // ========== Perform TLS handshake ==========

    spdlog::info("client_hello - START");

    if (auto r = server.client_hello(client.client_hello()); !r.empty()) {
        spdlog::error("Failed CLIENT_HELLO: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed CLIENT_HELLO");
    }

    spdlog::info("client_hello - OK");
    spdlog::info("server_hello - START");

    if (auto r = client.server_hello(server.server_hello()); !r.empty()) {
        spdlog::error("Failed SERVER_HELLO: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_HELLO");
    }

    spdlog::info("server_hello - OK");
    spdlog::info("server_certificate - START");

    if (auto r = client.server_certificate(server.server_certificate()); !r.empty()) {
        spdlog::error("Failed SERVER_CERTIFICATE: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_CERTIFICATE");
    }

    spdlog::info("server_certificate - OK");
    spdlog::info("server_key_exchange - START");

    if (auto r = client.server_key_exchange(server.server_key_exchange()); !r.empty()) {
        // TODO: Failed intermittently
        spdlog::error("Failed SERVER_KEY_EXCHANGE: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_KEY_EXCHANGE");
    }

    spdlog::info("server_key_exchange - OK");
    spdlog::info("server_hello_done - START");

    if (auto r = client.server_hello_done(server.server_hello_done()); !r.empty()) {
        spdlog::error("Failed SERVER_HELLO_DONE: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_HELLO_DONE");
    }

    spdlog::info("server_hello_done - OK");
    spdlog::info("client_key_exchange - START");

    if (auto r = server.client_key_exchange(client.client_key_exchange()); !r.empty()) {
        spdlog::error("Failed CLIENT_KEY_EXCHANGE: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed CLIENT_KEY_EXCHANGE");
    }

    spdlog::info("client_key_exchange - OK");
    spdlog::info("client_change_cipher_spec - START");

    if (auto r = server.change_cipher_spec(client.change_cipher_spec()); !r.empty()) {
        spdlog::error("Failed CLIENT_CHANGE_CIPHER_SPEC: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed CLIENT_CHANGE_CIPHER_SPEC");
    }

    spdlog::info("client_change_cipher_spec - OK");
    spdlog::info("client_finished - START");

    if (auto r = server.finished(client.finished()); !r.empty()) {
        spdlog::error("Failed CLIENT_FINISHED: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed CLIENT_FINISHED");
    }

    spdlog::info("client_finished - OK");
    spdlog::info("server_change_cipher_spec - START");

    if (auto r = client.change_cipher_spec(server.change_cipher_spec()); !r.empty()) {
        spdlog::error("Failed SERVER_CHANGE_CIPHER_SPEC: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_CHANGE_CIPHER_SPEC");
    }

    spdlog::info("server_change_cipher_spec - OK");
    spdlog::info("server_finished - START");

    if (auto r = client.finished(server.finished()); !r.empty()) {
        spdlog::error("Failed SERVER_FINISHED: {}", bytes_to_hex(r.cbegin(), r.cend()));
        FAIL("Failed SERVER_FINISHED");
    }

    spdlog::info("server_finished - OK");

    // ========== Finished TLS handshake ==========

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
    REQUIRE((opt_cli_msg = server.decode(client.encode("hello world"))));
    if (!opt_cli_msg) {
        FAIL("Failed to decode client message");
    }
    REQUIRE(*opt_cli_msg == std::string{"hello world"});

    auto opt_srv_msg = client.decode(server.encode("Hello, world!"));
    if (!opt_srv_msg) {
        FAIL("Failed to decode server message");
    }
    REQUIRE(*opt_srv_msg == std::string{"Hello, world!"});
}
