#include "core/tls12.h"
#include <algorithm>
#include <atomic>
#include <catch2/catch_test_macros.hpp>
#include <condition_variable>
#include <future>
#include <mutex>
#include <queue>
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
class TLSTest : public TLS12<SV> {
public:
    TLSTest(Read read_f, Write write_f)
        : TLS12<SV>{read_f, write_f} {}


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
    TLSTest<true> server{[]() -> std::optional<std::string> { return "dummy"; }, [](auto) {}};
    TLSTest<false> client{[]() -> std::optional<std::string> { return "dummy"; }, [](auto) {}};

    GCMTest client_aes[2];
    GCMTest server_aes[2];
    for (int i = 0; i < 2; ++i) {
        server.set_aes(i, server_aes[i]);
        client.set_aes(i, client_aes[i]);
    }

    // ========== TLS Handshake ==========

    spdlog::info("client_hello - START");
    auto r = server.client_hello(client.client_hello());
    REQUIRE_MESSAGE(r.empty(), "Failed CLIENT_HELLO: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("client_hello - OK");

    spdlog::info("server_hello - START");
    r = client.server_hello(server.server_hello());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_HELLO: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_hello - OK");

    spdlog::info("server_certificate - START");
    r = client.server_certificate(server.server_certificate());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_CERTIFICATE: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_certificate - OK");

    spdlog::info("server_key_exchange - START");
    r = client.server_key_exchange(server.server_key_exchange());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_KEY_EXCHANGE: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_key_exchange - OK");

    spdlog::info("server_hello_done - START");
    r = client.server_hello_done(server.server_hello_done());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_HELLO_DONE: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_hello_done - OK");

    spdlog::info("client_key_exchange - START");
    r = server.client_key_exchange(client.client_key_exchange());
    REQUIRE_MESSAGE(r.empty(), "Failed CLIENT_KEY_EXCHANGE: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("client_key_exchange - OK");

    spdlog::info("client_change_cipher_spec - START");
    r = server.change_cipher_spec(client.change_cipher_spec());
    REQUIRE_MESSAGE(r.empty(), "Failed CLIENT_CHANGE_CIPHER_SPEC: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("client_change_cipher_spec - OK");

    spdlog::info("client_finished - START");
    r = server.finished(client.finished());
    REQUIRE_MESSAGE(r.empty(), "Failed CLIENT_FINISHED: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("client_finished - OK");

    spdlog::info("server_change_cipher_spec - START");
    r = client.change_cipher_spec(server.change_cipher_spec());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_CHANGE_CIPHER_SPEC: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_change_cipher_spec - OK");

    spdlog::info("server_finished - START");
    r = client.finished(server.finished());
    REQUIRE_MESSAGE(r.empty(), "Failed SERVER_FINISHED: " << bytes_to_hex(r.cbegin(), r.cend()));
    spdlog::info("server_finished - OK");

    // ========== Check master secret, client random and server random ==========

    // clang-format off
    REQUIRE_MESSAGE(
        std::equal( server.get_master_secret().begin(), server.get_master_secret().end(), client.get_master_secret().begin()),
        "Server and client's master secrets are not equal."
    );
    REQUIRE_MESSAGE(
        std::equal( server.get_client_random().begin(), server.get_client_random().end(), client.get_client_random().begin()),
        "Server and client's client random values are not equal."
    );
    REQUIRE_MESSAGE(
        std::equal( server.get_server_random().begin(), server.get_server_random().end(), client.get_server_random().begin()),
        "Server and client's server random values are not equal."
    );
    // clang-format on

    // ========== Check schedule ==========

    for (int i = 0; i < 2; i++) {
        INFO("Server and client's " << i << "th schedule values are not equal.");
        REQUIRE(
            std::equal(
                AES128Test::get_schedule(((const GCMTest &) (server.get_aes(i))).get_cipher()),
                AES128Test::get_schedule(((const GCMTest &) (server.get_aes(i))).get_cipher()) + 11 * 16,
                AES128Test::get_schedule(((const GCMTest &) (client.get_aes(i))).get_cipher())
            )
        );
    }

    // ========== Client send message ==========

    auto opt_cli_msg = server.decode(client.encode("hello world"));
    REQUIRE_MESSAGE(opt_cli_msg.has_value(), "Server failed to decode client message. `opt_cli_msg` must have value.");
    REQUIRE_MESSAGE(*opt_cli_msg == std::string{"hello world"}, "Server failed to decode client message.");

    // ========== Server send message ==========

    auto opt_srv_msg = client.decode(server.encode("Hello, world!"));
    REQUIRE_MESSAGE(opt_srv_msg.has_value(), "Client failed to decode server message. `opt_srv_msg` must have value.");
    REQUIRE_MESSAGE(*opt_srv_msg == std::string{"Hello, world!"}, "Client failed to decode server message.");
}

TEST_CASE("Test TLS Handshake") {
    std::queue<std::string> to_server_q;
    std::mutex to_server_m;
    std::condition_variable to_server_cv;
    std::atomic_bool client_is_done = false;

    std::queue<std::string> to_client_q;
    std::mutex to_client_m;
    std::condition_variable to_client_cv;
    std::atomic_bool server_is_done = false;

    TLSTest<SV_SERVER> server{
        [&]() -> std::optional<std::string> {
            std::unique_lock<std::mutex> lk(to_server_m);
            to_server_cv.wait(lk, [&] { return !to_server_q.empty() || client_is_done; });
            spdlog::info("Acquire server mutex");
            if (to_server_q.empty()) {
                spdlog::info("Empty server queue");
                return std::nullopt;
            }
            std::string s = std::move(to_server_q.front());
            to_server_q.pop();
            return s;
        },
        [&](std::string s) {
            {
                std::lock_guard<std::mutex> lk(to_client_m);
                to_client_q.push(std::move(s));
            }
            to_client_cv.notify_one();
        }
    };
    TLSTest<SV_CLIENT> client{
        [&]() -> std::optional<std::string> {
            std::unique_lock<std::mutex> lk(to_client_m);
            to_client_cv.wait(lk, [&] { return !to_client_q.empty() || server_is_done; });
            if (to_client_q.empty()) {
                return std::nullopt;
            }
            std::string s = std::move(to_client_q.front());
            to_client_q.pop();
            return s;
        },
        [&](std::string s) {
            {
                std::lock_guard<std::mutex> lk(to_server_m);
                to_server_q.push(std::move(s));
            }
            to_server_cv.notify_one();
        }
    };

    auto server_task = [&]() -> bool {
        bool ok = server.handshake();
        server_is_done = true;
        to_client_cv.notify_one();
        return ok;
    };

    auto client_task = [&]() -> bool {
        bool ok = client.handshake();
        client_is_done = true;
        to_server_cv.notify_one();
        return ok;
    };

    auto server_future = std::async(std::launch::async, server_task);
    auto client_future = std::async(std::launch::async, client_task);

    bool server_ok = server_future.get();
    bool client_ok = client_future.get();

    REQUIRE(server_ok);
    REQUIRE(client_ok);

    // Post-handshake checks
    REQUIRE_MESSAGE(
        std::equal(
            server.get_master_secret().begin(), server.get_master_secret().end(), client.get_master_secret().begin()
        ),
        "Server and client's master secrets are not equal."
    );

    // Application data
    auto opt_cli_msg = server.decode(client.encode("hello world"));
    REQUIRE(opt_cli_msg.has_value());
    REQUIRE(*opt_cli_msg == "hello world");

    auto opt_srv_msg = client.decode(server.encode("Hello, world!"));
    REQUIRE(opt_srv_msg.has_value());
    REQUIRE(*opt_srv_msg == "Hello, world!");
}
