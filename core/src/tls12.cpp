#include "core/tls12.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gmpxx.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>
#include <utility>
#include <variant>
#include <vector>
#include "core/base64.h"
#include "core/cert.h"
#include "core/der.h"
#include "core/diffie_hellman.h"
#include "core/mpz.h"
#include "core/prf.h"
#include "core/rsa.h"
#include "core/sha/sha2.h"
#include "core/tls12_types.h"
#include "core/tls_types.h"
#include "core/utils.h"

static tls::Record init_certificate_message() {
    std::ifstream cert_pem{"./cert/example/cert.pem"};
    std::vector<std::string> certificates;
    for (std::string s; !(s = get_certificate_core(cert_pem)).empty();) {
        auto v = base64_decode(s);
        certificates.emplace_back(v.begin(), v.end());
    }
    return tls::Record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::CERTIFICATE,
            tls::Certificate{std::move(certificates)},
        }}
    };
}

static RSA init_rsa() {
    std::ifstream prv_pem{"./cert/example/key.pem"};
    if (!prv_pem.is_open()) {
        throw "Failed to open the private key PEM file.";
    }
    auto opt_keys = get_keys(prv_pem);
    if (!opt_keys) {
        throw "Failed to parse the private key PEM file.";
    }
    auto [K, e, d] = *opt_keys;
    return {e, d, K};
}

template<bool SV>
tls::Record TLS12<SV>::certificate_ = init_certificate_message();

template<bool SV>
RSA TLS12<SV>::rsa_ = init_rsa();

template<bool SV>
std::pair<int, int> TLS12<SV>::get_content_type(const std::string &s) {
    auto p = reinterpret_cast<const uint8_t *>(s.data());
    return {p[0], p[5]};
}

template<bool SV>
std::optional<std::string> TLS12<SV>::decode(std::string &&s) {
    auto res = tls::Record::parse(s, true);
    if (!res || (res->content_type != tls::HANDSHAKE && res->content_type != tls::APPLICATION_DATA))
        return std::nullopt;
    auto encoded_msg = std::get<tls::EncodedMessage>(res->messages[0]);

    // Increase sequence number after filling tag_data.seq.
    std::array<uint8_t, 8> seq{};
    mpz2bnd(dec_seq_num_++, seq.begin(), seq.end());

    auto msg_len = encoded_msg.data.length();
    tls::AAD aad{seq, res->content_type, res->version, static_cast<uint16_t>(msg_len)};

    aes_[!SV].set_aad(aad.serialize());
    aes_[!SV].set_iv(encoded_msg.iv.begin(), 4, 8);

    auto auth = aes_[!SV].decrypt(reinterpret_cast<unsigned char *>(encoded_msg.data.data()), msg_len);
    if (!std::equal(auth.begin(), auth.end(), encoded_msg.auth_tag.begin())) {
        // Failed to check authentication tag
        return std::nullopt;
    }
    return std::move(encoded_msg.data);
}

template<bool SV>
std::string TLS12<SV>::encode(std::string &&s, const tls::ContentType type) {
    // GCM-based encoding
    constexpr size_t CHUNK_SIZE = (1 << 14) - 64; // Maximum length for a chunk.
    const size_t len = std::min(s.size(), CHUNK_SIZE);

    std::array<uint8_t, 8> iv{};
    mpz2bnd(random_prime(8), iv.begin(), iv.end());
    aes_[SV].set_iv(iv.begin(), 4, 8);

    // Increase sequence number after filling tag_data.seq.
    std::array<uint8_t, 8> seq{};
    mpz2bnd(enc_seq_num_++, seq.begin(), seq.end());
    tls::AAD aad{seq, type, tls::TLS_VERSION_12, static_cast<uint16_t>(len)};
    aes_[SV].set_aad(aad.serialize());

    std::string frag = s.substr(0, len);
    auto tag = aes_[SV].encrypt(reinterpret_cast<unsigned char *>(frag.data()), frag.size());

    tls::Record rec{type, tls::TLS_VERSION_12, {tls::EncodedMessage{std::move(iv), std::move(frag), std::move(tag)}}};
    auto r = rec.serialize();

    if (s.size() > CHUNK_SIZE) {
        // Encode recursively if the message is long.
        r += encode(s.substr(CHUNK_SIZE));
    }
    return r;
}

// ========== TLS<SV> CLASS METHOD IMPLEMENTATIONS ==========

template<>
std::string TLS12<SV_CLIENT>::client_hello(std::string &&) {
    std::array<uint8_t, 32> client_random;
    mpz2bnd(random_prime(32), client_random.begin(), client_random.end());
    std::copy(client_random.begin(), client_random.end(), this->client_random_.begin());
    tls::Record record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::CLIENT_HELLO,
            tls::ClientHello{
                tls::TLS_VERSION_12,
                std::move(client_random),
                std::vector<uint8_t>(32),
                std::vector{tls::TLS_ECDHE_RSA_AES128_GCM_SHA256},
                std::vector<uint8_t>{0}
            }
        }}
    };
    return accumulate(record.serialize());
}

template<>
std::string TLS12<SV_SERVER>::client_hello(std::string &&s) {
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto handshake = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (handshake->handshake_type != tls::CLIENT_HELLO)
            return alert(2, 10);
        auto client_hello = std::get<tls::ClientHello>(handshake->message);
        accumulate(s);
        std::copy(client_hello.client_random.begin(), client_hello.client_random.end(), this->client_random_.begin());
        for (const auto &cipher_suite : client_hello.cipher_suites) {
            // Support only the one cipher suite.
            if (cipher_suite == tls::TLS_ECDHE_RSA_AES128_GCM_SHA256) {
                return ""; // success
            }
        }
    }
    return alert(2, 40); // handshake_failure
}

template<>
std::string TLS12<SV_CLIENT>::server_hello(std::string &&s) {
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto msg = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (msg->handshake_type != tls::SERVER_HELLO)
            return alert(2, 10);
        accumulate(s);
        auto server_hello = std::get<tls::ServerHello>(msg->message);
        std::copy(server_hello.server_random.begin(), server_hello.server_random.end(), this->server_random_.begin());
        this->session_id_.resize(server_hello.session_id.size());
        std::copy(server_hello.session_id.begin(), server_hello.session_id.end(), this->session_id_.begin());
        if (server_hello.cipher_suite == tls::TLS_ECDHE_RSA_AES128_GCM_SHA256)
            return ""; // success
    }
    return alert(2, 40);
}

template<>
std::string TLS12<SV_SERVER>::server_hello(std::string &&) {
    mpz2bnd(random_prime(32), this->server_random_.begin(), this->server_random_.end());
    mpz2bnd(random_prime(32), this->session_id_.begin(), this->session_id_.end());
    tls::Record record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::SERVER_HELLO,
            tls::ServerHello{
                tls::TLS_VERSION_12,
                std::array<uint8_t, 32>{this->server_random_},
                std::vector<uint8_t>{this->session_id_},
                tls::TLS_ECDHE_RSA_AES128_GCM_SHA256,
                0
            }
        }}
    };
    return accumulate(record.serialize());
}

template<>
std::string TLS12<SV_CLIENT>::server_certificate(std::string &&s) {
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto msg = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (msg->handshake_type != tls::CERTIFICATE)
            return alert(2, 10);
        accumulate(s);
        tls::Certificate certificate = std::get<tls::Certificate>(msg->message);
        // Read the first certificate and extract public key parameters.
        // TODO: Change to check all certificate chains.
        std::stringstream ss{certificate.certificates[0]};
        auto opt_pubkey = der2json(ss).and_then([](auto json_value) { return get_pubkeys(json_value); });
        if (!opt_pubkey) {
            spdlog::error("Failed to parse the received certificate.");
            return alert(2, 44);
        }
        auto [K, e, sign] = *opt_pubkey;
        rsa_.K_ = K;
        rsa_.e_ = e;
        return "";
    }
    return alert(2, 40);
}

template<>
std::string TLS12<SV_SERVER>::server_certificate(std::string &&) {
    return accumulate(certificate_.serialize());
}

template<bool SV>
void TLS12<SV>::generate_signature(unsigned char *pub_key, unsigned char *sign) const {
    // Prepare the data to be signed.
    unsigned char message_to_hash[MESSAGE_TO_HASH_SIZE]; // server random + client random + public key
    std::copy(client_random_.cbegin(), client_random_.cend(), message_to_hash);
    std::copy(server_random_.cbegin(), server_random_.cend(), message_to_hash + RANDOM_SIZE);
    std::copy_n(pub_key, PUBKEY_SIZE, message_to_hash + RANDOM_SIZE * 2);
    SHA256 sha;
    const auto hash = sha.hash(message_to_hash, message_to_hash + MESSAGE_TO_HASH_SIZE); // Result size is 32 bytes.

    // Prepare PKCS#1 v1.5 padding structure.
    // See more: https://www.rfc-editor.org/rfc/rfc8017#section-9.2
    unsigned char padded[RSA_SIG_SIZE];
    unsigned char *ptr = padded + RSA_SIG_SIZE; // Start from the end of padded
    // Add hash value.
    ptr -= hash.size();
    std::copy(hash.cbegin(), hash.cend(), ptr);
    *--ptr = hash.size(); // Add hash size (0x20) before hash value
    // der is depending on the signature method.
    constexpr unsigned char SHA256_DER[] = {
        0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04
    };
    ptr -= sizeof(SHA256_DER);
    std::copy_n(SHA256_DER, sizeof(SHA256_DER), ptr);
    *--ptr = hash.size() + sizeof(SHA256_DER) + 1; // Add length (0x31)
    *--ptr = 0x30;
    *--ptr = 0x00;
    // Add padding
    std::fill(padded + 2, ptr, 0xff);
    padded[0] = 0x00;
    padded[1] = 0x01;

    // Sign with RSA.
    const auto z = rsa_.sign(bnd2mpz(padded, padded + 256));
    mpz2bnd(z, sign, sign + RSA_SIG_SIZE);
}

template<bool SV>
void TLS12<SV>::derive_keys(const mpz_class &premaster_secret) {
    unsigned char pre[32], rand[64];
    mpz2bnd(premaster_secret, pre, pre + 32);
    PRF<SHA256> prf;
    prf.secret(pre, pre + 32);
    std::copy(client_random_.cbegin(), client_random_.cend(), rand);
    std::copy(server_random_.cbegin(), server_random_.cend(), rand + 32);
    prf.seed(rand, rand + 64);
    prf.label("master secret");
    master_secret_ = prf.get_n_bytes(48);
    prf.secret(master_secret_.begin(), master_secret_.end());
    std::copy(server_random_.cbegin(), server_random_.cend(), rand);
    std::copy(client_random_.cbegin(), client_random_.cend(), rand + 32);
    prf.seed(rand, rand + 64);
    prf.label("key expansion");
    const auto v = prf.get_n_bytes(40);
    aes_[0].set_key(&v[0]);
    aes_[1].set_key(&v[16]);
    aes_[0].set_iv(&v[32], 0, 4);
    aes_[1].set_iv(&v[36], 0, 4);
}

template<>
std::string TLS12<SV_CLIENT>::server_key_exchange(std::string &&s) {
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto msg = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (msg->handshake_type != tls::SERVER_KEY_EXCHANGE)
            return alert(2, 10);
        accumulate(s);
        auto server_key_exchange = std::get<tls::EcdheRsaServerKeyExchange>(msg->message);
        if (server_key_exchange.curve_type != tls::NAMED_CURVE ||
            server_key_exchange.named_curve != tls::NC_SECP256R1 || server_key_exchange.point_format != 0x04) {
            spdlog::error("server_key_exchange:client: Unsupported curve type, named curve, or point format.");
            return alert(2, 47); // illegal parameter
        }

        // Extract server's ephemeral public key from received message.
        const ECPoint Y{
            bnd2mpz(server_key_exchange.x.begin(), server_key_exchange.x.end()),
            bnd2mpz(server_key_exchange.y.begin(), server_key_exchange.y.end()),
            secp256r1_
        };
        // Compute shared key.
        derive_keys((prv_key_ * Y).x_);

        // Check signature.
        auto z = rsa_.encode(bnd2mpz(server_key_exchange.sign.begin(), server_key_exchange.sign.end()));
        unsigned char check_sig[RSA_SIG_SIZE];
        mpz2bnd(z, check_sig, check_sig + sizeof(check_sig));
        std::vector<uint8_t> check_hash;
        check_hash.insert(check_hash.end(), client_random_.begin(), client_random_.end());
        check_hash.insert(check_hash.end(), server_random_.begin(), server_random_.end());
        check_hash.push_back(server_key_exchange.curve_type);
        check_hash.push_back(server_key_exchange.named_curve >> 8);
        check_hash.push_back(server_key_exchange.named_curve);
        auto point_len = 1 + sizeof(server_key_exchange.x) + sizeof(server_key_exchange.y);
        check_hash.push_back(point_len);
        check_hash.push_back(server_key_exchange.point_format);
        check_hash.insert(check_hash.end(), server_key_exchange.x.begin(), server_key_exchange.x.end());
        check_hash.insert(check_hash.end(), server_key_exchange.y.begin(), server_key_exchange.y.end());

        SHA256 sha;
        auto hash = sha.hash(check_hash.begin(), check_hash.end());

        spdlog::debug("Encoded RSA Signature and hash must be same.");
        spdlog::debug("Encoded RSA Signature: 0x{}", z.get_str(16));
        spdlog::debug("Hash: 0x{}", bnd2mpz(hash.crbegin(), hash.crend()).get_str(16));

        if (!std::equal(hash.cbegin(), hash.cend(), check_sig + (RSA_SIG_SIZE - 32))) {
            spdlog::error("server_key_exchange:client: Check signature - fail");
            return alert(2, 51); // decrypt error
        }

        spdlog::info("server_key_exchange:client: Check signature - success");
        return "";
    }

    return alert(2, 40);
}

template<>
std::string TLS12<SV_SERVER>::server_key_exchange(std::string &&) {
    std::array<uint8_t, 32> x, y;
    mpz2bnd(P_.x_, x.begin(), x.end());
    mpz2bnd(P_.y_, y.begin(), y.end());

    std::vector<uint8_t> sign(RSA_SIG_SIZE), pub_key;
    pub_key.push_back(tls::NAMED_CURVE);
    pub_key.push_back(tls::NC_SECP256R1 >> 8);
    pub_key.push_back(tls::NC_SECP256R1);
    auto point_len = 1 + x.size() + y.size();
    pub_key.push_back(point_len);
    pub_key.push_back(4); // uncompressed
    pub_key.insert(pub_key.end(), x.begin(), x.end());
    pub_key.insert(pub_key.end(), y.begin(), y.end());
    generate_signature(pub_key.data(), sign.data());

    tls::Record record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::SERVER_KEY_EXCHANGE,
            tls::EcdheRsaServerKeyExchange{
                tls::NAMED_CURVE,
                tls::NC_SECP256R1,
                0x04,
                std::move(x),
                std::move(y),
                tls::SHA256,
                tls::RSA,
                std::move(sign)
            }
        }}
    };
    return accumulate(record.serialize());
}

template<>
std::string TLS12<SV_CLIENT>::server_hello_done(std::string &&s) {
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto msg = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (msg->handshake_type != tls::SERVER_DONE)
            return alert(2, 10);
        accumulate(s);
        return "";
    }
    return alert(2, 10);
}

template<>
std::string TLS12<SV_SERVER>::server_hello_done(std::string &&) {
    tls::Record record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::SERVER_DONE,
            tls::ServerHelloDone{},
        }}
    };
    return accumulate(record.serialize());
}

template<>
std::string TLS12<SV_CLIENT>::client_key_exchange(std::string &&) {
    // After `CLIENT_KEY_EXCHANGE`, messages between server and client are encrypted.
    std::array<uint8_t, 32> x, y;
    mpz2bnd(P_.x_, x.begin(), x.end());
    mpz2bnd(P_.y_, y.begin(), y.end());
    tls::Record record{
        tls::HANDSHAKE,
        tls::TLS_VERSION_12,
        {tls::Handshake{
            tls::CLIENT_KEY_EXCHANGE,
            tls::EcdheClientKeyExchange{
                0x04,
                std::move(x),
                std::move(y),
            }
        }}
    };
    return accumulate(record.serialize());
}

template<>
std::string TLS12<SV_SERVER>::client_key_exchange(std::string &&s) {
    // After `CLIENT_KEY_EXCHANGE`, messages between server and client are encrypted.
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12 || res->messages.empty())
        return alert(2, 10);
    if (auto handshake = std::get_if<tls::Handshake>(&res->messages[0])) {
        if (handshake->handshake_type != tls::CLIENT_KEY_EXCHANGE)
            return alert(2, 10);
        accumulate(s);
        auto client_key_exchange = std::get<tls::EcdheClientKeyExchange>(handshake->message);
        const ECPoint Y{
            bnd2mpz(client_key_exchange.x.begin(), client_key_exchange.x.end()),
            bnd2mpz(client_key_exchange.y.begin(), client_key_exchange.y.end()),
            secp256r1_
        };
        // Compute shared key.
        derive_keys((prv_key_ * Y).x_);
        return "";
    }
    return alert(2, 10);
}

template<bool SV>
std::string TLS12<SV>::change_cipher_spec(std::string &&s) {
    if (s.empty()) {
        // send CHANGE_CIPHER_SPEC message
        tls::Record record{
            tls::CHANGE_CIPHER_SPEC,
            tls::TLS_VERSION_12,
            {tls::ChangeCipherSpec{tls::ChangeCipherSpec::CHANGE_CIPHER_SPEC}},
        };
        return record.serialize();
    }
    // receive CHANGE_CIPHER_SPEC message
    auto res = tls::Record::parse(s);
    if (!res || res->content_type != tls::CHANGE_CIPHER_SPEC || res->version != tls::TLS_VERSION_12 ||
        res->messages.empty()) {
        return alert(2, 10);
    }
    if (std::get<tls::ChangeCipherSpec>(res->messages[0]).type != tls::ChangeCipherSpec::CHANGE_CIPHER_SPEC) {
        return alert(2, 10);
    }
    return "";
}

template<bool SV>
std::string TLS12<SV>::finished(std::string &&s) {
    PRF<SHA256> prf;
    SHA256 sha;
    prf.secret(master_secret_.cbegin(), master_secret_.cend());
    const auto hash = sha.hash(accumulated_handshakes_.cbegin(), accumulated_handshakes_.cend());
    prf.seed(hash.cbegin(), hash.cend());
    const char *finished_label[2] = {"client finished", "server finished"};
    prf.label(finished_label[s.empty() ? SV : !SV]);
    const auto v = prf.get_n_bytes(12);

    auto msg = tls::Handshake{tls::FINISHED, tls::Finished{v}}.serialize();
    accumulated_handshakes_ += msg;

    if (s.empty()) {
        // Send FINISHED message.
        return encode(std::move(msg), tls::HANDSHAKE);
    }

    // Verify received message.
    const auto opt_result = decode(std::move(s));
    if (!opt_result) {
        spdlog::error("Handshake verification failed: Decoding failed.");
        return alert(2, 51);
    }
    if (*opt_result != msg) {
        spdlog::error("Handshake verification failed: Not matched.");
        return alert(2, 51);
    }

    // Successes to parse received FINISHED message.
    return "";
}

template<bool SV>
std::string TLS12<SV>::alert(const uint8_t level, const uint8_t desc) {
    const alert_message h{level, desc};
    return struct2str(h);
}

template<bool SV>
int TLS12<SV>::alert(std::string &&s) {
    const auto *p = reinterpret_cast<alert_message *>(s.data());
    int level, desc;

    if (p->tls.get_length() == 2) {
        // For plain alert message
        level = p->alert_level;
        desc = p->alert_desc;
    } else {
        // For encrypted alert message
        s = *decode(std::move(s));
        level = static_cast<uint8_t>(s[0]);
        desc = static_cast<uint8_t>(s[1]);
    }

    switch (desc) {
    // Reuse s
    case 0: s = "close_notify(0)"; break;
    case 10: s = "unexpected_message(10)"; break;
    case 20: s = "bad_record_mac(20)"; break;
    case 21: s = "decryption_failed_RESERVED(21)"; break;
    case 22: s = "record_overflow(22)"; break;
    case 30: s = "decompression_failure(30)"; break;
    case 40: s = "handshake_failure(40)"; break;
    case 41: s = "no_certificate_RESERVED(41)"; break;
    case 42: s = "bad_certificate(42)"; break;
    case 43: s = "unsupported_certificate(43)"; break;
    case 44: s = "certificate_revoked(44)"; break;
    case 45: s = "certificate_expired(45)"; break;
    case 46: s = "certificate_unknown(46)"; break;
    case 47: s = "illegal_parameter(47)"; break;
    case 48: s = "unknown_ca(48)"; break;
    case 49: s = "access_denied(49)"; break;
    case 50: s = "decode_error(50)"; break;
    case 51: s = "decrypt_error(51)"; break;
    case 60: s = "export_restriction_RESERVED(60)"; break;
    case 70: s = "protocol_version(70)"; break;
    case 71: s = "insufficient_security(71)"; break;
    case 80: s = "internal_error(80)"; break;
    case 90: s = "user_canceled(90)"; break;
    case 100: s = "no_renegotiation(100)"; break;
    case 110: s = "unsupported_extension(110)"; break;
    default: s = "alert"; break;
    }

    if (level == 1 || level == 2) {
        spdlog::error("TLS Alert level {}: {}", level, s);
    }

    return desc;
}

template<bool SV>
std::string TLS12<SV>::accumulate(const std::string &s) {
    accumulated_handshakes_ += s.substr(sizeof(TLS_header));
    return s;
}

template<bool SV>
std::string TLS12<SV>::accumulate_raw(const std::string &s) {
    accumulated_handshakes_ += s;
    return s;
}

template<bool SV>
void TLS12<SV>::set_accumulate(const std::string &replace) {
    accumulated_handshakes_ = replace;
}

template<bool SV>
std::string TLS12<SV>::get_accumulate() {
    return accumulated_handshakes_;
}

// Explicit template instantiation
template class TLS12<true>;
template class TLS12<false>;
