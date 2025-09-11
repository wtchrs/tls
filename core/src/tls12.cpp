#include "core/tls12.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gmpxx.h>
#include <ios>
#include <iostream>
#include <optional>
#include <ostream>
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

std::string init_certificate() {
    std::ifstream cert_pem{"./cert/example/cert.pem"};
    std::vector<unsigned char> r = {HANDSHAKE, 3, 3, 0, 0, CERTIFICATE, 0, 0, 0, 0, 0, 0};
    for (std::string s; !(s = get_certificate_core(cert_pem)).empty();) {
        auto v = base64_decode(s);
        r.resize(r.size() + 3);
        mpz2bnd(static_cast<int>(v.size()), r.end() - 3, r.end());
        r.insert(r.end(), v.cbegin(), v.cend());
    }
    mpz2bnd(static_cast<int>(r.size() - 5), r.begin() + 3, r.begin() + 5); // size field of TLS header
    mpz2bnd(static_cast<int>(r.size() - 9), r.begin() + 6, r.begin() + 9); // size field of TLS handshake header
    mpz2bnd(static_cast<int>(r.size() - 12), r.begin() + 9, r.begin() + 12); // total size of certificates
    return {r.cbegin(), r.cend()};
}

RSA init_rsa() {
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
std::string TLS12<SV>::certificate_ = init_certificate();

template<bool SV>
RSA TLS12<SV>::rsa_ = init_rsa();

template<bool SV>
std::pair<int, int> TLS12<SV>::get_content_type(const std::string &s) {
    auto p = reinterpret_cast<const uint8_t *>(s.data());
    return {p[0], p[5]};
}

template<bool SV>
std::optional<std::string> TLS12<SV>::decode(std::string &&s) {
    const auto p = reinterpret_cast<received_message *>(s.data());
    auth_tag_data tag_data;
    if (const int type = get_content_type(s).first; type != HANDSHAKE && type != APPLICATION_DATA) {
        return std::nullopt;
    }
    // Increase sequence number after filling tag_data.seq.
    mpz2bnd(dec_seq_num_++, tag_data.seq, tag_data.seq + 8);
    tag_data.tls = p->tls;
    const auto msg_len = p->tls.get_length() - sizeof(received_message::iv) - 16; // except iv and tag length
    tag_data.tls.set_length(msg_len);
    const auto *aad = reinterpret_cast<uint8_t *>(&tag_data);
    aes_[!SV].set_aad(aad, sizeof(tag_data));
    aes_[!SV].set_iv(p->iv, 4, 8);

    auto auth = aes_[!SV].decrypt(p->m, msg_len);
    if (!std::equal(auth.begin(), auth.end(), p->m + msg_len)) {
        // Failed to check authentication tag
        return std::nullopt;
    }
    return std::string{p->m, p->m + msg_len};
}

template<bool SV>
std::string TLS12<SV>::encode(std::string &&s, const int type) {
    // GCM-based encoding
    send_message_header header;
    auth_tag_data tag_data;
    tag_data.tls.content_type = header.tls.content_type = type;

    // Increase sequence number after filling tag_data.seq.
    mpz2bnd(enc_seq_num_++, tag_data.seq, tag_data.seq + 8);
    constexpr size_t CHUNK_SIZE = (1 << 14) - 64; // Maximum length for one packet.
    const size_t len = std::min(s.size(), CHUNK_SIZE);
    tag_data.tls.set_length(len);
    std::string frag = s.substr(0, len);

    mpz2bnd(random_prime(8), header.iv, header.iv + 8);
    aes_[SV].set_iv(header.iv, 4, 8);
    const auto *aad = reinterpret_cast<uint8_t *>(&tag_data);
    aes_[SV].set_aad(aad, sizeof(tag_data));

    const auto tag = aes_[SV].encrypt(reinterpret_cast<unsigned char *>(frag.data()), frag.size());
    frag += std::string{tag.cbegin(), tag.cend()}; // Attach auth tag
    header.tls.set_length(sizeof(header.iv) + frag.size());
    std::string r = struct2str(header) + frag;

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
    if (!res)
        return alert(2, 80); // TODO: Change to proper error description.
    if (res->content_type != tls::HANDSHAKE || res->version != tls::TLS_VERSION_12)
        return alert(2, 10);
    if (auto handshake = std::get_if<tls::Handshake>(&res->messages[0]);
        handshake->handshake_type == tls::CLIENT_HELLO) {
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
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, SERVER_HELLO}) {
        return alert(2, 10);
    }
    accumulate(s);
    const auto msg = reinterpret_cast<server_hello_message *>(s.data());
    std::copy_n(msg->hello.random, 32, server_random_.begin());
    std::copy_n(msg->hello.session_id, 32, session_id_.begin());
    // Return null string if cipher suite is TLS_ECDHE_RSA_AES128_GCM_SHA256 (0xc02f).
    if (msg->cipher_suite[0] == 0xc0 && msg->cipher_suite[1] == 0x2f) {
        return "";
    }
    // If not, return alert message.
    return alert(2, 40);
}

template<>
std::string TLS12<SV_SERVER>::server_hello(std::string &&) {
    server_hello_message msg;
    mpz2bnd(random_prime(32), server_random_.begin(), server_random_.end());
    mpz2bnd(random_prime(32), session_id_.begin(), session_id_.end());
    std::copy(server_random_.begin(), server_random_.end(), msg.hello.random);
    std::copy(session_id_.cbegin(), session_id_.cend(), msg.hello.session_id);
    return accumulate(struct2str(msg));
}

template<>
std::string TLS12<SV_CLIENT>::server_certificate(std::string &&s) {
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, CERTIFICATE}) {
        return alert(2, 10);
    }
    accumulate(s);
    const auto msg = reinterpret_cast<certificate_message *>(s.data());
    std::stringstream ss;
    const uint8_t *p = msg->certificate_length[1]; // length of only the first certificate
    // TODO: Change this method to check all certificate chains.
    for (int i = 0, j = *p * 0x10000 + *(p + 1) * 0x100 + *(p + 2); i < j; i++) {
        // Write bytes of the first certificate to ss
        ss << std::noskipws << msg->certificate[i];
    }
    // Read the first certificate and extract public key parameters.
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

template<>
std::string TLS12<SV_SERVER>::server_certificate(std::string &&) {
    return accumulate(certificate_);
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
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, SERVER_KEY_EXCHANGE}) {
        return alert(2, 10);
    }
    accumulate(s);
    const auto p = reinterpret_cast<const server_key_exchange_message *>(s.data());
    // Extract server's ephemeral public key from received message.
    const ECPoint Y{bnd2mpz(p->x, p->x + 32), bnd2mpz(p->y, p->y + 32), secp256r1_};
    // Compute shared key.
    derive_keys((prv_key_ * Y).x_);

    // Check signature.
    auto z = rsa_.encode(bnd2mpz(p->sign, p->sign + RSA_SIG_SIZE));
    unsigned char check_sig[RSA_SIG_SIZE];
    mpz2bnd(z, check_sig, check_sig + RSA_SIG_SIZE);
    unsigned char check_hash[MESSAGE_TO_HASH_SIZE];
    std::copy(client_random_.cbegin(), client_random_.cend(), check_hash);
    std::copy(server_random_.cbegin(), server_random_.cend(), check_hash + RANDOM_SIZE);
    std::copy_n(&p->named_curve, PUBKEY_SIZE, check_hash + RANDOM_SIZE * 2);

    SHA256 sha;
    auto hash = sha.hash(check_hash, check_hash + MESSAGE_TO_HASH_SIZE);

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

template<>
std::string TLS12<SV_SERVER>::server_key_exchange(std::string &&) {
    server_key_exchange_message msg;
    msg.tls.set_length(sizeof(msg) - sizeof(TLS_header));
    msg.handshake.set_length(sizeof(msg) - sizeof(TLS_header) - sizeof(handshake_header));
    msg.handshake.handshake_type = SERVER_KEY_EXCHANGE;
    mpz2bnd(P_.x_, msg.x, msg.x + 32);
    mpz2bnd(P_.y_, msg.y, msg.y + 32);
    generate_signature(&msg.named_curve, msg.sign);
    return accumulate(struct2str(msg));
}

template<>
std::string TLS12<SV_CLIENT>::server_hello_done(std::string &&s) {
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, SERVER_DONE}) {
        return alert(2, 10);
    }
    accumulate(s);
    return "";
}

template<>
std::string TLS12<SV_SERVER>::server_hello_done(std::string &&) {
    constexpr server_hello_done_message msg;
    return accumulate(struct2str(msg));
}

template<>
std::string TLS12<SV_CLIENT>::client_key_exchange(std::string &&) {
    // After `CLIENT_KEY_EXCHANGE`, messages between server and client are encrypted.
    client_key_exchange_message msg;
    msg.tls.set_length(sizeof(msg) - sizeof(TLS_header));
    msg.handshake.set_length(sizeof(msg) - sizeof(TLS_header) - sizeof(handshake_header));
    // Fill with client's public key coordinates.
    mpz2bnd(P_.x_, msg.x, msg.x + 32);
    mpz2bnd(P_.y_, msg.y, msg.y + 32);
    return accumulate(struct2str(msg));
}

template<>
std::string TLS12<SV_SERVER>::client_key_exchange(std::string &&s) {
    // After `CLIENT_KEY_EXCHANGE`, messages between server and client are encrypted.
    if (get_content_type(s) != std::pair<int, int>{HANDSHAKE, CLIENT_KEY_EXCHANGE}) {
        return alert(2, 10);
    }
    accumulate(s);
    auto p = reinterpret_cast<client_key_exchange_message *>(s.data());
    const ECPoint Y{bnd2mpz(p->x, p->x + 32), bnd2mpz(p->y, p->y + 32), secp256r1_};
    // Compute shared key.
    derive_keys((prv_key_ * Y).x_);
    return "";
}

template<bool SV>
std::string TLS12<SV>::change_cipher_spec(std::string &&s) {
    if (s.empty()) {
        // send CHANGE_CIPHER_SPEC message
        change_cipher_spec_message msg;
        msg.tls.set_length(1);
        return struct2str(msg);
    }
    // receive CHANGE_CIPHER_SPEC message
    if (get_content_type(s).first != CHANGE_CIPHER_SPEC) {
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
    const char *label[2] = {"client finished", "server finished"};
    prf.label(label[s.empty() ? SV : !SV]);
    const auto v = prf.get_n_bytes(12);

    handshake_header handshake;
    handshake.handshake_type = FINISHED;
    handshake.set_length(12);

    std::string msg = struct2str(handshake) + std::string{v.cbegin(), v.cend()};
    accumulated_handshakes_ += msg;

    if (s.empty()) {
        // Send FINISHED message.
        return encode(std::move(msg), HANDSHAKE);
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
