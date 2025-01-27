#include "tls/tls.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <gmpxx.h>
#include <ios>
#include <iostream>
#include <optional>
#include <ostream>
#include <sstream>
#include <utility>
#include <vector>
#include "tls/base64.h"
#include "tls/cert.h"
#include "tls/der.h"
#include "tls/diffie_hellman.h"
#include "tls/mpz.h"
#include "tls/prf.h"
#include "tls/rsa.h"
#include "tls/sha/sha2.h"

static mpz_class zK, ze, zd;

static std::string init_certificate() {
    std::ifstream prv_pem{"cert/example/key.pem"};
    std::ifstream cert_pem{"cert/example/cert.pem"};
    auto opt_keys = get_keys(prv_pem);
    if (!opt_keys) {
        throw "Failed to parse the private key PEM file.";
    }
    auto [K, e, d] = *opt_keys;
    zK = K;
    ze = e;
    zd = d;
    std::vector<unsigned char> r = {tls_type::HANDSHAKE, 3, 3, 0, 0, tls_handshake_type::CERTIFICATE, 0, 0, 0, 0, 0, 0};
    for (std::string s; (s = get_certificate_core(cert_pem)) != "";) {
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

template<bool SV>
std::string TLS<SV>::certificate_ = init_certificate();

template<bool SV>
rsa_class TLS<SV>::rsa_{ze, zd, zK};

// Pack structs to 1 byte alignment to avoid padding
#pragma pack(push, 1)

struct TLS_header {
    /** 0x15: Alert, 0x16: Handshake, 0x17: Application data */
    uint8_t content_type = tls_type::HANDSHAKE;
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    uint8_t length[2] = {0, 4};

    void set_length(size_t k) {
        length[0] = k / 0x100;
        length[1] = k % 0x100;
    }

    size_t get_length() {
        return length[0] * 0x100 + length[1];
    }
};

struct handshake_header {
    uint8_t handshake_type;
    uint8_t length[3] = {0, 0, 0};

    void set_length(size_t k) {
        length[0] = k / 0x10000;
        length[1] = k % 0x10000 / 0x100;
        length[2] = k % 0x100;
    }

    size_t get_length() {
        return length[0] * 0x10000 + length[1] * 0x100 + length[2];
    }
};

struct hello_common {
    /** 0x0303 for TLS 1.2 */
    uint8_t version[2] = {0x03, 0x03};
    /** Server random and client random */
    uint8_t random[32];
    uint8_t session_id_length = 32;
    uint8_t session_id[32];
};

struct client_hello_message {
    TLS_header tls;
    handshake_header handshake{tls_handshake_type::CLIENT_HELLO};
    hello_common hello;

    /* length of cipher_suite. It should be even number. */
    uint8_t cipher_suite_length[2] = {0, 2};
    /**
     * Cipher suite list that client can accept.
     * In this implementation, only TLS_ECDHE_RSA_AES128_GCM_SHA256 cipher suite (0xc02f) is concidered.
     */
    uint8_t cipher_suite[2] = {0xc0, 0x2f};
    uint8_t compression_length = 1;
    uint8_t compression_method = 0; // None

    int get_cipher_suite_length() {
        return cipher_suite_length[0] * 0x100 + cipher_suite_length[1];
    }
};

struct server_hello_message {
    TLS_header tls{.length = {0, sizeof(server_hello_message) - sizeof(TLS_header)}};
    handshake_header handshake{
            .handshake_type = tls_handshake_type::SERVER_HELLO,
            .length = {0, 0, sizeof(server_hello_message) - sizeof(TLS_header) - sizeof(handshake_header)},
    };
    hello_common hello;
    /**
     * Cipher suite that server chose.
     * In this implementation, only TLS_ECDHE_RSA_AES128_GCM_SHA256 cipher suite (0xc02f) is concidered.
     */
    uint8_t cipher_suite[2] = {0xc0, 0x2f};
    uint8_t compression = 0;
    uint8_t extension_length[2] = {0, 0};
};

// Used only on client-side for handling received certificate message.
// On the server-side, a pre-prepared certificate message is simply sent.
struct certificate_message {
    TLS_header tls;
    handshake_header handshake;

    /** Total length of all certificates and length of the first certificate */
    uint8_t certificate_length[2][3];
    unsigned char certificate[];
};

struct server_key_exchange_message {
    TLS_header tls;
    handshake_header handshake;

    uint8_t named_curve = 3;
    uint8_t secp256r[2] = {0, 0x17};
    uint8_t key_length = 65;
    uint8_t uncompressed = 4;
    uint8_t x[32], y[32];

    /**
     * signature hash  value
     * NONE            0
     * MD5             1
     * SHA-1           2
     * SHA-224         3
     * SHA-256         4
     * SHA-384         5
     * SHA-512         6
     */
    uint8_t signature_hash = 4;
    /**
     * signature sign  value
     * anonymous       0
     * RSA             1
     * DSA             2
     * ECDSA           3
     */
    uint8_t signature_sign = 1;
    uint8_t signature_length[2] = {1, 0}; // length: 256 (0x100)
    uint8_t sign[256];
};

struct server_hello_done_message {
    TLS_header tls;
    handshake_header handshake{.handshake_type = tls_handshake_type::SERVER_DONE};
};

struct client_key_exchange_message {
    TLS_header tls;
    handshake_header handshake{.handshake_type = tls_handshake_type::CLIENT_KEY_EXCHANGE};
    uint8_t len = 65;
    uint8_t uncompressed = 4;
    uint8_t x[32], y[32];
};

struct change_cipher_spec_message {
    TLS_header tls{.content_type = tls_type::CHANGE_CIPHER_SPEC};
    uint8_t spec = 1;
};

// For parsing received message.
struct received_message {
    TLS_header tls;
    uint8_t iv[8];
    unsigned char m[];
};

// Header for sending message.
struct send_message_header {
    TLS_header tls;
    uint8_t iv[8];
};

// For authentication tag.
struct auth_tag_data {
    uint8_t seq[8];
    TLS_header tls;
};

struct alert_message {
    /** tls.content_type: 0x15, tls.length: 2 */
    TLS_header tls{.content_type = tls_type::ALERT, .length = {0, 2}};
    uint8_t alert_level;
    uint8_t alert_desc;
};

#pragma pack(pop)

template<typename T>
static std::string struct2str(const T &t) {
    return std::string{reinterpret_cast<char *>(&t), sizeof(t)};
}

template<bool SV>
std::optional<std::string> TLS<SV>::decode(std::string &&s) {
    auto p = (received_message *) s.data();
    auth_tag_data tag_data;
    if (int type = get_content_type(s).first; type != tls_type::HANDSHAKE && type != tls_type::APPLICATION_DATA) {
        return std::nullopt;
    }
    // Increase sequence number after filling tag_data.seq.
    mpz2bnd(dec_seq_num_++, tag_data.seq, tag_data.seq + 8);
    tag_data.tls = p->tls;
    int msg_len = p->tls.get_length() - sizeof(received_message::iv) - 16; // except iv and tag length
    tag_data.tls.set_length(msg_len);
    uint8_t *aad = reinterpret_cast<uint8_t *>(&tag_data);
    aes_[!SV].set_aad(aad, sizeof(tag_data));
    aes_[!SV].set_iv(p->iv, 4, 8);
    auto auth = aes_[!SV].decrypt(p->m, msg_len);
    if (std::equal(auth.begin(), auth.end(), p->m + msg_len)) {
        return std::string{p->m, p->m + msg_len};
    } else {
        // Failed to check authentication tag
        return std::nullopt;
    }
}

template<bool SV>
std::string TLS<SV>::encode(std::string &&s, int type) {
    // GCM-based encoding
    send_message_header header;
    auth_tag_data tag_data;
    tag_data.tls.content_type = header.tls.content_type = type;

    // Increase sequence number after filling tag_data.seq.
    mpz2bnd(enc_seq_num_++, tag_data.seq, tag_data.seq + 8);
    constexpr size_t chunk_size = (1 << 14) - 64; // Maximum length for one packet.
    size_t len = std::min(s.size(), chunk_size);
    tag_data.tls.set_length(len);
    std::string frag = s.substr(0, len);

    mpz2bnd(random_prime(8), header.iv, header.iv + 8);
    aes_[SV].set_iv(header.iv, 4, 8);
    uint8_t *aad = reinterpret_cast<uint8_t *>(&header);
    aes_[SV].set_aad(aad, sizeof(header));
    auto tag = aes_[SV].encrypt(reinterpret_cast<unsigned char *>(&frag[0]), frag.size());
    frag += std::string{tag.cbegin(), tag.cend()}; // Attach auth tag
    header.tls.set_length(sizeof(header.iv) + frag.size());
    std::string r = struct2str(header) + frag;

    if (s.size() > chunk_size) {
        // Encode recursively if the message is long.
        r += encode(s.substr(chunk_size));
    }
    return r;
}

// ========== TLS<SV> CLASS METHOD IMPLEMENTATIONS ==========

template<bool SV>
std::string TLS<SV>::client_hello(std::string &&s) {
    if constexpr (!SV) {
        // client
        client_hello_message msg;
        msg.tls.set_length(sizeof(client_hello_message) - sizeof(TLS_header));
        msg.handshake.set_length(sizeof(client_hello_message) - sizeof(TLS_header) - sizeof(hello_common));
        mpz2bnd(random_prime(32), msg.hello.random, msg.hello.random + 32);
        std::copy_n(msg.hello.random, 32, client_random_.data());
        return accumulate(struct2str(msg));
    } else {
        // server
        if (get_content_type(s) != std::pair{tls_type::HANDSHAKE, tls_handshake_type::CLIENT_HELLO}) {
            return alert(2, 10);
        }
        accumulate(s);
        client_hello_message *received = reinterpret_cast<client_hello_message *>(s.data());
        std::copy_n(received->hello.random, 32, client_random_.data());
        int len = received->get_cipher_suite_length();
        unsigned char *p = received->cipher_suite;
        // Return null string if TLS_ECDHE_RSA_AES128_GCM_SHA256 (0xc02f) exists in cipher suite list.
        for (int i = 0; i < len; i += 2) {
            if (*(p + i) == 0xc0 && *(p + i + 1) == 0x2f) {
                return "";
            }
        }
        // If not, return alert message.
        return alert(2, 40);
    }
}

template<bool SV>
std::string TLS<SV>::server_hello(std::string &&s) {
    if constexpr (SV) {
        // server
        server_hello_message msg;
        mpz2bnd(random_prime(32), server_random_.begin(), server_random_.end());
        mpz2bnd(random_prime(32), session_id_.begin(), session_id_.end());
        std::copy(server_random_.begin(), server_random_.end(), msg.hello.random);
        std::copy(session_id_.cbegin(), session_id_.cend(), msg.hello.session_id);
        return accumulate(struct2str(msg));
    } else {
        // client
        if (get_content_type(s) != std::pair{tls_type::HANDSHAKE, tls_handshake_type::SERVER_HELLO}) {
            return alert(2, 10);
        }
        accumulate(s);
        server_hello_message *msg = reinterpret_cast<server_hello_message *>(s.data());
        std::copy_n(msg->hello.random, 32, server_random_.begin());
        std::copy_n(msg->hello.session_id, 32, session_id_.begin());
        // Return null string if cipher suite is TLS_ECDHE_RSA_AES128_GCM_SHA256 (0xc02f).
        if (msg->cipher_suite[0] == 0xc0 && msg->cipher_suite[1] == 0x2f) {
            return "";
        }
        // If not, return alert message.
        return alert(2, 40);
    }
}

template<bool SV>
std::string TLS<SV>::server_certificate(std::string &&s) {
    if constexpr (SV) {
        // server
        return accumulate(certificate_);
    } else {
        // client
        if (get_content_type(s) != std::pair{tls_type::HANDSHAKE, tls_handshake_type::CERTIFICATE}) {
            return alert(2, 10);
        }
        accumulate(s);
        certificate_message *msg = reinterpret_cast<certificate_message *>(s.data());
        std::stringstream ss;
        uint8_t *p = msg->certificate_length[1]; // length of only the first certificate
        // TODO: Change this method to check all certificate chains.
        for (int i = 0, j = *p * 0x10000 + *(p + 1) * 0x100 + *(p + 2); i < j; i++) {
            // Write bytes of the first certificate to ss
            ss << std::noskipws << msg->certificate[i];
        }
        // Read the first certificate and extract public key parameters.
        auto opt_pubkey = der2json(ss).transform([](auto json_value) { return get_pubkeys(json_value); });
        if (!opt_pubkey) {
            std::cerr << "Failed to parse the received certificate.";
            return alert(2, 44);
        }
        auto [K, e, sign] = *opt_pubkey;
        rsa_.K = K;
        rsa_.e = e;
        return "";
    }
}

template<bool SV>
void TLS<SV>::generate_signature(unsigned char *pub_key, unsigned char *sign) {
    // Prepare the data to be signed.
    constexpr size_t RANDOM_SIZE = 32;
    constexpr size_t PUBKEY_SIZE = 69;
    constexpr size_t MESSAGE_TO_HASH_SIZE = RANDOM_SIZE * 2 + PUBKEY_SIZE;
    unsigned char message_to_hash[MESSAGE_TO_HASH_SIZE]; // server random + client random + public key
    std::copy(server_random_.cbegin(), server_random_.cend(), message_to_hash);
    std::copy(client_random_.cbegin(), client_random_.cend(), message_to_hash + RANDOM_SIZE);
    std::copy_n(pub_key, 69, message_to_hash + RANDOM_SIZE * 2);
    sha256 sha;
    auto hash = sha.hash(message_to_hash, message_to_hash + MESSAGE_TO_HASH_SIZE); // Result size is 32 bytes.

    // Prepare PKCS#1 v1.5 padding structure.
    // See more: https://www.rfc-editor.org/rfc/rfc8017#section-9.2
    constexpr size_t RSA_SIZE = 256;
    unsigned char padded[RSA_SIZE];
    unsigned char *ptr = padded + RSA_SIZE; // Start from the end of padded
    // Add hash value.
    ptr -= hash.size();
    std::copy(hash.cbegin(), hash.cend(), ptr);
    *--ptr = hash.size(); // Add hash size (0x20) before hash value
    // der is depending on the signature method.
    constexpr unsigned char SHA256_DER[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                            0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04};
    ptr -= sizeof(SHA256_DER);
    std::copy_n(SHA256_DER, sizeof(SHA256_DER), ptr);
    *--ptr = hash.size() + sizeof(SHA256_DER) + 1; // Add length (0x31)
    *--ptr = 0x30;
    *--ptr = 0x00;
    // Add padding
    std::fill(padded + 2, ptr, 0xff);
    padded[1] = 0x01;

    // Sign with RSA.
    auto z = rsa_.sign(bnd2mpz(padded, padded + 256));
    mpz2bnd(z, sign, sign + 256);
}

template<bool SV>
void TLS<SV>::derive_keys(mpz_class premaster_secret) {
    unsigned char pre[32], rand[64];
    mpz2bnd(premaster_secret, pre, pre + 32);
    prf<sha256> p;
    p.secret(pre, pre + 32);
    std::copy(client_random_.cbegin(), client_random_.cend(), rand);
    std::copy(server_random_.cbegin(), server_random_.cend(), rand + 32);
    p.seed(rand, rand + 64);
    p.label("master secret");
    master_secret_ = p.get_n_bytes(48);
    p.secret(master_secret_.begin(), master_secret_.end());
    std::copy(server_random_.cbegin(), server_random_.cend(), rand);
    std::copy(client_random_.cbegin(), client_random_.cend(), rand + 32);
    p.seed(rand, rand + 64);
    p.label("key expansion");
    auto v = p.get_n_bytes(40);
    aes_[0].set_key(&v[0]);
    aes_[1].set_key(&v[16]);
    aes_[0].set_iv(&v[32], 0, 4);
    aes_[1].set_iv(&v[36], 0, 4);
}

template<bool SV>
std::string TLS<SV>::server_key_exchange(std::string &&s) {
    if constexpr (SV) {
        // server
        server_key_exchange_message msg;
        msg.tls.set_length(sizeof(msg) - sizeof(TLS_header));
        msg.handshake.set_length(sizeof(msg) - sizeof(TLS_header) - sizeof(handshake_header));
        msg.handshake.handshake_type = tls_handshake_type::SERVER_KEY_EXCHANGE;
        mpz2bnd(P_.x, msg.x, msg.x + 32);
        mpz2bnd(P_.y, msg.y, msg.y + 32);
        generate_signature(&msg.named_curve, msg.sign);
        return accumulate(struct2str(msg));
    } else {
        // client
        if (get_content_type(s) != std::pair{tls_type::HANDSHAKE, tls_handshake_type::SERVER_KEY_EXCHANGE}) {
            return alert(2, 10);
        }
        accumulate(s);
        auto p = reinterpret_cast<const server_key_exchange_message *>(s.data());
        // Extract server's ephemeral public key from received message.
        ec_point Y{bnd2mpz(p->x, p->x + 32), bnd2mpz(p->y, p->y + 32), secp256r1_};
        // Compute shared key.
        derive_keys((prv_key_ * Y).x);

        // Check signature.
        auto z = rsa_.encode(bnd2mpz(p->sign, p->sign + 256));
        unsigned char check_sig[256];
        mpz2bnd(z, check_sig, check_sig + 256);
        unsigned char check_hash[133];
        std::copy(client_random_.cbegin(), client_random_.cend(), check_hash);
        std::copy(server_random_.cbegin(), server_random_.cend(), check_hash + 32);
        std::copy_n(&p->named_curve, 69, check_hash + 64);
        sha256 sha;
        auto hash = sha.hash(check_hash, check_hash + 133);

        if (std::equal(check_sig + 224, check_sig + 256, hash.begin())) {
            return "";
        } else {
            return alert(2, 51); // decrypt error
        }
    }
}

template<bool SV>
std::string TLS<SV>::server_hello_done(std::string &&s) {
    if constexpr (SV) {
        // server
        server_hello_done_message msg;
        return accumulate(struct2str(msg));
    } else {
        // client
        if (get_content_type(s) != std::pair{tls_type::HANDSHAKE, tls_handshake_type::SERVER_DONE}) {
            return alert(2, 10);
        }
        accumulate(s);
        return "";
    }
}

template<bool SV>
std::string TLS<SV>::client_key_exchange(std::string &&s) {
    // After this step, messages between server and client are encrypted.
    if constexpr (SV) {
        // server
        if (get_content_type(s) == std::pair{tls_type::HANDSHAKE, tls_handshake_type::CLIENT_KEY_EXCHANGE}) {
            return alert(2, 10);
        }
        accumulate(s);
        auto p = (client_key_exchange_message *) s.data();
        ec_point Y{bnd2mpz(p->x, p->x + 32), bnd2mpz(p->y, p->y + 32), secp256r1_};
        // Compute shared key.
        derive_keys((prv_key_ * Y).x);
        return "";
    } else {
        // client
        client_key_exchange_message msg;
        msg.tls.set_length(sizeof(msg) - sizeof(TLS_header));
        msg.handshake.set_length(sizeof(msg) - sizeof(TLS_header) - sizeof(handshake_header));
        // Fill with client's public key coordinates.
        mpz2bnd(P_.x, msg.x, msg.x + 32);
        mpz2bnd(P_.y, msg.y, msg.y + 32);
        return accumulate(struct2str(msg));
    }
}

template<bool SV>
std::string TLS<SV>::change_cipher_spec(std::string &&s) {
    if (s == "") {
        // send CHANGE_CIPHER_SPEC message
        change_cipher_spec_message msg;
        msg.tls.set_length(1);
        return struct2str(msg);
    } else {
        // receive CHANGE_CIPHER_SPEC message
        if (get_content_type(s).first != tls_type::CHANGE_CIPHER_SPEC) {
            return alert(2, 10);
        }
        return "";
    }
}

template<bool SV>
std::string TLS<SV>::finished(std::string &&s) {
    prf<sha256> prf;
    sha256 sha;
    prf.secret(master_secret_.cbegin(), master_secret_.cend());
    auto hash = sha.hash(accumulated_handshakes_.cbegin(), accumulated_handshakes_.cend());
    prf.seed(hash.cbegin(), hash.cend());
    const char *label[2] = {"client finished", "server finished"};
    prf.label(label[s == "" ? SV : !SV]);
    auto v = prf.get_n_bytes(12);

    handshake_header handshake;
    handshake.handshake_type = tls_handshake_type::FINISHED;
    handshake.set_length(12);

    std::string msg = struct2str(handshake) + std::string{v.cbegin(), v.cend()};
    accumulated_handshakes_ += msg;

    if (s == "") {
        // Send FINISHED message.
        return encode(std::move(msg), tls_type::HANDSHAKE);
    } else if (decode(std::move(s)) != msg) {
        // Failed to parse received FINISHED message.
        return alert(2, 51);
    } else {
        // Successed to parse received FINISHED message.
        return "";
    }
}

template<bool SV>
std::string TLS<SV>::alert(uint8_t level, uint8_t desc) {
    alert_message h{.alert_level = level, .alert_desc = desc};
    return struct2str(h);
}

template<bool SV>
int TLS<SV>::alert(std::string &&s) {
    alert_message *p = reinterpret_cast<alert_message *>(s.data());
    int level, desc;

    if (p->tls.get_length() == 2) {
        // For plain alert message
        level = p->alert_level;
        desc = p->alert_desc;
    } else {
        // For encrypted alert message
        s = decode(s);
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
    }

    if (level == 1 || level == 2) {
        std::cerr << s << std::endl;
    }

    return desc;
}

template<bool SV>
std::string TLS<SV>::accumulate(const std::string &s) {
    accumulated_handshakes_ += s.substr(sizeof(TLS_header));
    return s;
}
